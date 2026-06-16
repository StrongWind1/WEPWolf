//! Per-BSSID WEP frame harvesting and classification (FR-WEP-1..6, FR-CLASSIFY-1).
//!
//! For each frame we fold evidence and material into the BSSID's `BssidWep`. Beacons/probes give the Privacy bit, any RSN/WPA IE, and the ESSID. Protected data frames give IV samples (keystream from the known LLC/SNAP header, plus a longer one whose known plaintext -- ARP, IPv4, IPv6 Neighbor Discovery, or EAPOL -- is chosen from the cleartext destination MAC, FR-WEP-6), each tagged with its WEP key slot, and are split WEP vs WPA on the Extended-IV bit. The Shared-Key authentication exchange gives a keystream by pairing the WEP-encrypted frame 3 with the cleartext challenge from frame 2. Counting is exhaustive: every WEP-bearing frame increments a counter.
//!
//! This mirrors how aircrack-ng decides encryption and gathers IVs, the ground truth the differential gate checks against (C5).

use std::collections::{BTreeMap, HashMap};

use crate::ieee80211::frame::{MacHeader, TYPE_DATA, TYPE_MANAGEMENT};
use crate::ieee80211::ie::{OUI_WFA, iter_ies, vendor_ie_body};
use crate::model::{BssidWep, EncFrame, IvSample, Mac};
use crate::types::trim_nul_padding;
use crate::wep;

pub use crate::model::Encryption;

/// What the frame carver (`--carve`, FR-OUT-6) should do with a just-observed frame.
///
/// Returned by [`observe`] so the scanner can write the WEP-relevant frames
/// without re-deriving the WEP-vs-WPA decision it already made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carve {
    /// Not part of a WEP network's crack material or identity -- do not write.
    Skip,
    /// A WEP crack frame (WEP-encrypted data, or a Shared-Key auth frame): its
    /// BSSID is a WEP network, so write it immediately.
    Wep,
    /// A beacon/probe carrying a network's SSID: buffer it; write only if the
    /// BSSID turns out to be WEP.
    Beacon,
}

// --- Frame/IE constants, per [IEEE 802.11-2007] §7.2.3, §7.3, §8.2.1 ---
/// Management subtype: Probe Response. §7.2.3, Table 7-1.
const SUBTYPE_PROBE_RESP: u8 = 5;
/// Management subtype: Beacon. §7.2.3, Table 7-1.
const SUBTYPE_BEACON: u8 = 8;
/// Management subtype: Authentication. §7.2.3, Table 7-1.
const SUBTYPE_AUTH: u8 = 11;
/// Beacon/Probe-Resp fixed fields before the IEs: Timestamp(8)+Interval(2)+Capability(2).
const MGMT_FIXED_FIELDS: usize = 12;
/// Byte offset of the 2-octet Capability Information field within the body.
const CAPABILITY_OFFSET: usize = 10;
/// Privacy bit (bit 4) of the Capability Information field. §7.3.1.4.
const CAP_PRIVACY: u16 = 0x0010;
/// RSN information element id. §7.3.2.25.
const IE_RSN: u8 = 48;
/// Vendor-IE type marking a pre-RSN WPA1 element (OUI `00:50:F2`).
const WPA_IE_TYPE: u8 = 1;
/// Challenge Text information element id. §7.3.2.8.
const IE_CHALLENGE: u8 = 16;
/// Authentication Algorithm Number for Shared Key. §7.3.1.1.
const AUTH_SHARED_KEY: u16 = 1;
/// Authentication Transaction Sequence Number of the challenge frame (frame 2).
const AUTH_SEQ_CHALLENGE: u16 = 2;

/// LLC/SNAP header (RFC 1042) plus the high octet of the `EtherType` (`0x08` for
/// IP and ARP): the known-plaintext prefix of a WEP data MSDU. Seven octets of
/// keystream is exactly enough for WEP-40 PTW.
const SNAP_PREFIX: [u8; 7] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08];
/// Known plaintext for an ARP-over-WEP MSDU: SNAP + `EtherType`(ARP) + the fixed
/// ARP header (htype/ptype/hlen/plen) + the Operation (assumed Request `0x0001`).
/// Sixteen octets -- the whole fixed prefix is deterministic, which is exactly
/// what gives PTW clean votes through WEP-104 (needs `keylen + 2 = 15`). The
/// sender/target addresses that follow are *not* appended: replayed ARP (the
/// common IV-farming case) carries a sender MAC unrelated to the 802.11 source,
/// so guessing them -- as aircrack-ng does from `get_sa` -- would only add noise
/// to the positions past 104-bit anyway.
const ARP_KNOWN: [u8; 16] =
    [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
/// MSDU lengths of a WEP ARP request/response, matching aircrack-ng's `is_arp`
/// (`lib/crypto/crypto.c`): the bare 28-octet ARP after SNAP (36), and the same
/// padded to the 802.3 minimum payload (54). Both carry the fixed ARP prefix.
const ARP_MSDU_LENS: [usize; 2] = [36, 54];
/// Octets of IPv4 known plaintext we reconstruct (SNAP 8 + IPv4 header start 8):
/// enough keystream for WEP-104 PTW, which needs `keylen + 2 = 15`.
const IP_KNOWN_LEN: usize = 16;
/// Keystream index of the IPv4 Don't-Fragment octet: SNAP(8) + IPv4 flags offset
/// 6. Its plaintext is `0x40` (DF set, ~85%) or `0x00` (~15%), so it is voted
/// both ways rather than trusted as the assumed `0x40`.
const IP_DF_INDEX: u8 = 14;

// --- Known-plaintext from the cleartext L2 destination (FR-WEP-6) ---
// The 802.11 Destination Address stays in the clear even when the MSDU is
// WEP-encrypted, and multicast/broadcast group MACs map deterministically to an
// L3 protocol family. That lets us pick the right known plaintext for an encrypted
// frame without decrypting it -- more precise than guessing purely by length, and
// it catches IPv6, which the IPv4-shaped guess would mis-key.

/// IPv6 multicast MAC prefix (`33:33`), per [RFC 2464] §7: the low 32 bits carry
/// the group, so this DA marks an IPv6 frame (Neighbor Discovery RS/RA/NS/NA to
/// `ff02::1` / `ff02::2` / a solicited-node group, and other `ICMPv6`).
const IPV6_MCAST_PREFIX: [u8; 2] = [0x33, 0x33];
/// IPv4 multicast MAC prefix (`01:00:5e`), per [RFC 1112] §6.4: marks an IPv4
/// frame -- mDNS (`224.0.0.251`), SSDP (`239.255.255.250`), IGMP (`224.0.0.x`).
const IPV4_MCAST_PREFIX: [u8; 3] = [0x01, 0x00, 0x5e];
/// All-ones broadcast: ARP, or broadcast IPv4 such as DHCP to `255.255.255.255`.
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// 802.1X PAE group address (`01:80:c2:00:00:03`), per [IEEE 802.1X] §7.8: marks
/// an EAPOL frame (`EtherType` `0x888E`).
const PAE_GROUP_MAC: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03];

/// IPv6-ND known-plaintext length: SNAP(8) + the IPv6 fixed-header start (8).
/// Sixteen octets -- enough for WEP-104 PTW, like the IPv4/ARP prefixes.
const IPV6_ND_KNOWN_LEN: usize = 16;
/// EAPOL known plaintext: just the LLC/SNAP header with the 802.1X `EtherType`
/// (`0x888E`). The EAPOL body past it (version/type) is not reliably fixed across
/// implementations, so only these eight octets are trusted -- WEP-40 reach, and
/// the correct `EtherType` where the generic `0x08` SNAP guess would be wrong.
const EAPOL_KNOWN: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

/// The L3 protocol family inferred from a frame's cleartext Destination Address,
/// used to choose known plaintext for an encrypted MSDU without decrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DstHint {
    /// IPv6 (`33:33` multicast) -- Neighbor Discovery and other `ICMPv6`.
    Ipv6,
    /// IPv4 (`01:00:5e` multicast, or broadcast) -- mDNS/SSDP/IGMP/DHCP, etc.
    Ipv4,
    /// 802.1X EAPOL (the PAE group address).
    Eapol,
    /// No multicast/broadcast signal: a unicast frame of unknown L3 (the common case).
    Unknown,
}

/// Infer the L3 family from the cleartext Destination Address (FR-WEP-6).
fn dst_hint(dst: Mac) -> DstHint {
    let b = dst.0;
    if b.starts_with(&IPV6_MCAST_PREFIX) {
        DstHint::Ipv6
    } else if b.starts_with(&IPV4_MCAST_PREFIX) || b == BROADCAST_MAC {
        DstHint::Ipv4
    } else if b == PAE_GROUP_MAC {
        DstHint::Eapol
    } else {
        DstHint::Unknown
    }
}

/// Known plaintext for an IPv6 Neighbor-Discovery (or other `ICMPv6`) MSDU, or
/// `None` if the frame is too short to carry a full IPv6 header.
///
/// IPv6 has no header checksum and ND mandates a hop limit of 255 (RFC 4861 §4,
/// verified by receivers), so the fixed-header start is highly predictable:
/// LLC/SNAP + `EtherType` `0x86DD`, version `6` / traffic-class `0`, flow label `0`
/// (typical for ND), the payload length *computed from the captured frame*, next
/// header `0x3A` (`ICMPv6`), and hop limit `0xFF`. Sixteen reliable octets where the
/// IPv4-shaped guess would mis-key every byte from the `EtherType` on -- this is the
/// case the generic harvest gets wrong today.
fn ipv6_nd_known_plaintext(payload_len: usize) -> Option<[u8; IPV6_ND_KNOWN_LEN]> {
    // MSDU = SNAP(8) + IPv6 header(40) + `ICMPv6`; the IPv6 payload-length field is
    // MSDU - 48, recovered exactly from the captured frame size.
    let msdu_len = payload_len.checked_sub(4)?;
    let plen = msdu_len.checked_sub(48)?; // require a full 40-octet IPv6 header
    let [hi, lo] = u16::try_from(plen).ok()?.to_be_bytes();
    Some([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, hi, lo, 0x3A, 0xFF])
}

/// Cache of Shared-Key challenge text keyed by BSSID.
///
/// Filled from the cleartext frame 2, consumed by the WEP-encrypted frame 3. Keyed by BSSID rather than by client because the client is `addr1` in frame 2 but `addr2` in frame 3, so an `(ap, sta)` key would never match across the two frames.
pub type ChallengeCache = HashMap<Mac, Vec<u8>>;

/// Fold one parsed frame into the BSSID map, harvesting WEP material and classification evidence.
///
/// Only Beacon/Probe-Response, Authentication, and Protected data frames carry signal; everything else is ignored here.
pub fn observe(
    map: &mut BTreeMap<Mac, BssidWep>,
    challenges: &mut ChallengeCache,
    hdr: &MacHeader,
    body: &[u8],
) -> Carve {
    if hdr.frame_type == TYPE_MANAGEMENT {
        if hdr.subtype == SUBTYPE_BEACON || hdr.subtype == SUBTYPE_PROBE_RESP {
            observe_beacon(entry(map, hdr.ap), body);
            Carve::Beacon
        } else if hdr.subtype == SUBTYPE_AUTH {
            observe_auth(map, challenges, hdr, body)
        } else {
            Carve::Skip
        }
    } else if hdr.frame_type == TYPE_DATA && hdr.protected {
        observe_protected_data(entry(map, hdr.ap), hdr.dst, body)
    } else {
        Carve::Skip
    }
}

/// Get the per-BSSID record, stamping its BSSID on first sight.
fn entry(map: &mut BTreeMap<Mac, BssidWep>, ap: Mac) -> &mut BssidWep {
    let record = map.entry(ap).or_default();
    record.bssid = ap;
    record
}

/// `keystream[i] = ciphertext[i] XOR known_plaintext[i]` over the known prefix.
fn xor_prefix(ciphertext: &[u8], known: &[u8]) -> Vec<u8> {
    ciphertext.iter().zip(known).map(|(c, p)| c ^ p).collect()
}

/// The assumed known plaintext of an IPv4-over-WEP MSDU, or `None` if the frame
/// is too short to carry it.
///
/// The IPv4 header start is highly predictable: LLC/SNAP for IP, version/IHL
/// `0x45`, TOS `0x00`, the total length *computed from the captured frame*, the
/// IP ID (assumed `0x0000`), and the Don't-Fragment flags `0x4000`. Sixteen
/// octets -- enough for WEP-104 PTW. Mirrors aircrack-ng's `known_clear()` IP
/// branch (`lib/crypto/crypto.c`, C5): a wrong guess (non-IP frame, or a nonzero
/// IP ID) only adds noise the Klein vote averages out, while the length field --
/// the one variable part -- is recovered exactly from the MSDU size.
fn ip_known_plaintext(payload_len: usize) -> Option<[u8; IP_KNOWN_LEN]> {
    // IP total length = MSDU (payload minus the 4-octet ICV) minus the 8-octet
    // SNAP; require the full 16 known octets to fall inside the MSDU.
    let msdu_len = payload_len.checked_sub(4)?;
    if msdu_len < IP_KNOWN_LEN {
        return None;
    }
    let [hi, lo] = u16::try_from(msdu_len - 8).ok()?.to_be_bytes();
    Some([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, hi, lo, 0x00, 0x00, 0x40, 0x00])
}

/// Read the Privacy bit, the SSID, and any RSN/WPA IE from a Beacon/Probe-Resp body.
fn observe_beacon(record: &mut BssidWep, body: &[u8]) {
    record.saw_beacon = true;
    if let Some(cap) = body.get(CAPABILITY_OFFSET..CAPABILITY_OFFSET + 2).and_then(|s| <[u8; 2]>::try_from(s).ok())
        && u16::from_le_bytes(cap) & CAP_PRIVACY != 0
    {
        record.saw_privacy = true;
    }
    let Some(ies) = body.get(MGMT_FIXED_FIELDS..) else {
        return;
    };
    for ie in iter_ies(ies) {
        if ie.id == 0 {
            if record.essid.is_none() {
                let ssid = trim_nul_padding(ie.value);
                if !ssid.is_empty() {
                    record.essid = Some(ssid.to_vec());
                }
            }
        } else if ie.id == IE_RSN || vendor_ie_body(&ie, OUI_WFA, WPA_IE_TYPE).is_some() {
            record.saw_crypto_ie = true;
        }
    }
}

/// Split WEP vs TKIP/CCMP on the Extended-IV bit (FR-WEP-1) and, for WEP, harvest
/// the IV sample (SNAP keystream, plus a longer protocol keystream -- FR-WEP-3,
/// FR-WEP-6), the Key ID (FR-WEP-5), and a verifier frame.
fn observe_protected_data(record: &mut BssidWep, dst: Mac, body: &[u8]) -> Carve {
    let Some(view) = wep::parse(body) else {
        return Carve::Skip;
    };
    if view.ext_iv {
        record.saw_wpa_data = true;
        return Carve::Skip;
    }
    record.saw_wep_data = true;
    record.wep_data_frames += 1;
    record.key_ids_seen |= 1u8 << view.key_id;

    // Short keystream from the LLC/SNAP prefix (always present) -> FMS / KoreK.
    record.ivs.push(IvSample::new(view.iv, &xor_prefix(view.payload, &SNAP_PREFIX)).with_key_id(view.key_id));

    // Longer PTW keystream from known plaintext. ARP is detected by its fixed MSDU
    // length; otherwise the cleartext Destination Address picks the L3 family
    // (FR-WEP-6) -- IPv6 (Neighbor Discovery) and EAPOL would be mis-keyed by the
    // IPv4-shaped guess, while IPv4 multicast/broadcast and ordinary unicast use the
    // reconstructed IPv4 header. This is what lets PTW reach WEP-104, which the
    // 7-octet SNAP alone cannot (FR-ATK-PTW-1).
    let msdu_len = view.payload.len().checked_sub(4);
    if msdu_len.is_some_and(|n| ARP_MSDU_LENS.contains(&n)) {
        record
            .arp_keystreams
            .push(IvSample::new(view.iv, &xor_prefix(view.payload, &ARP_KNOWN)).with_key_id(view.key_id));
    } else {
        match dst_hint(dst) {
            DstHint::Ipv6 => {
                // IPv6 ND / `ICMPv6`: a long, checksum-free, highly-predictable header.
                if let Some(known) = ipv6_nd_known_plaintext(view.payload.len()) {
                    record
                        .arp_keystreams
                        .push(IvSample::new(view.iv, &xor_prefix(view.payload, &known)).with_key_id(view.key_id));
                }
            },
            DstHint::Eapol => {
                // 802.1X: only the SNAP + `EtherType` is reliably fixed.
                record
                    .arp_keystreams
                    .push(IvSample::new(view.iv, &xor_prefix(view.payload, &EAPOL_KNOWN)).with_key_id(view.key_id));
            },
            DstHint::Ipv4 | DstHint::Unknown => {
                // IPv4 (multicast/broadcast confirmed, or a unicast guess). The
                // Don't-Fragment octet (keystream index 14) is dual-valued, so mark
                // it for two-keystream voting (FR-WEP-3).
                if let Some(ip_known) = ip_known_plaintext(view.payload.len()) {
                    record.arp_keystreams.push(
                        IvSample::new_ip(view.iv, &xor_prefix(view.payload, &ip_known), IP_DF_INDEX)
                            .with_key_id(view.key_id),
                    );
                }
            },
        }
    }

    record.retain_enc_frame(EncFrame { iv: view.iv, data: view.payload.to_vec(), key_id: view.key_id });
    Carve::Wep
}

/// Handle a Shared-Key authentication frame (FR-WEP-4): cache the cleartext
/// frame-2 challenge, or recover keystream from the WEP-encrypted frame 3.
fn observe_auth(
    map: &mut BTreeMap<Mac, BssidWep>,
    challenges: &mut ChallengeCache,
    hdr: &MacHeader,
    body: &[u8],
) -> Carve {
    if hdr.protected {
        let Some(view) = wep::parse(body) else {
            return Carve::Skip;
        };
        let record = entry(map, hdr.ap);
        record.saw_wep_auth = true;
        record.wep_auth_frames += 1;
        record.key_ids_seen |= 1u8 << view.key_id;
        if let Some(challenge) = challenges.get(&hdr.ap) {
            // Known plaintext of frame 3: alg=1, seq=3, status=0, Challenge IE, challenge bytes.
            let mut known =
                vec![0x01, 0x00, 0x03, 0x00, 0x00, 0x00, IE_CHALLENGE, u8::try_from(challenge.len()).unwrap_or(0)];
            known.extend_from_slice(challenge);
            let keystream = xor_prefix(view.payload, &known);
            // The long SKA keystream bootstraps the statistical attacks as one
            // more IV sample (FR-ATK-SKA-1).
            record.arp_keystreams.push(IvSample::new(view.iv, &keystream).with_key_id(view.key_id));
            if record.ska_keystream.is_none() {
                record.ska_keystream = Some(keystream);
            }
        }
        record.retain_enc_frame(EncFrame { iv: view.iv, data: view.payload.to_vec(), key_id: view.key_id });
    } else {
        // Cleartext auth body: alg(2) seq(2) status(2) [Challenge IE]. Only Shared-Key
        // auth (alg=1) belongs to a WEP network; Open System auth (alg=0) does not.
        let alg = body.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok()).map(u16::from_le_bytes);
        if alg != Some(AUTH_SHARED_KEY) {
            return Carve::Skip;
        }
        // Cache the frame-2 challenge so the encrypted frame 3 can recover keystream.
        let seq = body.get(2..4).and_then(|s| <[u8; 2]>::try_from(s).ok()).map(u16::from_le_bytes);
        if seq == Some(AUTH_SEQ_CHALLENGE)
            && let Some(ies) = body.get(6..)
        {
            for ie in iter_ies(ies) {
                if ie.id == IE_CHALLENGE {
                    challenges.insert(hdr.ap, ie.value.to_vec());
                }
            }
        }
    }
    // Both branches that reach here are Shared-Key auth frames of a WEP network.
    Carve::Wep
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::cast_possible_truncation,
        reason = "test module builds fixed-length fixtures"
    )]

    use super::*;
    use crate::ieee80211::frame::FrameDirection;

    fn hdr(ap: Mac, sta: Mac, frame_type: u8, subtype: u8, protected: bool) -> MacHeader {
        MacHeader {
            ap,
            sta,
            dst: sta,
            frame_type,
            subtype,
            protected,
            body_offset: 24,
            direction: FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        }
    }

    /// A protected WEP data frame header addressed to a specific cleartext DA.
    fn data_hdr_to(ap: Mac, dst: Mac) -> MacHeader {
        let mut h = hdr(ap, Mac::default(), TYPE_DATA, 0, true);
        h.dst = dst;
        h
    }

    fn beacon_body(privacy: bool, ies: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 12];
        if privacy {
            body[10] = 0x10;
        }
        body.extend_from_slice(ies);
        body
    }

    fn ssid_ie(name: &[u8]) -> Vec<u8> {
        let mut ie = vec![0u8, u8::try_from(name.len()).unwrap()];
        ie.extend_from_slice(name);
        ie
    }

    fn run(frames: &[(MacHeader, Vec<u8>)]) -> BTreeMap<Mac, BssidWep> {
        let mut map = BTreeMap::new();
        let mut challenges = ChallengeCache::new();
        for (h, body) in frames {
            observe(&mut map, &mut challenges, h, body);
        }
        map
    }

    #[test]
    fn privacy_without_rsn_is_wep() {
        // FR-CLASSIFY-1: Privacy bit, no RSN -> WEP.
        let m = run(&[(
            hdr(Mac::default(), Mac::default(), TYPE_MANAGEMENT, SUBTYPE_BEACON, false),
            beacon_body(true, &ssid_ie(b"w")),
        )]);
        assert_eq!(m[&Mac::default()].encryption(), Encryption::Wep);
    }

    #[test]
    fn rsn_is_wpa() {
        // FR-CLASSIFY-1: an RSN IE means WPA even with the Privacy bit set.
        let mut ies = ssid_ie(b"w");
        ies.extend_from_slice(&[IE_RSN, 2, 0x01, 0x00]);
        let m = run(&[(
            hdr(Mac::default(), Mac::default(), TYPE_MANAGEMENT, SUBTYPE_BEACON, false),
            beacon_body(true, &ies),
        )]);
        assert_eq!(m[&Mac::default()].encryption(), Encryption::Wpa);
    }

    #[test]
    fn wep_data_harvests_iv_and_counts() {
        // FR-WEP-2: a protected data frame (ExtIV clear) is counted and yields an IV sample.
        // Body: IV 01 02 03, key-id octet 0x00, then payload (SNAP + ICV).
        let body = vec![0x01, 0x02, 0x03, 0x00, 0xAA ^ 0xEE, 0xAA ^ 0x11, 0x03 ^ 0x22, 0x00, 0x00, 0x00, 0x00, 0x00];
        let m = run(&[(hdr(Mac::default(), Mac::default(), TYPE_DATA, 0, true), body)]);
        let r = &m[&Mac::default()];
        assert_eq!(r.encryption(), Encryption::Wep);
        assert_eq!(r.wep_data_frames, 1);
        assert_eq!(r.ivs.len(), 1);
        assert_eq!(r.ivs[0].iv, [0x01, 0x02, 0x03]);
        // keystream[0] = cipher[0] ^ 0xAA = 0xEE; [1] = ^0xAA = 0x11; [2] = ^0x03 = 0x22.
        assert_eq!(&r.ivs[0].keystream()[0..3], &[0xEE, 0x11, 0x22]);
        assert_eq!(r.key_ids_seen, 0b0001);
        assert_eq!(r.enc_frames.len(), 1);
    }

    #[test]
    fn ip_data_frame_marks_the_df_octet() {
        // FR-ATK-PTW-1 (two-keystream IPv4 voting): an IPv4-sized WEP data frame
        // (MSDU not the ARP 36/54) yields a sample whose DF keystream octet is
        // marked so the attacks vote it both ways.
        let mut body = vec![0x01, 0x02, 0x03, 0x00]; // IV(3) + Key-ID octet
        body.extend_from_slice(&[0xAA; 24]); // 24-octet payload -> MSDU 20 -> IP path
        let m = run(&[(hdr(Mac::default(), Mac::default(), TYPE_DATA, 0, true), body)]);
        let r = &m[&Mac::default()];
        assert_eq!(r.arp_keystreams.len(), 1);
        assert_eq!(r.arp_keystreams[0].df_index, Some(14));
    }

    #[test]
    fn dst_hint_maps_group_macs_to_l3() {
        // FR-WEP-6: multicast/broadcast group MACs map to an L3 family; a unicast
        // address carries no signal.
        assert_eq!(dst_hint(Mac::from_bytes([0x33, 0x33, 0, 0, 0, 1])), DstHint::Ipv6); // ff02::1
        assert_eq!(dst_hint(Mac::from_bytes([0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa])), DstHint::Ipv4); // SSDP
        assert_eq!(dst_hint(Mac::from_bytes([0xff; 6])), DstHint::Ipv4); // broadcast (DHCP)
        assert_eq!(dst_hint(Mac::from_bytes([0x01, 0x80, 0xc2, 0, 0, 3])), DstHint::Eapol); // PAE group
        assert_eq!(dst_hint(Mac::from_bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])), DstHint::Unknown); // unicast
    }

    #[test]
    fn ipv6_nd_frame_is_mined_with_correct_known_plaintext() {
        // FR-WEP-6: a WEP data frame to an IPv6 multicast DA (33:33:..) is recognized
        // as IPv6 and mined with the ND known plaintext (`EtherType` 86DD, next-header
        // `ICMPv6` 0x3A, hop-limit 0xFF) -- not the IPv4-shaped guess that would mis-key
        // every octet from the `EtherType` on.
        let known = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x86, 0xDD, 0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3A, 0xFF];
        let mut payload = known.to_vec();
        payload.resize(60, 0); // MSDU 56 -> IPv6 payload length 8, matching known[12..14]
        let mut body = vec![0x01, 0x02, 0x03, 0x00]; // IV + key-id octet
        body.extend_from_slice(&payload);
        let dst = Mac::from_bytes([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // ff02::1 all-nodes
        let r = &run(&[(data_hdr_to(Mac::default(), dst), body)])[&Mac::default()];
        assert_eq!(r.arp_keystreams.len(), 1, "an IPv6 ND sample is harvested");
        assert_eq!(r.arp_keystreams[0].df_index, None, "IPv6 sample has no IPv4 DF octet");
        // payload equals the known plaintext over the prefix, so keystream is zero --
        // proving the IPv6 ND known plaintext (not the IPv4 guess) was applied.
        assert_eq!(&r.arp_keystreams[0].keystream()[..16], &[0u8; 16], "IPv6 ND known plaintext applied");
    }

    #[test]
    fn eapol_frame_uses_dot1x_ethertype() {
        // FR-WEP-6: a frame to the 802.1X PAE group address is mined with the EAPOL
        // SNAP + `EtherType` (0x888E), where the generic 0x08 SNAP guess is wrong.
        let mut payload = EAPOL_KNOWN.to_vec();
        payload.resize(20, 0);
        let mut body = vec![0x09, 0x09, 0x09, 0x00];
        body.extend_from_slice(&payload);
        let dst = Mac::from_bytes([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);
        let r = &run(&[(data_hdr_to(Mac::default(), dst), body)])[&Mac::default()];
        assert_eq!(r.arp_keystreams.len(), 1);
        assert_eq!(&r.arp_keystreams[0].keystream()[..8], &[0u8; 8], "EAPOL known plaintext applied");
    }

    #[test]
    fn ipv4_multicast_recognized_as_ip() {
        // FR-WEP-6: a frame to the mDNS multicast MAC (01:00:5e:00:00:fb) is confirmed
        // IPv4 and mined with the IPv4 known plaintext (DF octet marked for voting).
        let mut body = vec![0x01, 0x02, 0x03, 0x00];
        body.extend_from_slice(&[0xAA; 24]); // MSDU 20 -> IP path
        let dst = Mac::from_bytes([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        let r = &run(&[(data_hdr_to(Mac::default(), dst), body)])[&Mac::default()];
        assert_eq!(r.arp_keystreams.len(), 1);
        assert_eq!(r.arp_keystreams[0].df_index, Some(14), "IPv4 DF octet marked for two-keystream voting");
    }

    #[test]
    fn extended_iv_data_is_wpa_not_harvested() {
        // FR-WEP-1: ExtIV set -> TKIP/CCMP, classified WPA, no IV harvested.
        let body = vec![0x01, 0x02, 0x03, 0x20, 0, 0, 0, 0, 0];
        let r = &run(&[(hdr(Mac::default(), Mac::default(), TYPE_DATA, 0, true), body)])[&Mac::default()];
        assert_eq!(r.encryption(), Encryption::Wpa);
        assert_eq!(r.wep_data_frames, 0);
        assert!(r.ivs.is_empty());
    }

    #[test]
    fn shared_key_auth_recovers_keystream_and_classifies_wep() {
        // FR-WEP-4: frame 2 challenge + WEP-encrypted frame 3 -> recovered keystream,
        // and the BSSID classifies as WEP from the auth frame alone (no beacon).
        let ap = Mac::from_bytes([1, 1, 1, 1, 1, 1]);
        let sta = Mac::from_bytes([2, 2, 2, 2, 2, 2]);
        let challenge: Vec<u8> = (0..16u8).collect();
        let keystream: Vec<u8> = (0..40u8).map(|b| b.wrapping_mul(3)).collect();

        // Frame 2 (cleartext): alg=1, seq=2, status=0, Challenge IE.
        let mut f2 = vec![0x01, 0x00, 0x02, 0x00, 0x00, 0x00, IE_CHALLENGE, challenge.len() as u8];
        f2.extend_from_slice(&challenge);

        // Frame 3 (WEP): IV(4) + RC4(plaintext) + ICV(4); plaintext known.
        let mut plaintext = vec![0x01, 0x00, 0x03, 0x00, 0x00, 0x00, IE_CHALLENGE, challenge.len() as u8];
        plaintext.extend_from_slice(&challenge);
        plaintext.extend_from_slice(&[0u8; 4]); // ICV placeholder
        let cipher: Vec<u8> = plaintext.iter().zip(keystream.iter().cycle()).map(|(p, k)| p ^ k).collect();
        let mut f3 = vec![0x09, 0x09, 0x09, 0x00]; // IV + key-id octet
        f3.extend_from_slice(&cipher);

        let m = run(&[
            (hdr(ap, sta, TYPE_MANAGEMENT, SUBTYPE_AUTH, false), f2),
            (hdr(ap, sta, TYPE_MANAGEMENT, SUBTYPE_AUTH, true), f3),
        ]);
        let r = &m[&ap];
        assert_eq!(r.encryption(), Encryption::Wep);
        assert_eq!(r.wep_auth_frames, 1);
        let ks = r.ska_keystream.as_ref().expect("ska keystream recovered");
        // The recovered keystream over the known prefix must match what we used.
        let known_len = 8 + challenge.len();
        assert_eq!(&ks[..known_len], &keystream.iter().cycle().take(known_len).copied().collect::<Vec<_>>()[..]);
    }
}
