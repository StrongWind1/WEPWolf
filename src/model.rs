//! Core domain types shared across the pipeline.
//!
//! The BSSID address, the WEP key and its length class, and the per-BSSID
//! bundle of recovered material an attack consumes. Per [IEEE 802.11-2007]
//! section 8.2.1.

use std::fmt;

/// The BSSID/MAC address type, shared with the ported capture parser
/// (`crate::types::MacAddr`).
pub use crate::types::MacAddr as Mac;

/// The three real WEP key lengths. The 16-octet "152-bit" vendor extension is
/// deliberately absent -- aircrack-ng accepts only these, and so do we (C6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyLen {
    /// WEP-40: 5-octet secret ("64-bit" with the 24-bit IV).
    Wep40,
    /// WEP-104: 13-octet secret ("128-bit").
    Wep104,
    /// WEP-232: 29-octet secret ("256-bit").
    Wep232,
}

impl KeyLen {
    /// Secret length in octets (5 / 13 / 29).
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Wep40 => 5,
            Self::Wep104 => 13,
            Self::Wep232 => 29,
        }
    }

    /// Nominal key strength in bits (40 / 104 / 232).
    #[must_use]
    pub const fn bits(self) -> u16 {
        match self {
            Self::Wep40 => 40,
            Self::Wep104 => 104,
            Self::Wep232 => 232,
        }
    }

    /// Classify a secret length in octets, rejecting anything that is not a real
    /// WEP key size (notably the 16-octet "152-bit" extension).
    #[must_use]
    pub const fn from_byte_len(n: usize) -> Option<Self> {
        match n {
            5 => Some(Self::Wep40),
            13 => Some(Self::Wep104),
            29 => Some(Self::Wep232),
            _ => None,
        }
    }

    /// All lengths shortest-first -- the order attacks consider them, since the
    /// statistical attacks recover length implicitly and none is prioritised.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Wep40, Self::Wep104, Self::Wep232]
    }

    /// Parse a user-supplied key strength in bits (40 / 104 / 232), rejecting
    /// anything that is not a real WEP size. Backs the `--keylen` CLI filter.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Self> {
        match bits {
            40 => Some(Self::Wep40),
            104 => Some(Self::Wep104),
            232 => Some(Self::Wep232),
            _ => None,
        }
    }
}

/// A recovered WEP secret. Stored in a fixed 29-octet buffer with a length
/// class so the type is `Copy` and never larger than the maximum key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WepKey {
    len: KeyLen,
    bytes: [u8; 29],
}

impl WepKey {
    /// Build a key from exactly 5, 13, or 29 octets; any other length is `None`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Option<Self> {
        let len = KeyLen::from_byte_len(bytes.len())?;
        let mut buf = [0u8; 29];
        buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self { len, bytes: buf })
    }

    /// The key's length class.
    #[must_use]
    pub const fn len(self) -> KeyLen {
        self.len
    }

    /// The secret octets (5 / 13 / 29 of them).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len.byte_len()).unwrap_or(&[])
    }
}

impl fmt::Display for WepKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, byte) in self.as_slice().iter().enumerate() {
            if idx > 0 {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A captured IV paired with keystream recovered from known plaintext (ARP or
/// LLC/SNAP headers). The statistical attacks (M4+) consume these.
#[derive(Debug, Clone, Copy)]
pub struct IvSample {
    /// The 24-bit IV in transmission order.
    pub iv: [u8; 3],
    /// Recovered keystream octets (only the first `ks_len` are valid).
    pub keystream: [u8; 32],
    /// Count of valid octets in `keystream`.
    pub ks_len: u8,
    /// For an IPv4-derived sample, the keystream index of the IPv4 flags octet
    /// (the Don't-Fragment byte), whose plaintext is `0x40` (~85%) or `0x00`
    /// (~15%). `None` for ARP / LLC-SNAP / SKA samples whose prefix is fully
    /// known. The statistical attacks vote this octet both ways (FR-ATK-PTW-1).
    pub df_index: Option<u8>,
    /// The WEP default-key slot (Key ID 0-3) the frame was encrypted under. An AP
    /// can run up to four keys at once; samples from different slots use different
    /// key schedules, so the attacks must not pool their votes (FR-ATK-SLOT-1).
    /// Defaults to 0; set per frame by `crate::classify`.
    pub key_id: u8,
}

impl IvSample {
    /// Build a sample from an IV and recovered keystream (truncated to 32 octets).
    #[must_use]
    pub fn new(iv: [u8; 3], keystream: &[u8]) -> Self {
        Self::with_df(iv, keystream, None)
    }

    /// Build an IPv4-derived sample, marking the Don't-Fragment keystream octet at
    /// `df_index` as dual-valued so the attacks vote it both ways.
    #[must_use]
    pub fn new_ip(iv: [u8; 3], keystream: &[u8], df_index: u8) -> Self {
        Self::with_df(iv, keystream, Some(df_index))
    }

    /// Shared constructor copying the keystream and recording the DF marker.
    #[must_use]
    fn with_df(iv: [u8; 3], keystream: &[u8], df_index: Option<u8>) -> Self {
        let mut buf = [0u8; 32];
        let n = keystream.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), keystream.get(..n)) {
            dst.copy_from_slice(src);
        }
        Self { iv, keystream: buf, ks_len: u8::try_from(n).unwrap_or(32), df_index, key_id: 0 }
    }

    /// Tag this sample with the WEP key slot it was encrypted under (FR-ATK-SLOT-1).
    /// A builder so the existing constructors stay slot-agnostic (default slot 0).
    #[must_use]
    pub const fn with_key_id(mut self, key_id: u8) -> Self {
        self.key_id = key_id;
        self
    }

    /// The valid keystream octets.
    #[must_use]
    pub fn keystream(&self) -> &[u8] {
        self.keystream.get(..usize::from(self.ks_len)).unwrap_or(&[])
    }
}

/// One WEP-encrypted MPDU retained for verification: its 24-bit IV and the
/// still-encrypted Data+ICV octets (the transmitted ICV is the encrypted tail).
#[derive(Debug, Clone)]
pub struct EncFrame {
    /// The 24-bit IV in transmission order (the RC4 seed prefix).
    pub iv: [u8; 3],
    /// The encrypted Data+ICV (at least 4 octets).
    pub data: Vec<u8>,
    /// The WEP default-key slot (Key ID 0-3) this frame was encrypted under, so
    /// the verifier can confirm a per-slot key against frames of its own slot
    /// (FR-ATK-SLOT-1). Defaults to 0.
    pub key_id: u8,
}

/// The encryption a BSSID uses, resolved from its observed frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// No confidentiality (no Privacy bit, no crypto IE).
    Open,
    /// WEP (Privacy bit without RSN/WPA, a WEP data frame, or a Shared-Key auth frame).
    Wep,
    /// WPA/WPA2/WPA3 (RSN or WPA IE, or a Protected data frame with Extended IV).
    Wpa,
    /// Insufficient evidence to classify.
    Unknown,
}

/// The heavy per-BSSID attack material, boxed inside [`BssidWep`].
///
/// A non-WEP BSSID -- which never harvests any -- pays a single null pointer
/// instead of four empty collections. On a real corpus the BSSID map is
/// overwhelmingly non-WEP (WPA/open/unknown), so keeping those records lean is
/// what bounds the ingest-time peak memory (FR-IN-5).
#[derive(Debug, Clone, Default)]
pub struct WepMaterial {
    /// IV + short-keystream samples for FMS / `KoreK` / bias.
    pub ivs: Vec<IvSample>,
    /// IV + long-keystream samples from known plaintext -- ARP's fixed header or
    /// the reconstructed IPv4 header -- long enough to drive WEP-104+ PTW.
    pub arp_keystreams: Vec<IvSample>,
    /// Keystream recovered from a Shared-Key authentication exchange, if seen.
    pub ska_keystream: Option<Vec<u8>>,
    /// A few full WEP frames retained for the `Verifier` (the accept path).
    pub enc_frames: Vec<EncFrame>,
}

/// Everything `WEPWolf` has gathered for one BSSID.
///
/// The classification evidence and frame counts are always present; the heavy WEP
/// attack material is boxed in [`WepMaterial`] and allocated lazily on the first
/// WEP frame, so the WPA/open/unknown majority keep `material == None` and stay
/// small. Populated by the scan/harvest stage (`crate::classify`); consumed by the
/// attack engine. Read the material through [`BssidWep::ivs`] /
/// [`BssidWep::arp_keystreams`] / [`BssidWep::enc_frames`] /
/// [`BssidWep::ska_keystream`]; mutate it through [`BssidWep::material_mut`].
#[derive(Debug, Clone, Default)]
pub struct BssidWep {
    /// The access point's BSSID.
    pub bssid: Mac,
    /// The advertised ESSID, if a beacon/probe carried it.
    pub essid: Option<Vec<u8>>,
    /// Harvested WEP attack material, allocated on the first WEP frame; `None` for
    /// a BSSID that never showed WEP traffic, so non-WEP records stay small.
    pub material: Option<Box<WepMaterial>>,
    /// Bitmask of WEP Key IDs (0..3) observed in this BSSID's traffic.
    pub key_ids_seen: u8,
    /// Count of WEP-encrypted data frames seen.
    pub wep_data_frames: u64,
    /// Count of WEP-encrypted Shared-Key authentication frames seen.
    pub wep_auth_frames: u64,
    /// A Beacon or Probe Response was seen.
    pub saw_beacon: bool,
    /// The Capability Privacy bit was set.
    pub saw_privacy: bool,
    /// An RSN or WPA vendor IE was present.
    pub saw_crypto_ie: bool,
    /// A Protected data frame without the Extended IV bit (WEP) was seen.
    pub saw_wep_data: bool,
    /// A Protected data frame with the Extended IV bit (TKIP/CCMP) was seen.
    pub saw_wpa_data: bool,
    /// A WEP-encrypted Shared-Key authentication frame was seen.
    pub saw_wep_auth: bool,
}

impl BssidWep {
    /// Full frames retained for verification (two suffice; a few guard against
    /// the rare corrupt frame).
    const MAX_ENC_FRAMES: usize = 8;

    /// The IV/short-keystream samples (empty when no WEP material was harvested).
    #[must_use]
    pub fn ivs(&self) -> &[IvSample] {
        self.material.as_deref().map_or(&[], |m| m.ivs.as_slice())
    }

    /// The long-keystream (ARP/IPv4/IPv6/SKA) samples for PTW (empty when none).
    #[must_use]
    pub fn arp_keystreams(&self) -> &[IvSample] {
        self.material.as_deref().map_or(&[], |m| m.arp_keystreams.as_slice())
    }

    /// The full frames retained for the `Verifier` accept path (empty when none).
    #[must_use]
    pub fn enc_frames(&self) -> &[EncFrame] {
        self.material.as_deref().map_or(&[], |m| m.enc_frames.as_slice())
    }

    /// The recovered Shared-Key-auth keystream, if one was captured.
    #[must_use]
    pub fn ska_keystream(&self) -> Option<&[u8]> {
        self.material.as_deref().and_then(|m| m.ska_keystream.as_deref())
    }

    /// Mutable access to the attack material, allocating the box on first use.
    /// Called only on the WEP harvest path, so non-WEP records never allocate it.
    pub fn material_mut(&mut self) -> &mut WepMaterial {
        self.material.get_or_insert_with(|| Box::new(WepMaterial::default()))
    }

    /// Build a record already carrying `material` (a concise constructor for
    /// utility code and tests; the harvester uses [`BssidWep::material_mut`]).
    #[must_use]
    pub fn with_material(material: WepMaterial) -> Self {
        Self { material: Some(Box::new(material)), ..Default::default() }
    }

    /// Resolve the accumulated evidence to a single classification. WPA evidence
    /// outranks WEP (a WPA beacon also sets the Privacy bit), which outranks open.
    #[must_use]
    pub const fn encryption(&self) -> Encryption {
        if self.saw_crypto_ie || self.saw_wpa_data {
            Encryption::Wpa
        } else if self.saw_wep_data || self.saw_wep_auth || (self.saw_beacon && self.saw_privacy) {
            Encryption::Wep
        } else if self.saw_beacon {
            Encryption::Open
        } else {
            Encryption::Unknown
        }
    }

    /// Retain a full WEP frame for the verifier, up to the cap *per key slot*.
    ///
    /// The cap is per Key ID so a multi-slot AP keeps verifiable frames for every
    /// slot (FR-ATK-SLOT-1): a per-slot recovered key needs two frames of its own
    /// slot to confirm, and a first-come global cap could fill with one busy slot.
    pub fn retain_enc_frame(&mut self, frame: EncFrame) {
        let m = self.material_mut();
        if m.enc_frames.iter().filter(|f| f.key_id == frame.key_id).count() < Self::MAX_ENC_FRAMES {
            m.enc_frames.push(frame);
        }
    }

    /// Fold another record for the same BSSID into this one (FR-IN-3, FR-IN-6).
    ///
    /// When the inputs are scanned in parallel, the same access point can appear in
    /// several files; each file builds an independent record and they are merged
    /// here in input-file order, so the result is identical to a sequential scan
    /// regardless of thread scheduling. Material concatenates, counts add, and the
    /// evidence flags OR together; the ESSID and SKA keystream are taken from the
    /// first file that carried them, and retained full frames stop at the cap.
    pub fn merge_from(&mut self, other: Self) {
        if self.essid.is_none() {
            self.essid = other.essid;
        }
        // Merge the heavy material only when the other record harvested some, so a
        // non-WEP merge never allocates a box (keeps the WPA/open majority lean).
        if let Some(om) = other.material {
            let m = self.material_mut();
            m.ivs.extend(om.ivs);
            m.arp_keystreams.extend(om.arp_keystreams);
            if m.ska_keystream.is_none() {
                m.ska_keystream = om.ska_keystream;
            }
            for frame in om.enc_frames {
                // Per-slot cap, mirroring `retain_enc_frame` (inlined to avoid re-borrowing self).
                if m.enc_frames.iter().filter(|f| f.key_id == frame.key_id).count() < Self::MAX_ENC_FRAMES {
                    m.enc_frames.push(frame);
                }
            }
        }
        self.key_ids_seen |= other.key_ids_seen;
        self.wep_data_frames += other.wep_data_frames;
        self.wep_auth_frames += other.wep_auth_frames;
        self.saw_beacon |= other.saw_beacon;
        self.saw_privacy |= other.saw_privacy;
        self.saw_crypto_ie |= other.saw_crypto_ie;
        self.saw_wep_data |= other.saw_wep_data;
        self.saw_wpa_data |= other.saw_wpa_data;
        self.saw_wep_auth |= other.saw_wep_auth;
    }
}
