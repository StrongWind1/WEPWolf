//! WEP frame carving (FR-OUT-6).
//!
//! Write the frames wepwolf parsed for a WEP network to a standalone pcap, so a
//! messy multi-file capture set collapses into one self-contained capture both wepwolf
//! and aircrack-ng can crack.
//!
//! Two frame classes are written, for every BSSID classified WEP:
//! - every WEP crack frame (WEP-encrypted data, and Shared-Key auth frames),
//!   streamed as it is parsed so memory stays bounded (FR-IN-5);
//! - a few beacon/probe frames per BSSID, carrying the ESSID, buffered and
//!   written at the end once the WEP classification is known.
//!
//! Frames are written post-link-strip as raw IEEE 802.11 (LINKTYPE 105), so the
//! mixed radiotap/Prism/AVS link layers of the inputs all normalise to one link
//! type -- exactly the set wepwolf's parser (with its tiered header recovery)
//! recovers, which a generic dissector cannot reproduce. Timestamps are zeroed so
//! the output is deterministic and order-independent.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write as _};
use std::path::Path;

use crate::model::{BssidWep, Encryption, Mac};

/// `LINKTYPE_IEEE802_11`: raw 802.11 MPDU with no link header and no FCS -- what
/// remains after the scanner strips radiotap/Prism/AVS and the trailing FCS.
const LINKTYPE_IEEE802_11: u32 = 105;
/// Classic pcap little-endian, microsecond magic.
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
/// Snap length: the largest 802.11 MPDU is well under this.
const SNAPLEN: u32 = 65_535;
/// Beacons/probes retained per BSSID -- enough to carry the ESSID without letting
/// a long capture's periodic beacons grow unbounded (FR-IN-5).
const MAX_BEACONS_PER_BSSID: usize = 4;

/// Streams parsed WEP frames to a pcap and buffers WEP-network beacons.
#[derive(Debug)]
pub struct Carver {
    /// The output pcap (classic, LINKTYPE 105).
    out: BufWriter<File>,
    /// Beacon/probe frames per BSSID, capped, written for WEP BSSIDs at finish.
    beacons: BTreeMap<Mac, Vec<Vec<u8>>>,
    /// First write error, if any; reported by [`Carver::finish`].
    err: Option<io::Error>,
    /// Count of frames written so far (for the closing report).
    written: u64,
}

impl Carver {
    /// Create the pcap and write its global header.
    ///
    /// # Errors
    /// Propagates the I/O error if the file cannot be created or the header written.
    pub fn create(path: &Path) -> io::Result<Self> {
        let mut out = BufWriter::new(File::create(path)?);
        out.write_all(&PCAP_MAGIC.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?; // version major
        out.write_all(&4u16.to_le_bytes())?; // version minor
        out.write_all(&0i32.to_le_bytes())?; // thiszone (UTC)
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&SNAPLEN.to_le_bytes())?;
        out.write_all(&LINKTYPE_IEEE802_11.to_le_bytes())?;
        Ok(Self { out, beacons: BTreeMap::new(), err: None, written: 0 })
    }

    /// Write a WEP crack frame now (timestamp zeroed). Best-effort: the first
    /// error is stored and surfaced by [`Carver::finish`].
    pub fn wep_frame(&mut self, frame: &[u8]) {
        if self.err.is_some() {
            return;
        }
        match self.write_record(frame) {
            Ok(()) => self.written += 1,
            Err(e) => self.err = Some(e),
        }
    }

    /// Buffer a beacon/probe for its BSSID (capped); written at finish if WEP.
    pub fn beacon(&mut self, ap: Mac, frame: &[u8]) {
        let slot = self.beacons.entry(ap).or_default();
        if slot.len() < MAX_BEACONS_PER_BSSID {
            slot.push(frame.to_vec());
        }
    }

    /// Flush the buffered beacons of every WEP BSSID and close the file.
    ///
    /// # Errors
    /// Returns the first write error encountered (during streaming or here).
    pub fn finish(mut self, bssids: &BTreeMap<Mac, BssidWep>) -> io::Result<u64> {
        let beacons = std::mem::take(&mut self.beacons);
        for (mac, frames) in &beacons {
            if self.err.is_none() && bssids.get(mac).is_some_and(|b| b.encryption() == Encryption::Wep) {
                for frame in frames {
                    match self.write_record(frame) {
                        Ok(()) => self.written += 1,
                        Err(e) => {
                            self.err = Some(e);
                            break;
                        },
                    }
                }
            }
        }
        self.out.flush()?;
        match self.err.take() {
            Some(e) => Err(e),
            None => Ok(self.written),
        }
    }

    /// Write one pcap record with a zeroed timestamp and the frame verbatim.
    fn write_record(&mut self, frame: &[u8]) -> io::Result<()> {
        let len = u32::try_from(frame.len()).map_err(|_| io::Error::other("frame exceeds pcap record length"))?;
        self.out.write_all(&0u32.to_le_bytes())?; // ts_sec = 0
        self.out.write_all(&0u32.to_le_bytes())?; // ts_usec = 0
        self.out.write_all(&len.to_le_bytes())?; // incl_len
        self.out.write_all(&len.to_le_bytes())?; // orig_len
        self.out.write_all(frame)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{Carver, LINKTYPE_IEEE802_11, PCAP_MAGIC};
    use crate::model::{BssidWep, Mac};

    #[test]
    fn writes_a_valid_pcap_header_and_records() {
        let dir = std::env::temp_dir().join(format!("wepwolf-carve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("carve.pcap");

        // A WEP BSSID with a beacon buffered, plus a streamed crack frame.
        let ap = Mac::from_bytes([1, 2, 3, 4, 5, 6]);
        let mut bssids: BTreeMap<Mac, BssidWep> = BTreeMap::new();
        let mut rec = BssidWep { bssid: ap, ..Default::default() };
        rec.saw_beacon = true;
        rec.saw_privacy = true; // -> classified WEP
        bssids.insert(ap, rec);

        let mut carver = Carver::create(&path).unwrap();
        carver.wep_frame(&[0xAA; 40]); // a crack frame, written now
        carver.beacon(ap, &[0xBB; 30]); // a beacon, written at finish (WEP BSSID)
        let written = carver.finish(&bssids).unwrap();
        assert_eq!(written, 2, "one crack frame + one WEP beacon");

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[0..4], &PCAP_MAGIC.to_le_bytes(), "pcap magic");
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), LINKTYPE_IEEE802_11);
        // 24-byte global header + 2 records (16-byte rec header each + 40 + 30 data).
        assert_eq!(bytes.len(), 24 + (16 + 40) + (16 + 30));
        // Timestamps are zeroed.
        assert_eq!(&bytes[24..32], &[0u8; 8]);
    }

    #[test]
    fn skips_beacons_of_non_wep_bssids() {
        let dir = std::env::temp_dir().join(format!("wepwolf-carve2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("carve.pcap");
        let ap = Mac::from_bytes([9, 9, 9, 9, 9, 9]);
        // An open BSSID (beacon, no privacy) -> not WEP -> its beacon is dropped.
        let mut bssids: BTreeMap<Mac, BssidWep> = BTreeMap::new();
        bssids.insert(ap, BssidWep { bssid: ap, saw_beacon: true, ..Default::default() });
        let mut carver = Carver::create(&path).unwrap();
        carver.beacon(ap, &[0xBB; 30]);
        assert_eq!(carver.finish(&bssids).unwrap(), 0, "open BSSID beacons are not carved");
    }
}
