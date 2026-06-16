//! WEP MPDU body parsing (FR-WEP-2): extract the IV, Key ID, and payload.
//!
//! The 4-octet IV field splits into the 24-bit IV, the 2-bit Key ID, and the
//! Extended-IV bit, followed by the encrypted Data+ICV. Per [IEEE 802.11-2007]
//! §8.2.1.2. WEP leaves the Extended-IV bit clear; TKIP/CCMP set it, which is how
//! a WEP frame is told apart from a WPA one without decrypting.

/// The 4-octet WEP IV field: IV(3) + Key-ID octet. Per [IEEE 802.11-2007] §8.2.1.2.
const IV_FIELD_LEN: usize = 4;
/// The trailing 4-octet ICV (encrypted). Per [IEEE 802.11-2007] §8.2.1.4.
const ICV_LEN: usize = 4;
/// Extended IV bit (bit 5 of the Key-ID octet): clear for WEP, set for TKIP/CCMP.
const EXT_IV_BIT: u8 = 0x20;

/// A parsed view over a WEP MPDU body.
#[derive(Debug, Clone, Copy)]
pub struct WepView<'a> {
    /// The 24-bit IV in transmission order (the RC4 seed prefix).
    pub iv: [u8; 3],
    /// The default-key index (0..3) from bits 6-7 of the Key-ID octet.
    pub key_id: u8,
    /// The Extended-IV bit: when set the frame is TKIP/CCMP, not WEP.
    pub ext_iv: bool,
    /// The encrypted Data+ICV (everything after the 4-octet IV field).
    pub payload: &'a [u8],
}

/// Parse a frame body as a WEP MPDU. Returns `None` if it is too short to hold an
/// IV field plus the trailing ICV.
#[must_use]
pub fn parse(body: &[u8]) -> Option<WepView<'_>> {
    let field = body.get(..IV_FIELD_LEN)?;
    let payload = body.get(IV_FIELD_LEN..)?;
    if payload.len() < ICV_LEN {
        return None;
    }
    let iv = [*field.first()?, *field.get(1)?, *field.get(2)?];
    let key_id_octet = *field.get(3)?;
    Some(WepView { iv, key_id: key_id_octet >> 6, ext_iv: key_id_octet & EXT_IV_BIT != 0, payload })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_iv_keyid_and_payload() {
        // IV = 01 02 03, Key-ID octet = 0x40 (key_id=1, ext_iv clear), then data+icv.
        let body = [0x01, 0x02, 0x03, 0x40, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let v = parse(&body).expect("valid WEP body");
        assert_eq!(v.iv, [0x01, 0x02, 0x03]);
        assert_eq!(v.key_id, 1);
        assert!(!v.ext_iv);
        assert_eq!(v.payload, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn flags_extended_iv() {
        // Key-ID octet 0x20 sets the Extended-IV bit -> TKIP/CCMP, not WEP.
        let body = [0x01, 0x02, 0x03, 0x20, 0, 0, 0, 0];
        assert!(parse(&body).expect("parses").ext_iv);
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse(&[0x01, 0x02, 0x03, 0x00, 0x00]).is_none()); // payload < ICV
        assert!(parse(&[0x01, 0x02]).is_none()); // no IV field
    }
}
