//! 802.11 Information Element (tagged parameter) parser: the defensive TLV
//! iterator and the vendor-IE matcher. Ported from `WPAWolf` (C9); the
//! WPS/credential parsing is dropped (WPA-specific).
//!
//! Each IE is a TLV triplet: tag (u8), length (u8), value (length octets). The
//! iterator is defensive -- a truncated or length-overrun IE stops iteration
//! rather than panicking or skipping to the wrong offset.

// --- IE TLV iterator ---

/// A single parsed Information Element from a 802.11 tagged parameter block.
///
/// Per [IEEE 802.11-2024] §9.4.2, every IE is a 1-byte Element ID, 1-byte
/// length, and `length` value octets. Common IDs: 0=SSID, 48=RSN, 221=Vendor.
#[derive(Debug, Clone, Copy)]
pub struct Ie<'a> {
    /// Element ID (tag byte). Common values: 0=SSID, 48=RSN, 221=Vendor.
    pub id: u8,
    /// Element value octets (not including the ID or Length fields).
    pub value: &'a [u8],
}

/// Iterator over Information Elements in a 802.11 tagged parameter block.
///
/// Stops cleanly at end-of-data or on a truncated IE (never panics). Callers
/// typically iterate once and filter by `ie.id`. Per [IEEE 802.11-2024] §9.4.2.
pub struct IeIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl core::fmt::Debug for IeIter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IeIter")
            .field("pos", &self.pos)
            .field("remaining", &self.data.len().saturating_sub(self.pos))
            .finish()
    }
}

impl<'a> IeIter<'a> {
    /// Creates an iterator over the tagged parameter block starting at `data[0]`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for IeIter<'a> {
    type Item = Ie<'a>;

    fn next(&mut self) -> Option<Ie<'a>> {
        // Per [IEEE 802.11-2024] §9.4.2: each IE is [ID (1)][Length (1)][Value (Length)].
        // Fewer than 2 bytes remaining means no complete IE header -- stop.
        let id = *self.data.get(self.pos)?;
        let len = *self.data.get(self.pos + 1)? as usize;
        let value_start = self.pos + 2;
        let value_end = value_start + len;
        // A value_end overrun means the IE is truncated -- stop rather than panic.
        let value = self.data.get(value_start..value_end)?;
        self.pos = value_end;
        Some(Ie { id, value })
    }
}

/// Creates an iterator over Information Elements in `data`.
///
/// `data` is the tagged parameter block -- the part of a Beacon, `ProbeResponse`,
/// etc. following the fixed fields. Iteration stops cleanly on truncation.
#[must_use]
pub const fn iter_ies(data: &[u8]) -> IeIter<'_> {
    IeIter::new(data)
}

// --- Vendor IE helper ---

/// Wi-Fi Alliance (Microsoft/WFA) OUI `00:50:F2`, used by the WPA (type 1)
/// vendor IE that marks a pre-RSN WPA1 BSSID. Per [IEEE 802.11-2024] §9.4.2.25.
pub const OUI_WFA: [u8; 3] = [0x00, 0x50, 0xF2];

/// Element ID for Vendor-Specific IEs. Per [IEEE 802.11-2024] §9.4.2.25, Table 9-92.
const IE_ID_VENDOR: u8 = 221;

/// Returns `Some(body)` if `ie` is a vendor IE matching the given OUI and type.
///
/// Vendor IEs (Element ID 221) per [IEEE 802.11-2024] §9.4.2.25 have the layout
/// OUI (3 octets) + Type (1 octet) + body. Returns the body after that prefix,
/// or `None` if the IE is too short or the OUI/type do not match.
#[must_use]
pub fn vendor_ie_body<'a>(ie: &Ie<'a>, oui: [u8; 3], ie_type: u8) -> Option<&'a [u8]> {
    if ie.id != IE_ID_VENDOR {
        return None;
    }
    // value must be at least 4 octets: 3 OUI + 1 type.
    let prefix = ie.value.get(0..4)?;
    if prefix.get(0..3)? != oui {
        return None;
    }
    if *prefix.get(3)? != ie_type {
        return None;
    }
    ie.value.get(4..)
}
