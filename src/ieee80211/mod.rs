//! IEEE 802.11 MAC frame and Information Element parsing, ported from `WPAWolf` (C9).
//!
//! **Citation note (C7 documented deviation).** The ported parsers carry the IEEE 802.11-2024 section numbers they had in `WPAWolf` (§9.2.4, §9.3.2.1, §9.4.2). The MAC frame and IE wire formats are edition-stable, so these map directly onto the WEPWolf-mandated IEEE 802.11-2007 references: frame control and addresses are 2007 §7.1.3 / §7.2; Information Elements are 2007 §7.3.2; and the WEP-specific frame body (IV / Key ID / ICV) is 2007 §8.2.1, parsed in the `wep` layer. WPA/EAPOL/WPS/A-MSDU machinery is not ported.

pub mod frame;
pub mod ie;
