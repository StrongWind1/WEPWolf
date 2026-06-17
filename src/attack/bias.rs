//! The Sepehrdad RC4-bias database (FR-ATK-1; reported as `bias`).
//!
//! This is the full "Smashing WEP in a Passive Attack" key-recovery database
//! ([Sepehrdad-Vaudenay-Vuagnoux, FSE 2013], Table 1) -- the most efficient
//! passive WEP attack published, and the one aircrack-ng does **not** ship (it
//! carries only FMS/KoreK and Klein-PTW). Every bias estimates the *same*
//! cumulative key sum `Kbar[i] = K[0] + .. + K[i]` from a single packet, so they all
//! vote into one per-position table that the shared PTW search
//! (`crate::attack::ptw::search_sigma_table`) then resolves into a key the
//! `Verifier` accepts (C4). Voting many weak biases together is what pushes the
//! packets-needed below PTW's: where Klein-alone wants ~40k and PTW similar, the
//! database converges from far fewer.
//!
//! The frame is *key-independent* (the Vaudenay-Vuagnoux reduction): the KSA is
//! simulated over the 3 clear IV octets only (`t = 2`), giving a permutation `S`
//! (and its inverse `Sinv`) and the per-round `j` history; `sigma_i(t)` is then
//! `j2 + S[3] + .. + S[q]` for paper index `q = 3 + i`. Each bias contributes a
//! candidate `f - sigma_i(t)` for `Kbar[i]` when its condition `g` holds. The KoreK
//! `A_*` rows reuse aircrack-ng's `K_COEFF` reliability weights; the
//! Klein/Maitra-Paul/SVV weights are scaled to their published biases. Conditions
//! and candidates are transcribed from Table 1, cross-checked against
//! aircrack-ng's KoreK voting block (`src/aircrack-ng/aircrack-ng.c`) for the
//! exact `A_neg` constants (C5, C7).
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    reason = "byte-permute KSA over a 256-octet state indexed by u8-derived values in range by construction; KoreK / Klein / Maitra-Paul / SVV are attack names"
)]

use super::Attack;
use crate::attack::ptw::search_sigma_table;
use crate::model::{BssidWep, KeyLen, WepKey};
use crate::wep::Verifier;

// --- Vote weights (optimal coefficient a_opt) ---
// Each weight is `round(64 * a_opt)`, where a_opt is the FSE-2013 optimal voting
// coefficient ([Sepehrdad-Vaudenay-Vuagnoux, FSE 2013] §7):
//     a_opt = (p - 1/N) / [ (p - 1/N) + (2/N)(1 - 1/N)(1 - q/N) ]
// p = P[candidate correct | condition], q = P[condition], N = 256. Unlike a flat
// per-attack weight, a_opt gives a bias influence proportional to how decisive it
// is *when it fires*: the rare KoreK correlations (u15, s13, u13_*, u5_2, ...)
// are near-certain (p ~ 20-50/N) and so outweigh the ever-present but weak Klein
// (p ~ 1.32/N) per vote. p,q are measured by the `measure_aopt_weights` test;
// biases too sparse to measure here (the i=4 cases, SVV_10 at WEP-232) keep a
// conservative theory weight. The negative attacks keep aircrack's -20 penalty.
const W_KLEIN: i32 = 13;
const W_MP: i32 = 4;
const W_U15: i32 = 61;
const W_S13: i32 = 60;
const W_U13_1: i32 = 58;
const W_U13_2: i32 = 60;
const W_U13_3: i32 = 55;
const W_S5_1: i32 = 53;
const W_S5_2: i32 = 5; // too sparse to measure; theory weight
const W_S5_3: i32 = 48;
const W_U5_1: i32 = 12;
const W_U5_2: i32 = 58;
const W_U5_3: i32 = 40;
const W_S3: i32 = 41;
const W_4_S13: i32 = 13; // i=4 only; theory weight
const W_4_U5_1: i32 = 5; // i=4 only; theory weight
const W_4_U5_2: i32 = 13; // i=4 only; theory weight
const W_SVV10: i32 = 13; // WEP-232 only; theory weight
const W_NEG: i32 = -20;
// NB: the raw SAC-2010 black-box biases (New_bb_*) are deliberately NOT added.
// They are seed-relative, and in WEP the first seed octets are the known IV, so
// their prefix sums recover no secret octet (measured p ~ 1/N, i.e. no signal);
// their usable WEP form is the sigma-reduced Table 1 biases above. The companion
// key-repetition merge (Kbar[i+16j] = Kbar[i] + j*Kbar[15]) applies only to
// 16-octet keys, which C6 rejects, so it is out of scope here.

/// The KSA state after the IV-only key schedule (`t = 2`).
struct Ksa {
    /// The permutation after the 3 IV swaps.
    s: [u8; 256],
    /// Its inverse: `sinv[s[x]] == x`.
    sinv: [u8; 256],
    /// `j` after KSA rounds 0, 1, 2 (`jh[2]` is `j2`).
    jh: [u8; 3],
}

/// The candidate(s) a bias casts for `Kbar[i]`, or none when its condition fails.
enum Votes {
    /// Condition not met.
    None,
    /// One candidate value.
    One(u8),
    /// Two candidates (the `A_neg` rows double-vote).
    Two(u8, u8),
}

/// A bias: its short name, the weight to add per cast (negative for `A_neg`), and
/// the predicate+recovery evaluated per packet per position.
type BiasFn = fn(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes;

/// The full database, in canonical order. Klein and Maitra-Paul first (they fire
/// on almost every packet and carry the bulk of the signal), then the KoreK
/// `A_*` correlations, then SVV_10 and the four negative attacks.
const DATABASE: &[(&str, BiasFn, i32)] = &[
    ("klein", b_klein, W_KLEIN),
    ("mp", b_mp, W_MP),
    ("u15", b_u15, W_U15),
    ("s13", b_s13, W_S13),
    ("u13_1", b_u13_1, W_U13_1),
    ("u13_2", b_u13_2, W_U13_2),
    ("u13_3", b_u13_3, W_U13_3),
    ("s5_1", b_s5_1, W_S5_1),
    ("s5_2", b_s5_2, W_S5_2),
    ("s5_3", b_s5_3, W_S5_3),
    ("u5_1", b_u5_1, W_U5_1),
    ("u5_2", b_u5_2, W_U5_2),
    ("u5_3", b_u5_3, W_U5_3),
    ("s3", b_s3, W_S3),
    ("4_s13", b_4_s13, W_4_S13),
    ("4_u5_1", b_4_u5_1, W_4_U5_1),
    ("4_u5_2", b_4_u5_2, W_4_U5_2),
    ("svv10", b_svv10, W_SVV10),
    ("neg_1", b_neg_1, W_NEG),
    ("neg_2", b_neg_2, W_NEG),
    ("neg_3", b_neg_3, W_NEG),
    ("neg_4", b_neg_4, W_NEG),
];

/// The "out of range" predicate `Cond`: `Sinv[x] < t+1` (=3) or `> i-1` (=q-1).
/// True when the inverse lands outside the already-permuted prefix, which is when
/// the bias relation is informative.
const fn cond(v: u8, q: u8) -> bool {
    v < 3 || v > q.wrapping_sub(1)
}

// --- The biases (Table 1; candidate is always `base - sigma`) ---

/// Klein-Improved: `f = Sinv[i - z_i] - sigma`, `g = (i - z_i) not in {S[3..=i-1]}`.
fn b_klein(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let Some(&zq) = ks.get(usize::from(q) - 1) else {
        return Votes::None;
    };
    let target = q.wrapping_sub(zq);
    if (3..usize::from(q)).any(|x| k.s[x] == target) {
        return Votes::None;
    }
    Votes::One(k.sinv[usize::from(target)].wrapping_sub(sigma))
}

/// Maitra-Paul: `f = z_{i+1} - sigma`, `g = z_{i+1} >= i` and `z_{i+1}` not a KSA j.
fn b_mp(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let Some(&zq1) = ks.get(usize::from(q)) else {
        return Votes::None;
    };
    if zq1 >= q && k.jh[0] != zq1 && k.jh[1] != zq1 && k.jh[2] != zq1 {
        Votes::One(zq1.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u15: `f = 2 - sigma`, `g = S[i]=0, z2=0`.
fn b_u15(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[usize::from(q)] == 0 && ks[1] == 0 { Votes::One(2u8.wrapping_sub(sigma)) } else { Votes::None }
}

/// A_s13: `f = Sinv[0] - sigma`, `g = S[1]=i, Cond(Sinv[0]), z1=i`.
fn b_s13(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[1] == q && cond(k.sinv[0], q) && ks[0] == q {
        Votes::One(k.sinv[0].wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u13_1: `f = Sinv[z1] - sigma`, `g = S[1]=i, Cond(Sinv[z1]), z1=1-i`.
fn b_u13_1(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let iz1 = k.sinv[usize::from(ks[0])];
    if k.s[1] == q && cond(iz1, q) && ks[0] == 1u8.wrapping_sub(q) {
        Votes::One(iz1.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u13_2: `f = 1 - sigma`, `g = S[i]=i, S[1]=0, z1=i`.
fn b_u13_2(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[usize::from(q)] == q && k.s[1] == 0 && ks[0] == q {
        Votes::One(1u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u13_3: `f = 1 - sigma`, `g = S[i]=i, S[1]=1-i, z1=1-i`.
fn b_u13_3(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[usize::from(q)] == q && k.s[1] == 1u8.wrapping_sub(q) && ks[0] == 1u8.wrapping_sub(q) {
        Votes::One(1u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_s5_1 (generalized FMS): `f = Sinv[z1] - sigma`,
/// `g = S[1]<3, S[1]+S[S[1]]=i, z1 not in {S[1], S[S[1]]}`.
fn b_s5_1(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let s1 = k.s[1];
    let iz1 = k.sinv[usize::from(ks[0])];
    if s1 < 3 && s1.wrapping_add(k.s[usize::from(s1)]) == q && iz1 != 1 && iz1 != k.s[usize::from(s1)] {
        Votes::One(iz1.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_s5_2: `f = Sinv[S[1]-S[2]] - sigma`, `g = S[2]+S[1]=i, z2=S[1], Sinv[..] not in {1,2}`.
fn b_s5_2(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let (s1, s2) = (k.s[1], k.s[2]);
    let idx = s1.wrapping_sub(s2);
    let iv = k.sinv[usize::from(idx)];
    if s1 > q && s2.wrapping_add(s1) == q && ks[1] == s1 && iv != 1 && iv != 2 {
        Votes::One(iv.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_s5_3: `f = Sinv[z2] - sigma`, `g = S[2]+S[1]=i, z2=2-S[2], Sinv[z2] not in {1,2}`.
fn b_s5_3(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let (s1, s2) = (k.s[1], k.s[2]);
    let iz2 = k.sinv[usize::from(ks[1])];
    if s1 > q && s2.wrapping_add(s1) == q && ks[1] == 2u8.wrapping_sub(s2) && iz2 != 1 && iz2 != 2 {
        Votes::One(iz2.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u5_1: `f = Sinv[Sinv[z1]-i] - sigma`, `g = S[1]=i, Sinv[z1]<i, Sinv[Sinv[z1]-i]!=1`.
fn b_u5_1(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let iz1 = k.sinv[usize::from(ks[0])];
    if k.s[1] != q || iz1 >= q {
        return Votes::None;
    }
    let inner = k.sinv[usize::from(iz1.wrapping_sub(q))];
    if inner == 1 { Votes::None } else { Votes::One(inner.wrapping_sub(sigma)) }
}

/// A_u5_2: `f = 1 - sigma`, `g = S[i]=1, z1=S[2]` (i.e. Sinv[z1]=2).
fn b_u5_2(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.sinv[usize::from(ks[0])] == 2 && k.s[usize::from(q)] == 1 {
        Votes::One(1u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_u5_3: `f = 1 - sigma`, `g = S[i]=i, S[1] >= -i, q + S[1] - Sinv[z1] = 0`.
fn b_u5_3(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let iz1 = k.sinv[usize::from(ks[0])];
    if k.s[usize::from(q)] == q && k.s[1] >= q.wrapping_neg() && q.wrapping_add(k.s[1]).wrapping_sub(iz1) == 0 {
        Votes::One(1u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

// A_u5_4 (aircrack's enum has it; Table 1 does not) is intentionally omitted: in
// this key-independent frame it measured below the 1/N floor (anti-signal), so the
// faithful Table-1 database leaves it out rather than let it inject noise.

/// A_s3: `f = Sinv[z2] - sigma`, `g = S[1]!=2, S[2]!=0, J2<i, S[J2]+S[2]=i, Sinv[z2] not in {1,2,J2}`.
fn b_s3(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    let (s1, s2) = (k.s[1], k.s[2]);
    if s1 == 2 || s2 == 0 {
        return Votes::None;
    }
    let j2v = s1.wrapping_add(s2);
    let iz2 = k.sinv[usize::from(ks[1])];
    if usize::from(j2v) < usize::from(q)
        && k.s[usize::from(j2v)].wrapping_add(s2) == q
        && iz2 != 1
        && iz2 != 2
        && iz2 != j2v
    {
        Votes::One(iz2.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_4_s13 (i=4 only): `f = Sinv[0] - sigma`, `g = S[1]=2, z2=0`.
fn b_4_s13(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if q == 4 && k.s[1] == 2 && ks[1] == 0 { Votes::One(k.sinv[0].wrapping_sub(sigma)) } else { Votes::None }
}

/// A_4_u5_1 (i=4 only): `f = Sinv[254] - sigma`, `g = S[1]=2, z2!=0, jh[1]=2, Sinv[z2]=0`.
fn b_4_u5_1(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if q == 4 && k.s[1] == 2 && ks[1] != 0 && k.jh[1] == 2 && k.sinv[usize::from(ks[1])] == 0 {
        Votes::One(k.sinv[254].wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_4_u5_2 (i=4 only): `f = Sinv[255] - sigma`, `g = S[1]=2, z2!=0, jh[1]=2, Sinv[z2]=2`.
fn b_4_u5_2(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if q == 4 && k.s[1] == 2 && ks[1] != 0 && k.jh[1] == 2 && k.sinv[usize::from(ks[1])] == 2 {
        Votes::One(k.sinv[255].wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// SVV_10 (i=16 only): `f = Sinv[0] - sigma`, `g = Cond16(Sinv[0]), z16=-16, j2 not in {3..=15}`.
fn b_svv10(k: &Ksa, q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if q != 16 {
        return Votes::None;
    }
    let Some(&z16) = ks.get(15) else {
        return Votes::None;
    };
    if (k.sinv[0] < 3 || k.sinv[0] > 15) && z16 == 16u8.wrapping_neg() && !(3..=15).contains(&k.jh[2]) {
        Votes::One(k.sinv[0].wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_neg_1 (vote against): `g = S[2]=0, S[1]=2, z1=2`; candidates `1-sigma`, `2-sigma`.
fn b_neg_1(k: &Ksa, _q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[2] == 0 && k.s[1] == 2 && ks[0] == 2 {
        Votes::Two(1u8.wrapping_sub(sigma), 2u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_neg_2 (vote against): `g = S[2]=0, S[1]!=2, z2=0`; candidate `2-sigma`.
fn b_neg_2(k: &Ksa, _q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[2] == 0 && k.s[1] != 2 && ks[1] == 0 { Votes::One(2u8.wrapping_sub(sigma)) } else { Votes::None }
}

/// A_neg_3 (vote against): `g = S[1]=1, z1=S[2]`; candidates `1-sigma`, `2-sigma`.
fn b_neg_3(k: &Ksa, _q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[1] == 1 && ks[0] == k.s[2] {
        Votes::Two(1u8.wrapping_sub(sigma), 2u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// A_neg_4 (vote against): `g = S[1]=0, S[0]=1, z1=1`; candidates `0-sigma`, `1-sigma`.
fn b_neg_4(k: &Ksa, _q: u8, sigma: u8, ks: &[u8]) -> Votes {
    if k.s[1] == 0 && k.s[0] == 1 && ks[0] == 1 {
        Votes::Two(0u8.wrapping_sub(sigma), 1u8.wrapping_sub(sigma))
    } else {
        Votes::None
    }
}

/// Simulate the IV-only KSA, returning the state and `j2`.
fn ksa_over_iv(iv: [u8; 3]) -> (Ksa, u8) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    let mut jh = [0u8; 3];
    for i in 0..3 {
        j = j.wrapping_add(s[i]).wrapping_add(iv[i]);
        s.swap(i, usize::from(j));
        jh[i] = j;
    }
    let mut sinv = [0u8; 256];
    for (idx, &v) in s.iter().enumerate() {
        sinv[usize::from(v)] = idx as u8;
    }
    (Ksa { s, sinv, jh }, j)
}

/// Cast every database bias from one packet into the per-position `table`.
fn accumulate_database_votes(iv: [u8; 3], ks: &[u8], table: &mut [[i32; 256]]) {
    if ks.len() < 2 {
        return; // every KoreK bias needs at least z1, z2
    }
    let (k, j2) = ksa_over_iv(iv);
    let mut run = 0u8;
    for (i, row) in table.iter_mut().enumerate() {
        let q = (3 + i) as u8;
        run = run.wrapping_add(k.s[usize::from(q)]);
        let sigma = j2.wrapping_add(run); // sigma_i(t)
        for &(_, bias, weight) in DATABASE {
            match bias(&k, q, sigma, ks) {
                Votes::One(c) => row[usize::from(c)] += weight,
                Votes::Two(a, b) => {
                    row[usize::from(a)] += weight;
                    row[usize::from(b)] += weight;
                },
                Votes::None => {},
            }
        }
    }
}

/// The Sepehrdad bias-database attack (FR-ATK-1, reported as `bias`).
#[derive(Debug, Clone, Copy, Default)]
pub struct BiasAttack {
    /// Search tuning; the database uses `brute_tail` (`-x`) for the trailing sweep
    /// of the shared PTW search. (`-f`/`-c` shape KoreK's separate search.)
    pub tuning: super::Tuning,
}

impl Attack for BiasAttack {
    fn name(&self) -> &'static str {
        "bias"
    }

    fn applicable(&self, bssid: &BssidWep, len: KeyLen) -> bool {
        super::unique_iv_count(bssid) >= super::min_samples(len)
    }

    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        let n = len.byte_len();
        // Distinct IVs only -- a reused IV repeats its votes and biases the table.
        let samples = super::unique_samples(bssid.ivs(), bssid.arp_keystreams());
        let mut table = vec![[0i32; 256]; n];
        for sample in &samples {
            accumulate_database_votes(sample.iv, sample.keystream(), &mut table);
        }
        search_sigma_table(&table, verifier, self.tuning.brute_tail.min(n))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::needless_range_loop,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::suboptimal_flops,
        reason = "statistical test fixtures index parallel arrays by position and report empirical rates"
    )]

    use super::{DATABASE, Ksa, accumulate_database_votes, b_klein, ksa_over_iv};
    use crate::attack::Attack;
    use crate::attack::bias::BiasAttack;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey};
    use crate::wep::Verifier;

    /// ARP-style samples: counter IVs, the true 16-octet keystream for `key`.
    fn arp_samples(key: &[u8], n: u32) -> Vec<IvSample> {
        (0..n)
            .map(|c| {
                let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                let mut ks = [0u8; 16];
                Rc4::new(&seed).keystream(&mut ks);
                IvSample::new(iv, &ks)
            })
            .collect()
    }

    fn verifier_for(key: &[u8]) -> Verifier {
        let frames = [[1u8, 2, 3], [4, 5, 6]]
            .iter()
            .map(|iv| {
                let plain = b"\xaa\xaa\x03\x00\x00\x00 bias verifier frame body";
                let mut data = plain.to_vec();
                data.extend_from_slice(&crc32(plain).to_le_bytes());
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                Rc4::new(&seed).apply_keystream(&mut data);
                EncFrame { iv: *iv, data, key_id: 0 }
            })
            .collect();
        Verifier::new(frames)
    }

    /// True cumulative key sums sigma_i = K[0]+..+K[i].
    fn true_sigmas(key: &[u8]) -> Vec<u8> {
        let mut acc = 0u8;
        key.iter()
            .map(|&k| {
                acc = acc.wrapping_add(k);
                acc
            })
            .collect()
    }

    /// Build the KSA state and per-position sigma the biases see, for one packet.
    fn ctx(iv: [u8; 3], pos: usize) -> (Ksa, u8) {
        let (k, j2) = ksa_over_iv(iv);
        let mut run = 0u8;
        let mut sigma = 0u8;
        for i in 0..=pos {
            run = run.wrapping_add(k.s[3 + i]);
            sigma = j2.wrapping_add(run);
        }
        (k, sigma)
    }

    #[test]
    #[ignore = "measurement: per-bias (p,q) and the a_opt-derived integer weight"]
    fn measure_aopt_weights() {
        // For each bias measure p = P[candidate == true Kbar[i] | condition holds]
        // and q = P[condition holds], over many random keys/IVs/positions, then the
        // optimal coefficient a_opt = (p-1/N) / [(p-1/N) + (2/N)(1-1/N)(1-q/N)]
        // ([Sepehrdad et al., FSE 2013] §7). The baked W_* constants are
        // round(a_opt * SCALE) from this run; re-run to refresh.
        const N: f64 = 256.0;
        const SCALE: f64 = 64.0;
        let trials = 300_000u32;
        let mut fires = [0u64; 32];
        let mut hits = [0u64; 32];
        let mut evals = 0u64;
        for t in 0..trials {
            let mut key = [0u8; 13];
            let mut x = t.wrapping_mul(2_654_435_761).wrapping_add(101);
            for kk in &mut key {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *kk = (x >> 16) as u8;
            }
            let truth = true_sigmas(&key);
            let iv = [key[0] ^ (t as u8), (t >> 8) as u8, (t >> 16) as u8];
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            let mut ks = [0u8; 16];
            Rc4::new(&seed).keystream(&mut ks);
            for pos in 0..13 {
                let (k, sigma) = ctx(iv, pos);
                let q = (3 + pos) as u8;
                evals += 1;
                for (bi, &(_, bias, _)) in DATABASE.iter().enumerate() {
                    let mut tally = |c: u8| {
                        fires[bi] += 1;
                        if c == truth[pos] {
                            hits[bi] += 1;
                        }
                    };
                    match bias(&k, q, sigma, &ks) {
                        super::Votes::One(c) => tally(c),
                        super::Votes::Two(a, b) => {
                            tally(a);
                            tally(b);
                        },
                        super::Votes::None => {},
                    }
                }
            }
        }
        for (bi, &(name, _, w)) in DATABASE.iter().enumerate() {
            let f = fires[bi];
            if f == 0 {
                println!("{name:>7} cur_w={w:>4} fires=0  (insufficient data)");
                continue;
            }
            let p = hits[bi] as f64 / f as f64;
            let q = f as f64 / evals as f64;
            let num = p - 1.0 / N;
            let aopt = num / (num + (2.0 / N) * (1.0 - 1.0 / N) * (1.0 - q / N));
            let weight = (aopt * SCALE).round() as i32;
            println!("{name:>7} cur_w={w:>4}  p={:.3}/N q={q:.4} a_opt={aopt:+.4} -> W={weight}", p * N);
        }
    }

    #[test]
    fn klein_bias_predicts_the_true_sum() {
        // Sanity: the Klein bias's candidate equals the true cumulative sum far
        // more often than the 1/256 chance floor -- it is a real, correctly signed
        // bias. (~1.36/256 expected; assert clearly above the floor.)
        let key = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD];
        let truth = true_sigmas(&key);
        let (mut fires, mut hits) = (0u64, 0u64);
        for c in 0..200_000u32 {
            let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            let mut ks = [0u8; 16];
            Rc4::new(&seed).keystream(&mut ks);
            for pos in 0..key.len() {
                let (k, sigma) = ctx(iv, pos);
                if let super::Votes::One(cand) = b_klein(&k, (3 + pos) as u8, sigma, &ks) {
                    fires += 1;
                    if cand == truth[pos] {
                        hits += 1;
                    }
                }
            }
        }
        // p must be well above the 1/256 floor (Klein ~1.36/256).
        assert!(fires > 10_000, "klein should fire often (fires={fires})");
        assert!(hits * 256 > fires * 5 / 4, "klein p must exceed ~1.25/256 (hits={hits}, fires={fires})");
    }

    #[test]
    fn database_outranks_klein_alone() {
        // The whole database must rank the true sum #1 at *more* positions than the
        // Klein vote alone -- i.e. the extra biases are net signal, not noise. A
        // mis-transcribed bias that injected noise would make this regress.
        let key = [0x3Fu8, 0xA1, 0x8C, 0xD2, 0x6B, 0x04, 0xE9, 0x57, 0x1A, 0xCC, 0x80, 0x35, 0xF2];
        let truth = true_sigmas(&key);
        let samples = arp_samples(&key, 30_000);

        // Klein-only table (weight 1, no other bias).
        let mut klein = vec![[0i32; 256]; 13];
        // Full-database table.
        let mut full = vec![[0i32; 256]; 13];
        for s in &samples {
            let ks = s.keystream();
            // Klein-only: reuse the database's own Klein predicate at weight 1.
            let (k, j2) = ksa_over_iv(s.iv);
            let mut run = 0u8;
            for (i, row) in klein.iter_mut().enumerate() {
                let q = (3 + i) as u8;
                run = run.wrapping_add(k.s[usize::from(q)]);
                let sigma = j2.wrapping_add(run);
                if let super::Votes::One(c) = b_klein(&k, q, sigma, ks) {
                    row[usize::from(c)] += 1;
                }
            }
            accumulate_database_votes(s.iv, ks, &mut full);
        }
        let correct = |table: &[[i32; 256]]| -> usize {
            (0..13)
                .filter(|&i| {
                    let tv = table[i][usize::from(truth[i])];
                    !table[i].iter().any(|&v| v > tv)
                })
                .count()
        };
        let (kc, fc) = (correct(&klein), correct(&full));
        assert!(fc >= kc, "the full database must rank >= Klein alone (klein={kc}, full={fc})");
    }

    #[test]
    fn bias_recovers_wep104() {
        // End-to-end: the database recovers a WEP-104 key through the shared search.
        let key = [0x53u8, 0x1a, 0xc7, 0x09, 0xe2, 0x44, 0x8b, 0x10, 0x3d, 0x6f, 0xa1, 0xce, 0x72];
        let bssid = BssidWep::with_material(crate::model::WepMaterial {
            arp_keystreams: arp_samples(&key, 60_000),
            ..Default::default()
        });
        let recovered = BiasAttack::default().run(&bssid, KeyLen::Wep104, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn database_votes_low_wep232_positions_correctly() {
        // WEP-232's high key octets are recovered by the *sequential* KoreK attack,
        // not this parallel sigma-reduced frame: the Klein/MP reduction degrades
        // with key position (the ((N-1)/N)^(i-t-1) factor), so high octets need the
        // KSA run over the recovered prefix. Verify the database still votes the
        // *reachable* low octets correctly for a 29-octet key, so KoreK's prefix
        // search has a sound base.
        let key: Vec<u8> = (0..29u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
        let mut truth = [0u8; 29];
        let mut acc = 0u8;
        for (i, &k) in key.iter().enumerate() {
            acc = acc.wrapping_add(k);
            truth[i] = acc;
        }
        let mut table = vec![[0i32; 256]; 29];
        for c in 0..120_000u32 {
            let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            let mut ks = [0u8; 32];
            Rc4::new(&seed).keystream(&mut ks);
            accumulate_database_votes(iv, &ks, &mut table);
        }
        let correct = (0..8).filter(|&i| !table[i].iter().any(|&v| v > table[i][usize::from(truth[i])])).count();
        assert!(correct >= 7, "the database must vote the low WEP-232 octets correctly (got {correct}/8)");
    }

    #[test]
    fn bias_recovers_wep40() {
        let key = [0x64u8, 0x33, 0xa1, 0x07, 0xfe];
        let bssid =
            BssidWep::with_material(crate::model::WepMaterial { ivs: arp_samples(&key, 40_000), ..Default::default() });
        let recovered = BiasAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn database_recovers_where_aircrack_klein_only_fails() {
        // The headline "better than aircrack-ng" result, end to end. From one fixed
        // marginal 30k-packet WEP-104 capture, the Klein-only signal aircrack-ng's
        // PTW uses (weight-1 Klein vote, same search) leaves the key unrecoverable,
        // but the full Sepehrdad database -- the Maitra-Paul and KoreK biases
        // aircrack does not ship -- recovers it from the very same packets.
        use crate::attack::ptw::search_sigma_table;
        let mut key = [0u8; 13];
        let mut acc = 0x77u8;
        for k in &mut key {
            acc = acc.wrapping_mul(73).wrapping_add(41);
            *k = acc;
        }
        let verifier = verifier_for(&key);
        let samples = arp_samples(&key, 30_000);

        let mut klein = vec![[0i32; 256]; 13];
        let mut full = vec![[0i32; 256]; 13];
        for s in &samples {
            let ks = s.keystream();
            let (k, j2) = ksa_over_iv(s.iv);
            let mut run = 0u8;
            for (i, row) in klein.iter_mut().enumerate() {
                let q = (3 + i) as u8;
                run = run.wrapping_add(k.s[usize::from(q)]);
                if let super::Votes::One(c) = b_klein(&k, q, j2.wrapping_add(run), ks) {
                    row[usize::from(c)] += 1;
                }
            }
            accumulate_database_votes(s.iv, ks, &mut full);
        }
        assert!(
            search_sigma_table(&klein, &verifier, 1).is_none(),
            "Klein-only (aircrack's PTW) should not recover from these 30k packets",
        );
        let got = search_sigma_table(&full, &verifier, 1);
        assert_eq!(
            got.as_ref().map(WepKey::as_slice),
            Some(key.as_slice()),
            "the full Sepehrdad database recovers the key from the same packets",
        );
    }

    #[test]
    #[ignore = "diagnostic: per-bias empirical probability and density"]
    fn per_bias_diagnostic() {
        // For each bias, over many random packets and positions, report how often
        // its candidate equals the true sum (p) vs how often it fires (density).
        let trials = 40_000u32;
        let mut fires = [0u64; 32];
        let mut hits = [0u64; 32];
        for t in 0..trials {
            let mut key = [0u8; 13];
            let mut x = t.wrapping_mul(2_654_435_761).wrapping_add(99);
            for kk in &mut key {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *kk = (x >> 16) as u8;
            }
            let truth = true_sigmas(&key);
            let iv = [key[0] ^ (t as u8), (t >> 8) as u8, (t >> 16) as u8];
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            let mut ks = [0u8; 16];
            Rc4::new(&seed).keystream(&mut ks);
            for pos in 0..13 {
                let (k, sigma) = ctx(iv, pos);
                let q = (3 + pos) as u8;
                for (bi, &(_, bias, _)) in DATABASE.iter().enumerate() {
                    let check = |c: u8, fires: &mut [u64; 32], hits: &mut [u64; 32]| {
                        fires[bi] += 1;
                        if c == truth[pos] {
                            hits[bi] += 1;
                        }
                    };
                    match bias(&k, q, sigma, &ks) {
                        super::Votes::One(c) => check(c, &mut fires, &mut hits),
                        super::Votes::Two(a, b) => {
                            check(a, &mut fires, &mut hits);
                            check(b, &mut fires, &mut hits);
                        },
                        super::Votes::None => {},
                    }
                }
            }
        }
        for (bi, &(name, _, w)) in DATABASE.iter().enumerate() {
            let f = fires[bi];
            let p_per_n = if f == 0 { 0.0 } else { (hits[bi] as f64 / f as f64) * 256.0 };
            println!("{name:>7} w={w:>4} fires={f:>8} p={p_per_n:.3}/N");
        }
    }
}
