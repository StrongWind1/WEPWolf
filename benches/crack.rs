//! Microbenchmarks (FR-PERF-4: the parity-or-better bar, tracked here): PTW
//! recovery time and CRC-32 fold throughput.
//!
//! Run with `cargo bench`. A plain timed `main` (no criterion) keeps the
//! dependency budget tight; the numbers back the aircrack parity-or-better bar
//! and let the SIMD CRC fold be compared against the scalar reference.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::print_stdout,
    reason = "standalone benchmark harness, not library code"
)]

// lib-only deps; silence the per-target unused-crate-dependencies lint.
use clap as _;
use crc32fast as _;
use flate2 as _;
use indicatif as _;
use md5 as _;
use rayon as _;
use sysinfo as _;

use std::hint::black_box;
use std::time::Instant;

use wepwolf::attack::Attack;
use wepwolf::attack::brute::{CpuBrute, SimdBrute};
use wepwolf::attack::ptw::PtwAttack;
use wepwolf::attack::{BruteBackend, KeyRange};
use wepwolf::crypto::{Rc4, crc32};
use wepwolf::model::{BssidWep, EncFrame, IvSample, KeyLen, WepKey, WepMaterial};
use wepwolf::simd::{self, SimdTier};
use wepwolf::wep::Verifier;

fn main() {
    bench_ptw();
    bench_crc();
    bench_brute();
}

/// Time PTW recovery of a WEP-40 key from 80k synthetic ARP keystreams -- the
/// canonical "ordinary traffic" workload the parity bar is measured on.
fn bench_ptw() {
    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28];
    let arp: Vec<IvSample> = (0..80_000u32)
        .map(|c| {
            let iv = [c as u8, (c >> 8) as u8, (c >> 16) as u8];
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&key);
            let mut ks = [0u8; 16];
            Rc4::new(&seed).keystream(&mut ks);
            IvSample::new(iv, &ks)
        })
        .collect();
    let bssid = BssidWep::with_material(WepMaterial { arp_keystreams: arp, ..Default::default() });
    let verifier = verifier_for(&key);

    let start = Instant::now();
    let recovered = PtwAttack::default().run(black_box(&bssid), KeyLen::Wep40, black_box(&verifier));
    let elapsed = start.elapsed();
    assert_eq!(recovered.as_ref().map(WepKey::as_slice), Some(key.as_slice()), "bench must crack");
    println!("ptw_wep40_80k_samples       {elapsed:?}");
}

/// Compare scalar table CRC-32 against the best SIMD tier (PCLMULQDQ) over a
/// full-MTU buffer, the ICV fold the brute hammers per candidate.
fn bench_crc() {
    let data = vec![0xa5u8; 1500];
    let iters = 200_000u32;
    for tier in [SimdTier::Scalar, simd::best()] {
        let start = Instant::now();
        let mut acc = 0u32;
        for _ in 0..iters {
            acc ^= simd::crc32(tier, black_box(&data));
        }
        black_box(acc);
        println!("crc32_{:<11}_1500B_x{iters}  {:?}", tier.label(), start.elapsed());
    }
}

/// Compare the scalar per-key verify against the SIMD-batched known-plaintext
/// prefilter over a fixed key window, both scanning fully (the key is out of
/// range) -- the brute's keys/sec throughput and its parity bar (FR-PERF-4,
/// FR-SIMD-2). The prefilter spends a batched KSA plus four PRGA octets per
/// candidate and routes only the rare survivor to the full verify, so it clears
/// the window far faster than a full decrypt-and-CRC per key.
fn bench_brute() {
    const N: u64 = 1 << 20;
    // An index near the top of the 2^40 space, never inside the scanned window, so
    // both backends scan every key and the timing is pure throughput.
    let key = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee];
    let verifier = verifier_for(&key);
    let range = KeyRange { start: 0, end: N };

    let start = Instant::now();
    black_box(CpuBrute.search40(black_box(&verifier), range));
    let scalar = start.elapsed();
    println!("brute_cpu-scalar _{N}keys  {scalar:?}  {:.1}M keys/s", N as f64 / scalar.as_secs_f64() / 1e6);

    let backend = SimdBrute::new();
    let start = Instant::now();
    black_box(backend.search40(black_box(&verifier), range));
    let simd = start.elapsed();
    println!("brute_{:<10}_{N}keys  {simd:?}  {:.1}M keys/s", backend.label(), N as f64 / simd.as_secs_f64() / 1e6);
}

/// Two frames the recovered key must verify against.
fn verifier_for(key: &[u8]) -> Verifier {
    let frames = [[1u8, 2, 3], [4, 5, 6]]
        .iter()
        .map(|iv| {
            let plain = b"\xaa\xaa\x03\x00\x00\x00 bench verifier frame body";
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
