// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Multiplication of the generator with a table of its multiples.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

mod table;
use table::TABLE;

/// Computes `s · G` for the generator `G`, the same point as
/// `GENERATOR_EXTENDED * s`, in constant time.
///
/// With `s` written in 64 signed digits as `s = Σ d_i · 16^i`, and with
/// `i = 8j + m`, `s · G = Σ_m 16^m · Σ_j d_(8j+m) · 2^(32j) · G`. The table
/// holds `1` to `8` times each `2^(32j) · G`, so Horner's rule over `m` takes
/// 64 additions of table entries and 28 doublings, where the double-and-add of
/// `GENERATOR_EXTENDED * s` takes 252 of each.
///
/// The operations do not depend on `s`: the digits are computed without
/// branching, every entry of a row is read and the one needed is kept by a
/// constant-time selection, and the point formulas are complete.
pub(crate) fn mul_generator(s: &JubJubScalar) -> JubJubExtended {
    let digits = digits(s);

    let mut acc = JubJubExtended::identity();
    for m in (0..8).rev() {
        for (j, row) in TABLE.iter().enumerate() {
            acc += select(row, digits[8 * j + m]);
        }
        if m > 0 {
            acc = acc.double().double().double().double();
        }
    }
    acc
}

/// The signed digits `d_i` of `s = Σ d_i · 16^i`, each in `[-8, 8)` but the
/// last, in `[0, 1]` as `s < 2^252`.
fn digits(s: &JubJubScalar) -> [i8; 64] {
    let mut digits = [0i8; 64];
    for (i, byte) in s.to_bytes().into_iter().enumerate() {
        digits[2 * i] = (byte & 0xf) as i8;
        digits[2 * i + 1] = (byte >> 4) as i8;
    }
    // Move each digit from `[0, 16]` to `[-8, 8)`, carrying into the next.
    for i in 0..63 {
        let carry = (digits[i] + 8) >> 4;
        digits[i] -= carry << 4;
        digits[i + 1] += carry;
    }
    digits
}

/// Returns `d · B` for `d` in `[-8, 8]`, from the row `[1 · B, …, 8 · B]` of
/// the table, reading every entry of the row.
fn select(row: &[JubJubAffine; 8], d: i8) -> JubJubAffine {
    // All ones for a negative `d`, zero otherwise.
    let sign = d >> 7;
    let abs = ((d ^ sign) - sign) as u8;

    let mut point = JubJubAffine::identity();
    for (k, entry) in (1..=8).zip(row) {
        point.conditional_assign(entry, abs.ct_eq(&k));
    }
    JubJubAffine::conditional_select(
        &point,
        &-point,
        Choice::from((sign & 1) as u8),
    )
}

#[cfg(test)]
mod tests {
    use dusk_jubjub::GENERATOR_EXTENDED;
    use ff::Field;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn table_holds_the_multiples_of_the_generator() {
        let mut base = GENERATOR_EXTENDED;
        for (j, row) in TABLE.iter().enumerate() {
            let mut multiple = base;
            for (k, entry) in row.iter().enumerate() {
                let expected = JubJubAffine::from(multiple);
                assert_eq!(*entry, expected, "TABLE[{j}][{k}]");
                multiple += base;
            }
            for _ in 0..32 {
                base = base.double();
            }
        }
    }

    #[test]
    fn mul_generator_equals_the_double_and_add() {
        let nibbles = |n: u64| JubJubScalar::from_raw([n, n, n, n >> 4]);
        let edge = [
            JubJubScalar::zero(),
            JubJubScalar::one(),
            // -1, the order minus 1, the largest scalar
            -JubJubScalar::one(),
            -JubJubScalar::from(2u64),
            JubJubScalar::from(8u64),
            -JubJubScalar::from(8u64),
            JubJubScalar::from(9u64),
            JubJubScalar::from(u64::MAX),
            // every digit below the top one 8, each carrying into the next
            nibbles(0x8888_8888_8888_8888),
            // every digit below the top one 7, none carrying
            nibbles(0x7777_7777_7777_7777),
        ];

        let mut rng = StdRng::seed_from_u64(0x9e7);
        let random = (0..1000).map(|_| JubJubScalar::random(&mut rng));

        for s in edge.into_iter().chain(random) {
            assert_eq!(mul_generator(&s), GENERATOR_EXTENDED * s, "{s:?}");
        }
    }
}
