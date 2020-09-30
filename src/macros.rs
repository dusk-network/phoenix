// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[macro_export]
/// Creates an array of `n` bytes, copying the content from the `b` slice given.
///
/// If the `b` slice has a length greater than `n`, only the first `n` bytes
/// are copied.
///
/// If the `b` slice has a length smaller than `n`, the resulting array will
/// have `0u8` for the remaining bytes.
macro_rules! chunk_of {
    ($n:expr; $b:expr) => {{
        let mut buf = [0u8; $n];
        let len = std::cmp::min($b.len(), $n);
        (&mut buf[..len]).copy_from_slice(&$b[..len]);
        buf
    }};
}
