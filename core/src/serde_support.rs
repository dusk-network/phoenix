// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use core::fmt::{self, Debug};

use dusk_bytes::Serializable;
use dusk_jubjub::JubJubAffine;
use serde::de::{Error as SerdeError, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::As;
use serde_with::hex::Hex;
use zeroize::Zeroize;

use crate::{PublicKey, SecretKey, StealthAddress, ViewKey};

const OVER_LONG: Unexpected = Unexpected::Other("over-long base58 string");

/// Maximum Base58 output size across supported 64-byte types (64 bytes encode
/// to at most 88 characters).
const MAX_ENCODED_LEN: usize = 92;

fn serialize_bs58<T, S, const N: usize>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: Serializable<N>,
    S: Serializer,
{
    let mut bytes = value.to_bytes();
    let mut encoded = [0u8; MAX_ENCODED_LEN];
    let len = bs58::encode(&bytes)
        .onto(&mut encoded[..])
        .expect("stack buffer fits encoded bytes");
    let result = serializer.serialize_str(
        core::str::from_utf8(&encoded[..len])
            .expect("base58 output is valid UTF-8"),
    );
    bytes.zeroize();
    encoded.zeroize();
    result
}

/// Decodes a Base58 string of exactly `N` bytes into `T`.
///
/// Longer encodings are rejected before decoding, and decoding writes into a
/// fixed-size buffer that is wiped before returning.
fn deserialize_bs58<'de, D, T, const N: usize>(
    deserializer: D,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Serializable<N>,
    T::Error: Debug,
{
    struct Bs58<'a, const N: usize>(&'a mut [u8; N]);

    impl<const N: usize> Visitor<'_> for Bs58<'_, N> {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a base58 string encoding {N} bytes")
        }

        fn visit_str<E: SerdeError>(
            self,
            value: &str,
        ) -> Result<Self::Value, E> {
            self.visit_bytes(value.as_bytes())
        }

        fn visit_bytes<E: SerdeError>(
            self,
            value: &[u8],
        ) -> Result<Self::Value, E> {
            // `N` bytes encode to at most `ceil(N * log(256) / log(58))`
            // characters, and log(256) / log(58) < 1.366.
            if value.len() > N * 1366 / 1000 + 1 {
                return Err(E::invalid_value(OVER_LONG, &self));
            }
            match bs58::decode(value).onto(&mut self.0[..]) {
                Ok(len) if len == N => Ok(()),
                Ok(len) => Err(E::invalid_length(len, &self)),
                Err(bs58::decode::Error::BufferTooSmall) => {
                    Err(E::invalid_value(OVER_LONG, &self))
                }
                Err(err) => Err(E::custom(err)),
            }
        }
    }

    let mut bytes = [0u8; N];
    let value = deserializer
        .deserialize_str(Bs58(&mut bytes))
        .and_then(|()| {
            T::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))
        });
    bytes.zeroize();
    value
}

/// Decodes a point of exactly 32 bytes through [`Serializable::from_bytes`],
/// as the `dusk-bytes` decoders do, which requires it to lie in the
/// prime-order subgroup. The `Deserialize` of `JubJubAffine` skips that check
/// (dusk-network/jubjub#192).
pub(crate) fn deserialize_point<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<JubJubAffine, D::Error> {
    let bytes: [u8; JubJubAffine::SIZE] = As::<Hex>::deserialize(deserializer)?;
    // `JubJubAffine::from_bytes` resolves to the inherent decoder, which skips
    // the subgroup check.
    <JubJubAffine as Serializable<32>>::from_bytes(&bytes)
        .map_err(|err| SerdeError::custom(format!("{err:?}")))
}

/// Decodes the points of a sender encryption as [`deserialize_point`] does.
pub(crate) fn deserialize_sender_enc<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[(JubJubAffine, JubJubAffine); 2], D::Error> {
    struct Point(JubJubAffine);

    impl<'de> Deserialize<'de> for Point {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            deserialize_point(deserializer).map(Self)
        }
    }

    let enc = <[(Point, Point); 2]>::deserialize(deserializer)?;
    Ok(enc.map(|(c1, c2)| (c1.0, c2.0)))
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_bs58(self, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_bs58(self, serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for ViewKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_bs58(self, serializer)
    }
}

impl<'de> Deserialize<'de> for ViewKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}

impl Serialize for StealthAddress {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serialize_bs58(self, serializer)
    }
}

impl<'de> Deserialize<'de> for StealthAddress {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        deserialize_bs58(deserializer)
    }
}
