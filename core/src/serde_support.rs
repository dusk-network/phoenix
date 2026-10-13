// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

use dusk_bytes::Serializable;
use dusk_jubjub::JubJubAffine;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::As;
use serde_with::hex::Hex;

use crate::{PublicKey, SecretKey, StealthAddress, ViewKey};

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
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = Self::SIZE.to_string();
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        PublicKey::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = Self::SIZE.to_string();
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        SecretKey::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for ViewKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for ViewKey {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = Self::SIZE.to_string();
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        ViewKey::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}

impl Serialize for StealthAddress {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = bs58::encode(self.to_bytes()).into_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for StealthAddress {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded =
            bs58::decode(&s).into_vec().map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let byte_length_str = Self::SIZE.to_string();
        let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
            SerdeError::invalid_length(decoded_len, &byte_length_str.as_str())
        })?;
        StealthAddress::from_bytes(&bytes)
            .map_err(|err| SerdeError::custom(format!("{err:?}")))
    }
}
