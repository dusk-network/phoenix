// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

use dusk_bytes::Serializable;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PublicKey, SecretKey, StealthAddress, ViewKey};

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
