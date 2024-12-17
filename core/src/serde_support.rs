// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::JubJubAffine;
use serde::de::{
    self, Error as SerdeError, MapAccess, Unexpected, VariantAccess, Visitor,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Note, NoteType, PublicKey, SecretKey, Sender, StealthAddress, TxSkeleton,
    ViewKey, NOTE_VAL_ENC_SIZE,
};

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

impl Serialize for NoteType {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self {
            Self::Transparent => {
                serializer.serialize_unit_variant("NoteType", 0, "Transparent")
            }
            Self::Obfuscated => {
                serializer.serialize_unit_variant("NoteType", 1, "Obfuscated")
            }
        }
    }
}

impl<'de> Deserialize<'de> for NoteType {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "Obfuscated" => Ok(NoteType::Obfuscated),
            "Transparent" => Ok(NoteType::Transparent),
            v => Err(SerdeError::unknown_variant(
                v,
                &["Transparent", "Obfuscated"],
            )),
        }
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

// To serialize and deserialize u64s as big ints:
// https://github.com/dusk-network/rusk/issues/2773#issuecomment-2519791322.
struct Bigint(u64);

impl Serialize for Bigint {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s: String = format!("{}n", self.0);
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Bigint {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let mut s = String::deserialize(deserializer)?;
        let last_char = s.pop().ok_or_else(|| {
            SerdeError::invalid_value(
                Unexpected::Str(&s),
                &"a non-empty string",
            )
        })?;
        if last_char != 'n' {
            return Err(SerdeError::invalid_value(
                Unexpected::Str(&s),
                &"a bigint ending with character 'n'",
            ));
        }
        let parsed_number = u64::from_str_radix(&s, 10).map_err(|e| {
            SerdeError::custom(format!("failed to deserialize u64: {e}"))
        })?;
        Ok(Self(parsed_number))
    }
}

impl Serialize for Sender {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self {
            Sender::Encryption(pk) => serializer.serialize_newtype_variant(
                "Sender",
                0,
                "Encryption",
                pk,
            ),
            Sender::ContractInfo(info) => serializer.serialize_newtype_variant(
                "Sender",
                1,
                "ContractInfo",
                &hex::encode(info),
            ),
        }
    }
}

impl<'de> Deserialize<'de> for Sender {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct SenderVisitor;

        static VARIANTS: [&'static str; 2] = ["Encryption", "ContractInfo"];

        impl<'de> Visitor<'de> for SenderVisitor {
            type Value = Sender;

            fn expecting(
                &self,
                formatter: &mut alloc::fmt::Formatter,
            ) -> alloc::fmt::Result {
                formatter.write_str(
                    "an enum with variants Enrcyption and ContractInfo",
                )
            }

            fn visit_enum<A: de::EnumAccess<'de>>(
                self,
                data: A,
            ) -> Result<Self::Value, A::Error> {
                match data.variant()? {
                    ("Encryption", variant) => {
                        Ok(Sender::Encryption(variant.newtype_variant()?))
                    }
                    ("ContractInfo", variant) => {
                        let variant_data: String = variant.newtype_variant()?;
                        let decoded = hex::decode(&variant_data)
                            .map_err(SerdeError::custom)?;
                        let decoded_len = decoded.len();
                        let byte_length_str =
                            format!("{}", 4 * JubJubAffine::SIZE);
                        let bytes: [u8; 4 * JubJubAffine::SIZE] =
                            decoded.try_into().map_err(|_| {
                                SerdeError::invalid_length(
                                    decoded_len,
                                    &byte_length_str.as_str(),
                                )
                            })?;
                        Ok(Sender::ContractInfo(bytes))
                    }
                    (variant_name, _) => Err(SerdeError::unknown_variant(
                        variant_name,
                        &VARIANTS,
                    )),
                }
            }
        }

        deserializer.deserialize_enum("Sender", &VARIANTS, SenderVisitor)
    }
}

impl Serialize for Note {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut struct_ser = serializer.serialize_struct("Note", 6)?;
        struct_ser.serialize_field("note_type", &self.note_type)?;
        struct_ser
            .serialize_field("value_commitment", &self.value_commitment)?;
        struct_ser.serialize_field("stealth_address", &self.stealth_address)?;
        struct_ser.serialize_field("pos", &Bigint(self.pos))?;
        struct_ser
            .serialize_field("value_enc", &hex::encode(&self.value_enc))?;
        struct_ser.serialize_field("sender", &self.sender)?;
        struct_ser.end()
    }
}

impl<'de> Deserialize<'de> for Note {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct NoteVisitor;

        static FIELDS: [&'static str; 6] = [
            "note_type",
            "value_commitment",
            "stealth_address",
            "pos",
            "value_enc",
            "sender",
        ];

        impl<'de> Visitor<'de> for NoteVisitor {
            type Value = Note;

            fn expecting(
                &self,
                formatter: &mut alloc::fmt::Formatter,
            ) -> alloc::fmt::Result {
                formatter.write_str("expecting a struct with fields note_type, value_commitment, stealth_address, pos, value_enc, and sender")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut note_type = None;
                let mut value_commitment = None;
                let mut stealth_address = None;
                let mut pos: Option<Bigint> = None;
                let mut value_enc = None;
                let mut sender = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "note_type" => {
                            if note_type.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "note_type",
                                ));
                            }
                            note_type = Some(map.next_value()?);
                        }
                        "value_commitment" => {
                            if value_commitment.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "value_commitment",
                                ));
                            }
                            value_commitment = Some(map.next_value()?);
                        }
                        "stealth_address" => {
                            if stealth_address.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "stealth_address",
                                ));
                            }
                            stealth_address = Some(map.next_value()?);
                        }
                        "pos" => {
                            if pos.is_some() {
                                return Err(SerdeError::duplicate_field("pos"));
                            }
                            pos = Some(map.next_value()?);
                        }
                        "value_enc" => {
                            if sender.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "value_enc",
                                ));
                            }
                            value_enc = Some(map.next_value()?);
                        }
                        "sender" => {
                            if sender.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "sender",
                                ));
                            }
                            sender = Some(map.next_value()?);
                        }
                        field => {
                            return Err(SerdeError::unknown_field(
                                field, &FIELDS,
                            ))
                        }
                    }
                }

                let value_enc: String = value_enc
                    .ok_or_else(|| SerdeError::missing_field("value_enc"))?;
                let value_enc_len = value_enc.len();
                let decoded_value_enc =
                    hex::decode(value_enc).map_err(SerdeError::custom)?;
                let value_enc: [u8; NOTE_VAL_ENC_SIZE] =
                    decoded_value_enc.try_into().map_err(|_| {
                        SerdeError::invalid_length(
                            value_enc_len,
                            &NOTE_VAL_ENC_SIZE.to_string().as_str(),
                        )
                    })?;

                Ok(Note {
                    note_type: note_type.ok_or_else(|| {
                        SerdeError::missing_field("note_type")
                    })?,
                    stealth_address: stealth_address.ok_or_else(|| {
                        SerdeError::missing_field("stealth_address")
                    })?,
                    value_commitment: value_commitment.ok_or_else(|| {
                        SerdeError::missing_field("value_commitment")
                    })?,
                    pos: pos.ok_or_else(|| SerdeError::missing_field("pos"))?.0,
                    value_enc,
                    sender: sender
                        .ok_or_else(|| SerdeError::missing_field("sender"))?,
                })
            }
        }

        deserializer.deserialize_struct("Note", &FIELDS, NoteVisitor)
    }
}

// The current serde implementation for `BlsScalar` is not what it's expected to
// be, so this is needed at the moment: https://github.com/dusk-network/bls12_381/issues/145.
struct BlsScalarSerde(BlsScalar);

impl Serialize for BlsScalarSerde {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = hex::encode(self.0.to_bytes());
        s.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BlsScalarSerde {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
        let decoded_len = decoded.len();
        let bytes: [u8; BlsScalar::SIZE] =
            decoded.try_into().map_err(|_| {
                SerdeError::invalid_length(
                    decoded_len,
                    &BlsScalar::SIZE.to_string().as_str(),
                )
            })?;
        let bls_scalar = BlsScalar::from_bytes(&bytes).into_option().ok_or(
            SerdeError::custom(
                "Failed to deserialize BlsScalar: invalid BlsScalar",
            ),
        )?;
        Ok(BlsScalarSerde(bls_scalar))
    }
}

impl Serialize for TxSkeleton {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut struct_ser = serializer.serialize_struct("TxSkeleton", 5)?;
        let serde_nullifiers: Vec<BlsScalarSerde> = self
            .nullifiers
            .iter()
            .map(|nullifier| BlsScalarSerde(nullifier.clone()))
            .collect();
        struct_ser.serialize_field("root", &BlsScalarSerde(self.root))?;
        struct_ser.serialize_field("nullifiers", &serde_nullifiers)?;
        struct_ser.serialize_field("outputs", &self.outputs)?;
        struct_ser.serialize_field("max_fee", &Bigint(self.max_fee))?;
        struct_ser.serialize_field("deposit", &Bigint(self.deposit))?;
        struct_ser.end()
    }
}

impl<'de> Deserialize<'de> for TxSkeleton {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct TxSkeletonVisitor;
        static FIELDS: [&'static str; 5] =
            ["root", "nullifiers", "outputs", "max_fee", "deposit"];

        impl<'de> Visitor<'de> for TxSkeletonVisitor {
            type Value = TxSkeleton;

            fn expecting(
                &self,
                formatter: &mut alloc::fmt::Formatter,
            ) -> alloc::fmt::Result {
                formatter.write_str("a struct with fields: root, nullifiers, outputs, max_fee, and deposit")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut root: Option<BlsScalarSerde> = None;
                let mut nullifiers: Option<Vec<BlsScalarSerde>> = None;
                let mut outputs = None;
                let mut deposit: Option<Bigint> = None;
                let mut max_fee: Option<Bigint> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "root" => {
                            if root.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "root",
                                ));
                            }
                            root = Some(map.next_value()?);
                        }
                        "nullifiers" => {
                            if nullifiers.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "nullifiers",
                                ));
                            }
                            nullifiers = Some(map.next_value()?);
                        }
                        "outputs" => {
                            if outputs.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "outputs",
                                ));
                            }
                            outputs = Some(map.next_value()?);
                        }
                        "max_fee" => {
                            if max_fee.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "max_fee",
                                ));
                            }
                            max_fee = Some(map.next_value()?);
                        }
                        "deposit" => {
                            if deposit.is_some() {
                                return Err(SerdeError::duplicate_field(
                                    "deposit",
                                ));
                            }
                            deposit = Some(map.next_value()?);
                        }
                        field => {
                            return Err(SerdeError::unknown_field(
                                field, &FIELDS,
                            ))
                        }
                    }
                }
                Ok(TxSkeleton {
                    root: root
                        .ok_or_else(|| SerdeError::missing_field("root"))?
                        .0,
                    nullifiers: nullifiers
                        .ok_or_else(|| SerdeError::missing_field("nullifiers"))?
                        .into_iter()
                        .map(|serde_nullifier| serde_nullifier.0)
                        .collect(),
                    outputs: outputs
                        .ok_or_else(|| SerdeError::missing_field("output"))?,
                    max_fee: max_fee
                        .ok_or_else(|| SerdeError::missing_field("max_fee"))?
                        .0,
                    deposit: deposit
                        .ok_or_else(|| SerdeError::missing_field("deposit"))?
                        .0,
                })
            }
        }

        deserializer.deserialize_struct(
            "TxSkeleton",
            &FIELDS,
            TxSkeletonVisitor,
        )
    }
}
