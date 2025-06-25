//! Codec implementations for Malachite consensus messages

use crate::context::{BasePeerAddress, MalachiteContext};
use crate::height::Height;
use crate::proto;
use crate::{Address, ValueId};
use crate::{ProposalPart, Value};
use bytes::Bytes;
use malachitebft_app::engine::util::streaming::StreamMessage;
use malachitebft_codec::Codec;
use malachitebft_core_consensus::{LivenessMsg, ProposedValue, SignedConsensusMsg};
use malachitebft_core_types::{CommitCertificate, CommitSignature, Round, Validity, VoteType};
use malachitebft_proto::Error as ProtoError;
use malachitebft_signing_ed25519::Signature;
use malachitebft_sync as sync;
use prost::Message;

/// Protobuf codec for Malachite messages
#[derive(Copy, Clone, Debug)]
pub struct ProtoCodec;

// Helper functions for encoding/decoding
#[allow(dead_code)]
fn encode_signature(signature: &Signature) -> proto::Signature {
    proto::Signature {
        bytes: Bytes::copy_from_slice(signature.to_bytes().as_ref()),
    }
}

#[allow(dead_code)]
fn decode_signature(signature: proto::Signature) -> Result<Signature, ProtoError> {
    let bytes = <[u8; 64]>::try_from(signature.bytes.as_ref())
        .map_err(|_| ProtoError::Other("Invalid signature length".to_string()))?;
    Ok(Signature::from_bytes(bytes))
}

#[allow(dead_code)]
fn encode_votetype(vote_type: VoteType) -> proto::VoteType {
    match vote_type {
        VoteType::Prevote => proto::VoteType::Prevote,
        VoteType::Precommit => proto::VoteType::Precommit,
    }
}

#[allow(dead_code)]
fn decode_votetype(vote_type: i32) -> VoteType {
    match proto::VoteType::try_from(vote_type) {
        Ok(proto::VoteType::Prevote) => VoteType::Prevote,
        Ok(proto::VoteType::Precommit) => VoteType::Precommit,
        Err(_) => VoteType::Prevote, // Default fallback
    }
}

// For now, we'll implement only the essential codecs needed to compile
// In production, all of these would have proper implementations

impl Codec<Value> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<Value, Self::Error> {
        let proto = proto::Value::decode(bytes.as_ref())?;
        Ok(Value::new(proto.value.unwrap_or_default()))
    }

    fn encode(&self, msg: &Value) -> Result<Bytes, Self::Error> {
        let proto = proto::Value {
            value: Some(msg.extensions.clone()),
        };
        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<ProposalPart> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<ProposalPart, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &ProposalPart) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<SignedConsensusMsg<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<SignedConsensusMsg<MalachiteContext>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &SignedConsensusMsg<MalachiteContext>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<ProposedValue<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, bytes: Bytes) -> Result<ProposedValue<MalachiteContext>, Self::Error> {
        let proto = proto::ProposedValue::decode(bytes.as_ref())?;
        decode_proposed_value(proto)
    }

    fn encode(&self, msg: &ProposedValue<MalachiteContext>) -> Result<Bytes, Self::Error> {
        let proto = encode_proposed_value(msg)?;
        Ok(Bytes::from(proto.encode_to_vec()))
    }
}

impl Codec<LivenessMsg<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<LivenessMsg<MalachiteContext>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &LivenessMsg<MalachiteContext>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<StreamMessage<ProposalPart>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<StreamMessage<ProposalPart>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &StreamMessage<ProposalPart>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<sync::Status<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<sync::Status<MalachiteContext>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &sync::Status<MalachiteContext>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<sync::Request<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<sync::Request<MalachiteContext>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &sync::Request<MalachiteContext>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

impl Codec<sync::Response<MalachiteContext>> for ProtoCodec {
    type Error = ProtoError;

    fn decode(&self, _bytes: Bytes) -> Result<sync::Response<MalachiteContext>, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }

    fn encode(&self, _msg: &sync::Response<MalachiteContext>) -> Result<Bytes, Self::Error> {
        // Placeholder implementation
        Err(ProtoError::Other("Not implemented".to_string()))
    }
}

// Encoding/decoding functions for CommitCertificate
pub fn encode_commit_certificate(
    certificate: &CommitCertificate<MalachiteContext>,
) -> Result<proto::CommitCertificate, ProtoError> {
    Ok(proto::CommitCertificate {
        height: certificate.height.0,
        round: certificate
            .round
            .as_u32()
            .ok_or_else(|| ProtoError::Other("Round is nil, cannot encode".to_string()))?,
        value_id: Some(proto::ValueId {
            value: Some(Bytes::from(
                certificate.value_id.as_u64().to_be_bytes().to_vec(),
            )),
        }),
        signatures: certificate
            .commit_signatures
            .iter()
            .map(encode_commit_signature)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn decode_commit_certificate(
    proto: proto::CommitCertificate,
) -> Result<CommitCertificate<MalachiteContext>, ProtoError> {
    let value_id = proto
        .value_id
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitCertificate>("value_id"))?;

    let value_id_bytes = value_id
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::ValueId>("value"))?;

    Ok(CommitCertificate {
        height: Height(proto.height),
        round: Round::new(proto.round),
        value_id: ValueId::new(u64::from_be_bytes(
            value_id_bytes[..8].try_into().unwrap_or([0u8; 8]),
        )),
        commit_signatures: proto
            .signatures
            .into_iter()
            .map(decode_commit_signature)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn encode_commit_signature(
    signature: &CommitSignature<MalachiteContext>,
) -> Result<proto::CommitSignature, ProtoError> {
    Ok(proto::CommitSignature {
        validator_address: Some(proto::Address {
            value: Bytes::from(signature.address.0.as_bytes().to_vec()),
        }),
        signature: Some(encode_signature(&signature.signature)),
    })
}

fn decode_commit_signature(
    proto: proto::CommitSignature,
) -> Result<CommitSignature<MalachiteContext>, ProtoError> {
    let address = proto
        .validator_address
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitSignature>("validator_address"))?;

    let signature = proto
        .signature
        .ok_or_else(|| ProtoError::missing_field::<proto::CommitSignature>("signature"))?;

    let addr_bytes = &address.value;
    let address = if addr_bytes.len() == 20 {
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(addr_bytes);
        BasePeerAddress(Address::new(bytes))
    } else {
        return Err(ProtoError::Other("Invalid address length".to_string()));
    };

    Ok(CommitSignature::new(address, decode_signature(signature)?))
}

// Encoding/decoding functions for ProposedValue
fn encode_proposed_value(
    proposed_value: &ProposedValue<MalachiteContext>,
) -> Result<proto::ProposedValue, ProtoError> {
    Ok(proto::ProposedValue {
        height: proposed_value.height.0,
        round: proposed_value
            .round
            .as_u32()
            .ok_or_else(|| ProtoError::Other("Round is nil, cannot encode".to_string()))?,
        valid_round: proposed_value.valid_round.as_u32(),
        proposer: Some(proto::Address {
            value: Bytes::from(proposed_value.proposer.0.as_bytes().to_vec()),
        }),
        value: Some(proto::Value {
            value: Some(proposed_value.value.extensions.clone()),
        }),
        validity: proposed_value.validity.to_bool(),
    })
}

fn decode_proposed_value(
    proto: proto::ProposedValue,
) -> Result<ProposedValue<MalachiteContext>, ProtoError> {
    let proposer = proto
        .proposer
        .ok_or_else(|| ProtoError::missing_field::<proto::ProposedValue>("proposer"))?;

    let value = proto
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::ProposedValue>("value"))?;

    let value_data = value
        .value
        .ok_or_else(|| ProtoError::missing_field::<proto::Value>("value"))?;

    Ok(ProposedValue {
        height: Height(proto.height),
        round: Round::new(proto.round),
        valid_round: proto.valid_round.map(Round::new).unwrap_or(Round::Nil),
        proposer: {
            let addr_bytes = &proposer.value;
            if addr_bytes.len() == 20 {
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(addr_bytes);
                BasePeerAddress(Address::new(bytes))
            } else {
                return Err(ProtoError::Other(
                    "Invalid proposer address length".to_string(),
                ));
            }
        },
        value: Value::new(value_data),
        validity: Validity::from_bool(proto.validity),
    })
}
