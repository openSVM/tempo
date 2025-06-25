use crate::context::{BasePeerAddress, BasePeerSet, MalachiteContext};
use crate::height::Height;
use crate::provider::Ed25519Provider;
use crate::store::Store;
use crate::types::Address;
use crate::utils::seed_from_address;
use crate::{ProposalPart, Value};
use bytes::Bytes;
use eyre::Result;
use malachitebft_app_channel::app::streaming::StreamMessage;
use malachitebft_app_channel::app::types::{
    LocallyProposedValue, PeerId as MalachitePeerId, ProposedValue,
};
use malachitebft_core_types::{CommitCertificate, Height as HeightTrait, Round, VoteExtensions};
use rand::rngs::StdRng;
use rand::SeedableRng;
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_node_builder::NodeTypes;
use reth_node_ethereum::EthereumNode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;
use tracing::info;

/// Thread-safe wrapper for StdRng
#[derive(Debug)]
struct ThreadSafeRng {
    inner: Arc<TokioMutex<StdRng>>,
}

impl ThreadSafeRng {
    fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(TokioMutex::new(StdRng::seed_from_u64(seed))),
        }
    }

    async fn with_rng<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdRng) -> R,
    {
        let mut rng = self.inner.lock().await;
        f(&mut rng)
    }
}

impl Clone for ThreadSafeRng {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Represents the internal state of the application node
/// Contains information about current height, round, proposals and blocks
/// Thread-safe for concurrent access
#[derive(Clone)]
pub struct State {
    // Immutable fields (no synchronization needed)
    pub ctx: MalachiteContext,
    pub config: Config,
    pub genesis: Genesis,
    pub address: Address,
    pub store: Store, // Already thread-safe
    pub signing_provider: Ed25519Provider,
    pub engine_handle: BeaconConsensusEngineHandle<<EthereumNode as NodeTypes>::Payload>,

    // Mutable fields wrapped in RwLock for concurrent read/write access
    current_height: Arc<RwLock<Height>>,
    current_round: Arc<RwLock<Round>>,
    current_proposer: Arc<RwLock<Option<BasePeerAddress>>>,
    current_role: Arc<RwLock<Role>>,
    peers: Arc<RwLock<HashSet<MalachitePeerId>>>,
    streams_map: Arc<RwLock<PartStreamsMap>>,

    // Thread-safe RNG
    rng: ThreadSafeRng,
}

impl State {
    pub fn new(
        ctx: MalachiteContext,
        config: Config,
        genesis: Genesis,
        address: Address,
        store: Store,
        engine_handle: BeaconConsensusEngineHandle<<EthereumNode as NodeTypes>::Payload>,
    ) -> Self {
        Self {
            ctx,
            config,
            genesis,
            address,
            store,
            signing_provider: Ed25519Provider::new_test(),
            engine_handle,
            current_height: Arc::new(RwLock::new(Height::default())),
            current_round: Arc::new(RwLock::new(Round::Nil)),
            current_proposer: Arc::new(RwLock::new(None)),
            current_role: Arc::new(RwLock::new(Role::None)),
            peers: Arc::new(RwLock::new(HashSet::new())),
            streams_map: Arc::new(RwLock::new(PartStreamsMap::new())),
            rng: ThreadSafeRng::new(seed_from_address(&address, std::process::id() as u64)),
        }
    }

    // Getter methods for thread-safe access
    pub fn current_height(&self) -> Result<Height> {
        Ok(*self
            .current_height
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_height(&self, height: Height) -> Result<()> {
        *self
            .current_height
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = height;
        Ok(())
    }

    pub fn current_round(&self) -> Result<Round> {
        Ok(*self
            .current_round
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_round(&self, round: Round) -> Result<()> {
        *self
            .current_round
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = round;
        Ok(())
    }

    pub fn current_proposer(&self) -> Result<Option<BasePeerAddress>> {
        Ok(self
            .current_proposer
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .clone())
    }

    pub fn set_current_proposer(&self, proposer: Option<BasePeerAddress>) -> Result<()> {
        *self
            .current_proposer
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = proposer;
        Ok(())
    }

    pub fn current_role(&self) -> Result<Role> {
        Ok(*self
            .current_role
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_role(&self, role: Role) -> Result<()> {
        *self
            .current_role
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = role;
        Ok(())
    }

    pub fn add_peer(&self, peer: MalachitePeerId) -> Result<()> {
        self.peers
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .insert(peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer: &MalachitePeerId) -> Result<bool> {
        Ok(self
            .peers
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .remove(peer))
    }

    pub fn get_peers(&self) -> Result<HashSet<MalachitePeerId>> {
        Ok(self
            .peers
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .clone())
    }

    pub fn signing_provider(&self) -> &Ed25519Provider {
        &self.signing_provider
    }

    // RNG access through async interface
    pub async fn with_rng<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdRng) -> R,
    {
        self.rng.with_rng(f).await
    }

    /// Returns the validator set for the given height
    /// For now, returns a fixed validator set from genesis
    pub fn get_validator_set(&self, _height: Height) -> BasePeerSet {
        // For now, return a simple validator set based on genesis
        // In a real implementation, this would query the actual validator set
        BasePeerSet {
            peers: vec![],
            total_voting_power: 0,
        }
    }

    /// Creates a new proposal value for the given height and round
    pub async fn propose_value(
        &self,
        height: Height,
        round: Round,
    ) -> Result<LocallyProposedValue<MalachiteContext>> {
        // Simulate building a block
        sleep(Duration::from_millis(100)).await;

        // Create a simple value - in real implementation this would be a proper block
        let value = Value::new(bytes::Bytes::from(vec![1, 2, 3, 4])); // Placeholder data

        info!("Proposed value for height {} round {}", height, round);

        Ok(LocallyProposedValue::new(height, round, value))
    }

    /// Processes a received proposal part and potentially returns a complete proposal
    pub async fn received_proposal_part(
        &self,
        from: MalachitePeerId,
        _part: StreamMessage<ProposalPart>,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        // For now, just return None - this would normally reassemble streaming proposals
        info!("Received proposal part from {}", from);
        Ok(None)
    }

    /// Creates stream messages for a proposal
    pub fn stream_proposal(
        &self,
        value: LocallyProposedValue<MalachiteContext>,
        _pol_round: Round,
    ) -> impl Iterator<Item = StreamMessage<ProposalPart>> {
        // For now, return empty iterator - this would normally split proposal into parts
        info!("Streaming proposal for height {}", value.height);
        std::iter::empty()
    }

    /// Commits a decided value
    pub async fn commit(
        &self,
        certificate: CommitCertificate<MalachiteContext>,
        _extensions: VoteExtensions<MalachiteContext>,
    ) -> Result<()> {
        info!("Committing value at height {}", certificate.height);
        // In real implementation, this would commit the block to the chain
        Ok(())
    }

    /// Gets a decided value at the given height
    pub async fn get_decided_value(&self, height: Height) -> Option<DecidedValue> {
        // For now, return None - this would query the committed blocks
        info!("Requested decided value for height {}", height);
        None
    }

    /// Gets the earliest available height
    pub async fn get_earliest_height(&self) -> Height {
        Height::INITIAL // Start from height 1
    }

    /// Gets a previously built value for reuse
    pub async fn get_previously_built_value(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Option<LocallyProposedValue<MalachiteContext>>> {
        // For now, return None - this would check for previously built proposals
        info!(
            "Requested previously built value for height {} round {}",
            height, round
        );
        Ok(None)
    }

    // Stream map operations
    pub fn get_stream(&self, peer_id: &MalachitePeerId) -> Result<Option<PartialStreamState>> {
        Ok(self
            .streams_map
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .get_stream(peer_id)
            .cloned())
    }

    pub fn insert_stream(
        &self,
        peer_id: MalachitePeerId,
        stream: PartialStreamState,
    ) -> Result<()> {
        self.streams_map
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .insert_stream(peer_id, stream);
        Ok(())
    }

    pub fn remove_stream(&self, peer_id: &MalachitePeerId) -> Result<Option<PartialStreamState>> {
        Ok(self
            .streams_map
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .remove_stream(peer_id))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub validators: Vec<ValidatorInfo>,
    pub app_state: Vec<u8>,
}

impl Genesis {
    pub fn new(chain_id: String) -> Self {
        Self {
            chain_id,
            validators: Vec::new(),
            app_state: Vec::new(),
        }
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorInfo>) -> Self {
        self.validators = validators;
        self
    }

    pub fn with_app_state(mut self, app_state: Vec<u8>) -> Self {
        self.app_state = app_state;
        self
    }
}

impl Default for Genesis {
    fn default() -> Self {
        Self::new("malachite-test".to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub voting_power: u64,
    pub public_key: Vec<u8>,
}

impl ValidatorInfo {
    pub fn new(address: Address, voting_power: u64, public_key: Vec<u8>) -> Self {
        Self {
            address,
            voting_power,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub block_time: std::time::Duration,
    pub create_empty_blocks: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            block_time: std::time::Duration::from_secs(1),
            create_empty_blocks: true,
        }
    }
}

/// The role that the node is playing in the consensus protocol during a round.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// The node is the proposer for the current round.
    Proposer,
    /// The node is a validator for the current round.
    Validator,
    /// The node is not participating in the consensus protocol for the current round.
    None,
}

// Role conversion implementation removed as Role type is not exported from malachitebft_app_channel

#[derive(Debug, Clone)]
pub struct PartStreamsMap {
    // Maps from peer ID to their partial stream state
    streams: HashMap<MalachitePeerId, PartialStreamState>,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn get_stream(&self, peer_id: &MalachitePeerId) -> Option<&PartialStreamState> {
        self.streams.get(peer_id)
    }

    pub fn get_stream_mut(&mut self, peer_id: &MalachitePeerId) -> Option<&mut PartialStreamState> {
        self.streams.get_mut(peer_id)
    }

    pub fn insert_stream(&mut self, peer_id: MalachitePeerId, stream: PartialStreamState) {
        self.streams.insert(peer_id, stream);
    }

    pub fn remove_stream(&mut self, peer_id: &MalachitePeerId) -> Option<PartialStreamState> {
        self.streams.remove(peer_id)
    }
}

impl Default for PartStreamsMap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PartialStreamState {
    pub height: Height,
    pub round: Round,
    pub step: ConsensusStep,
    pub last_activity: std::time::Instant,
}

impl PartialStreamState {
    pub fn new(height: Height, round: Round) -> Self {
        Self {
            height,
            round,
            step: ConsensusStep::NewHeight,
            last_activity: std::time::Instant::now(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStep {
    NewHeight,
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

// Additional types needed for the consensus interface

#[derive(Debug, Clone)]
pub struct DecidedValue {
    pub value: Value,
    pub certificate: CommitCertificate<MalachiteContext>,
}

// Standalone functions

/// Reload the tracing subscriber log level based on the current height and round
pub fn reload_log_level(_height: Height, _round: Round) {
    // For now, do nothing - this would adjust log levels
}

/// Encode a value to its byte representation
pub fn encode_value(_value: &Value) -> Bytes {
    // For now, return empty bytes - this would serialize the value
    Bytes::new()
}

/// Decode a value from its byte representation
pub fn decode_value(_bytes: Bytes) -> Option<Value> {
    // For now, return None - this would deserialize the value
    None
}

// Type alias for compatibility
