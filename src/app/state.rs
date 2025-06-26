//! Application state management for Malachite consensus integration.
//!
//! This module implements the core application logic that bridges Malachite consensus
//! with Reth's execution engine. It handles:
//!
//! - Block proposal creation when requested by consensus
//! - Block validation and execution when received from peers
//! - State persistence and management across consensus rounds
//! - Communication with Reth's engine API for block processing
//!
//! The [`State`] struct is the main entry point, implementing the Malachite application
//! interface to respond to consensus events like proposal requests and commit decisions.
//!
//! # Architecture
//!
//! The state maintains connections to:
//! - Reth's beacon engine handle for block execution
//! - Payload builder for creating new blocks
//! - Storage layer for persisting consensus data
//! - Validator configuration and cryptographic keys

use crate::{
    context::{BasePeerAddress, BasePeerSet, MalachiteContext},
    height::Height,
    provider::Ed25519Provider,
    store::{DecidedValue, Store},
    types::{Address, ValueId},
    utils::seed_from_address,
    ProposalPart, Value,
};
use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatusEnum};
use bytes::Bytes;
use eyre::Result;
use malachitebft_app_channel::app::{
    streaming::StreamMessage,
    types::{LocallyProposedValue, PeerId as MalachitePeerId, ProposedValue},
};
use malachitebft_core_types::{
    CommitCertificate, Height as HeightTrait, Round, Validity, VoteExtensions,
};
use rand::{rngs::StdRng, SeedableRng};
use reth_engine_primitives::BeaconConsensusEngineHandle;
use reth_node_builder::{NodeTypes, PayloadTypes};
use reth_node_ethereum::EthereumNode;
use reth_payload_builder::{PayloadBuilderHandle, PayloadStore};
use reth_payload_primitives::{EngineApiMessageVersion, PayloadKind};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};

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

// Manual Clone implementation for State since PayloadStore doesn't implement Clone
impl Clone for State {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            config: self.config.clone(),
            genesis: self.genesis.clone(),
            address: self.address,
            store: self.store.clone(),
            signing_provider: self.signing_provider.clone(),
            engine_handle: self.engine_handle.clone(),
            payload_store: Arc::clone(&self.payload_store),
            current_height: Arc::clone(&self.current_height),
            current_round: Arc::clone(&self.current_round),
            current_proposer: Arc::clone(&self.current_proposer),
            current_role: Arc::clone(&self.current_role),
            peers: Arc::clone(&self.peers),
            streams_map: Arc::clone(&self.streams_map),
            rng: self.rng.clone(),
        }
    }
}

/// State represents the application state for the Malachite-Reth integration.
/// It manages consensus state, validator information, and block production.
///
/// # Architecture and API Boundaries
///
/// State serves as the central mediator between the consensus engine and the storage layer:
///
/// ```text
/// Consensus Handler
///       | (calls State methods)
///     State
///       | (internal Store access)
///     Store
///       | (database operations)
///   RethStore
/// ```
///
/// ## API Categories:
///
/// - **Consensus Operations**: `commit()`, `propose_value()`, `get_decided_value()`
/// - **State Management**: `current_height()`, `current_round()`, `get_validator_set()`
/// - **Storage Access**: `store_synced_proposal()`, `get_proposal_for_restreaming()`
/// - **Peer Management**: `add_peer()`, `remove_peer()`, `get_peers()`
pub struct State {
    // Immutable fields (no synchronization needed)
    pub ctx: MalachiteContext,
    pub config: Config,
    pub genesis: Genesis,
    pub address: Address,
    store: Store, // Already thread-safe
    pub signing_provider: Ed25519Provider,
    pub engine_handle: BeaconConsensusEngineHandle<<EthereumNode as NodeTypes>::Payload>,
    pub payload_store: Arc<PayloadStore<<EthereumNode as NodeTypes>::Payload>>,

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
        payload_builder_handle: PayloadBuilderHandle<<EthereumNode as NodeTypes>::Payload>,
        signing_provider: Option<Ed25519Provider>,
    ) -> Self {
        let payload_store = Arc::new(PayloadStore::new(payload_builder_handle));

        Self {
            ctx,
            config,
            genesis,
            address,
            store,
            signing_provider: signing_provider.unwrap_or_else(Ed25519Provider::new_test),
            engine_handle,
            payload_store,
            current_height: Arc::new(RwLock::new(Height::default())),
            current_round: Arc::new(RwLock::new(Round::Nil)),
            current_proposer: Arc::new(RwLock::new(None)),
            current_role: Arc::new(RwLock::new(Role::None)),
            peers: Arc::new(RwLock::new(HashSet::new())),
            streams_map: Arc::new(RwLock::new(PartStreamsMap::new())),
            rng: ThreadSafeRng::new(seed_from_address(&address, std::process::id() as u64)),
        }
    }

    /// Creates a new State instance from a database provider.
    ///
    /// This factory method encapsulates Store creation and initialization,
    /// ensuring that Store is not directly accessible outside the State module.
    pub async fn from_provider<P>(
        ctx: MalachiteContext,
        config: Config,
        genesis: Genesis,
        address: Address,
        provider: Arc<P>,
        engine_handle: BeaconConsensusEngineHandle<<EthereumNode as NodeTypes>::Payload>,
        payload_builder_handle: PayloadBuilderHandle<<EthereumNode as NodeTypes>::Payload>,
        signing_provider: Option<Ed25519Provider>,
    ) -> Result<Self>
    where
        P: reth_provider::DatabaseProviderFactory + Clone + Unpin + Send + Sync + 'static,
        <P as reth_provider::DatabaseProviderFactory>::Provider: Send + Sync,
        <P as reth_provider::DatabaseProviderFactory>::ProviderRW: Send,
    {
        // Create and verify the store
        let store = Store::new(provider);
        store.verify_tables().await?;

        Ok(Self::new(
            ctx,
            config,
            genesis,
            address,
            store,
            engine_handle,
            payload_builder_handle,
            signing_provider,
        ))
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
        // 1. Create payload attributes for the block at this height
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let parent_hash = self.get_parent_hash(height).await?;

        let payload_attrs = alloy_rpc_types_engine::PayloadAttributes {
            timestamp,
            prev_randao: B256::ZERO, // For PoS compatibility
            suggested_fee_recipient: self.config.fee_recipient,
            withdrawals: Some(vec![]), // Empty withdrawals for post-Shanghai
            parent_beacon_block_root: Some(B256::ZERO),
        };

        // 2. Send FCU to trigger payload building
        let forkchoice_state = ForkchoiceState {
            head_block_hash: parent_hash,
            safe_block_hash: parent_hash,
            finalized_block_hash: self.get_finalized_hash().await?,
        };

        let fcu_response = self
            .engine_handle
            .fork_choice_updated(
                forkchoice_state,
                Some(payload_attrs),
                EngineApiMessageVersion::V3,
            )
            .await?;

        // 3. Get the payload ID from the response
        let payload_id = fcu_response
            .payload_id
            .ok_or_else(|| eyre::eyre!("No payload ID returned from FCU"))?;

        // 4. Get the built payload - use WaitForPending to wait for at least one built payload
        // This will wait for the payload builder to produce a payload with transactions
        // It won't return an empty payload immediately like Earliest would
        let payload = self
            .payload_store
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
            .ok_or_else(|| eyre::eyre!("No payload found for id {:?}", payload_id))??;

        let sealed_block = payload.block();
        let value = Value::new(sealed_block.clone_block());

        info!(
            "Proposed value for height {} round {} with payload {:?}",
            height, round, payload_id
        );

        let locally_proposed = LocallyProposedValue::new(height, round, value.clone());

        // Store the proposal we just built so it can be retrieved later
        let proposer = BasePeerAddress(self.address);
        let proposed_value = ProposedValue {
            height,
            round,
            valid_round: Round::Nil,
            proposer,
            value,
            validity: Validity::Valid,
        };

        self.store_built_proposal(proposed_value).await?;

        Ok(locally_proposed)
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
        let height = certificate.height;
        let round = certificate.round;
        let value_id = certificate.value_id;

        info!(
            "Committing value at height {} round {} with value_id {:?}",
            height, round, value_id
        );

        // Try to find the value that matches the value_id
        // First check the round where it was decided, then check all rounds
        let mut value = None;

        // Check the decided round first
        if let Ok(Some(proposal)) = self.get_undecided_proposal(height, round, value_id).await {
            value = Some(proposal.value);
        }

        // If not found, search all rounds (the proposal might have been from an earlier round)
        if value.is_none() {
            for check_round in 0..=round.as_i64() as u32 {
                if let Ok(Some(proposal)) = self
                    .get_undecided_proposal(height, Round::new(check_round), value_id)
                    .await
                {
                    value = Some(proposal.value);
                    break;
                }
            }
        }

        // If we still don't have the value, this is an error
        let value = value.ok_or_else(|| {
            eyre::eyre!(
                "Could not find proposal for value_id {:?} at height {}",
                value_id,
                height
            )
        })?;

        // 1. Store the decided value first (for persistence)
        self.store
            .store_decided_value(certificate, value.clone())
            .await?;

        // 2. Convert the block to execution payload and send new_payload to validate it
        let block = &value.block;
        let sealed_block = reth_primitives::SealedBlock::seal_slow(block.clone());
        let payload =
            <reth_node_ethereum::EthEngineTypes as PayloadTypes>::block_to_payload(sealed_block);
        let payload_status = self.engine_handle.new_payload(payload).await?;

        if payload_status.status != PayloadStatusEnum::Valid {
            return Err(eyre::eyre!("Invalid payload status: {:?}", payload_status));
        }

        // 3. Update fork choice to make this block canonical
        let block_hash = block.header.hash_slow();
        let forkchoice_state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash, // In Malachite with instant finality, head = safe = finalized
            finalized_block_hash: block_hash, // Instant finality means committed = finalized
        };

        let fcu_response = self
            .engine_handle
            .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::V3)
            .await?;

        if fcu_response.payload_status.status != PayloadStatusEnum::Valid {
            return Err(eyre::eyre!("Invalid FCU response: {:?}", fcu_response));
        }

        info!(
            "Successfully committed block at height {} with hash {}",
            height, block_hash
        );

        Ok(())
    }

    /// Gets a decided value at the given height
    pub async fn get_decided_value(&self, height: Height) -> Option<DecidedValue> {
        match self.store.get_decided_value(height).await {
            Ok(value) => value,
            Err(e) => {
                tracing::error!("Failed to get decided value at height {}: {}", height, e);
                None
            }
        }
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
        info!(
            "Requested previously built value for height {} round {}",
            height, round
        );

        // Try to find any proposal we built for this height
        // Check the requested round and also round 0 (in case we're looking for any proposal)
        for check_round in [round, Round::new(0)] {
            if let Ok(proposals) = self.get_undecided_proposals(height, check_round).await {
                // Find a proposal that was built by us
                for proposal in proposals {
                    if proposal.proposer == BasePeerAddress(self.address) {
                        return Ok(Some(LocallyProposedValue::new(
                            height,
                            round,
                            proposal.value,
                        )));
                    }
                }
            }
        }

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

    // ===== Store Access API =====
    // The following methods provide controlled access to the Store for Consensus.
    // This design ensures that:
    // 1. Consensus never directly accesses Store
    // 2. State can enforce business rules and maintain invariants
    // 3. Storage implementation details are hidden from Consensus
    //
    // API Design:
    // - All Store access MUST go through State methods
    // - State methods provide domain-specific operations, not raw storage access
    // - State is responsible for data validation and business logic

    /// Stores a proposal that was synced from another node.
    ///
    /// This is called by consensus when it receives a complete proposal
    /// through the sync mechanism.
    pub async fn store_synced_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
    ) -> Result<()> {
        tracing::debug!(
            height = %proposal.height,
            round = %proposal.round,
            proposer = %proposal.proposer,
            "Storing synced proposal"
        );
        self.store.store_undecided_proposal(proposal).await
    }

    /// Retrieves a previously stored proposal for restreaming to peers.
    ///
    /// This is called when consensus needs to rebroadcast a proposal,
    /// typically when a validator missed the original broadcast.
    pub async fn get_proposal_for_restreaming(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        tracing::debug!(
            %height,
            %round,
            value_id = ?value_id,
            "Retrieving proposal for restreaming"
        );
        self.store
            .get_undecided_proposal(height, round, value_id)
            .await
    }

    /// Gets the highest height with a decided value.
    ///
    /// This can be used to determine the current chain height or to find
    /// gaps in the decided values.
    pub async fn get_max_decided_height(&self) -> Option<Height> {
        self.store.max_decided_value_height().await
    }

    /// Gets all undecided proposals for a specific height and round.
    ///
    /// This might be useful for debugging or for consensus to check
    /// what proposals it has received.
    pub async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>> {
        self.store.get_undecided_proposals(height, round).await
    }

    /// Stores a value that this node has built (not synced from others).
    ///
    /// This is called after successfully building a proposal in propose_value().
    /// Storing it allows us to retrieve it later if needed (e.g., for restreaming).
    pub async fn store_built_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
    ) -> Result<()> {
        tracing::debug!(
            height = %proposal.height,
            round = %proposal.round,
            "Storing locally built proposal"
        );
        self.store.store_undecided_proposal(proposal).await
    }

    /// Gets a specific undecided proposal by height, round, and value_id.
    ///
    /// This is used internally by State for looking up proposals during commit.
    async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        self.store
            .get_undecided_proposal(height, round, value_id)
            .await
    }

    /// Get the parent hash for a given height
    async fn get_parent_hash(&self, height: Height) -> Result<B256> {
        if height.as_u64() == 0 {
            return Ok(self.genesis.genesis_hash);
        }

        let parent_height = Height(height.as_u64() - 1);
        let parent = self
            .get_decided_value(parent_height)
            .await
            .ok_or_else(|| eyre::eyre!("Parent block not found at height {}", parent_height))?;

        Ok(parent.value.block.header.hash_slow())
    }

    /// Get the finalized block hash
    /// In Malachite, blocks have instant finality - once committed, they're immediately finalized
    async fn get_finalized_hash(&self) -> Result<B256> {
        // Get the highest decided block height from the store
        if let Some(max_height) = self.get_max_decided_height().await {
            if let Some(decided) = self.get_decided_value(max_height).await {
                return Ok(decided.value.block.header.hash_slow());
            }
        }

        // If no decided blocks yet, use genesis
        Ok(self.genesis.genesis_hash)
    }

    /// Validate a synced block through the engine API
    /// Returns true if the block is valid, false otherwise
    pub async fn validate_synced_block(&self, block: &reth_primitives::Block) -> Result<bool> {
        // Convert the block to execution payload
        let sealed_block = reth_primitives::SealedBlock::seal_slow(block.clone());
        let payload =
            <reth_node_ethereum::EthEngineTypes as PayloadTypes>::block_to_payload(sealed_block);
        // Send new_payload to validate it
        let payload_status = self.engine_handle.new_payload(payload).await?;

        match payload_status.status {
            PayloadStatusEnum::Valid => {
                info!("Synced block validated successfully");
                Ok(true)
            }
            PayloadStatusEnum::Invalid { .. } => {
                warn!("Synced block is invalid: {:?}", payload_status);
                Ok(false)
            }
            PayloadStatusEnum::Syncing => {
                // The node is still syncing, we might want to retry later
                info!("Engine is syncing, cannot validate block yet");
                Ok(false)
            }
            PayloadStatusEnum::Accepted => {
                // Block is accepted but not yet validated
                info!("Block accepted but not yet validated");
                Ok(true) // For now, treat as valid
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub validators: Vec<ValidatorInfo>,
    pub app_state: Vec<u8>,
    pub genesis_hash: B256,
}

impl Genesis {
    pub fn new(chain_id: String) -> Self {
        Self {
            chain_id,
            validators: Vec::new(),
            app_state: Vec::new(),
            genesis_hash: B256::ZERO,
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
    pub fee_recipient: alloy_primitives::Address,
    pub block_build_time_ms: u64,
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
            fee_recipient: alloy_primitives::Address::ZERO,
            block_build_time_ms: 500,
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

// Standalone functions

/// Reload the tracing subscriber log level based on the current height and round
pub fn reload_log_level(_height: Height, _round: Round) {
    // For now, do nothing - this would adjust log levels
}

/// Encode a value to its byte representation
pub fn encode_value(value: &Value) -> Bytes {
    // Serialize the block using bincode
    match bincode::serialize(&value.block) {
        Ok(bytes) => Bytes::from(bytes),
        Err(e) => {
            tracing::error!("Failed to encode value: {}", e);
            Bytes::new()
        }
    }
}

/// Decode a value from its byte representation
pub fn decode_value(bytes: Bytes) -> Option<Value> {
    // Deserialize the block using bincode
    match bincode::deserialize::<reth_primitives::Block>(&bytes) {
        Ok(block) => Some(Value::new(block)),
        Err(e) => {
            tracing::error!("Failed to decode value: {}", e);
            None
        }
    }
}

// Type alias for compatibility
