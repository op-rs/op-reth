//! RPC methods allowing fetching proofs sync status.

use async_trait::async_trait;
use derive_more::Constructor;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee_core::RpcResult;
use reth_optimism_trie::OpProofsStore;
use reth_rpc_server_types::result::internal_rpc_err;
use serde::{Deserialize, Serialize};

/// Represents the current proofs sync status.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ProofsSyncStatus {
    /// The earliest block number for which proofs are available.
    earliest: Option<u64>,
    /// The latest block number for which proofs are available.
    latest: Option<u64>,
}

/// RPC methods allowing fetching proofs sync status.
#[cfg_attr(not(test), rpc(server, namespace = "optimism"))]
#[cfg_attr(test, rpc(server, client, namespace = "optimism"))]
trait OptimismApi {
    /// Returns the current proofs sync status.
    #[method(name = "proofsSyncStatus")]
    async fn proofs_sync_status(&self) -> RpcResult<ProofsSyncStatus>;
}

/// Implements the `optimism_` namespace of the RPC API for fetching proofs sync status.
#[derive(Debug, Constructor)]
pub struct OptimismApi<P> {
    external_storage: P,
}

#[async_trait]
impl<P> OptimismApiServer for OptimismApi<P>
where
    P: OpProofsStore + Clone + 'static,
{
    async fn proofs_sync_status(&self) -> RpcResult<ProofsSyncStatus> {
        let earliest = self
            .external_storage
            .get_earliest_block_number()
            .await
            .map_err(|err| internal_rpc_err(err.to_string()))?;
        let latest = self
            .external_storage
            .get_latest_block_number()
            .await
            .map_err(|err| internal_rpc_err(err.to_string()))?;

        Ok(ProofsSyncStatus {
            earliest: earliest.map(|(block_number, _)| block_number),
            latest: latest.map(|(block_number, _)| block_number),
        })
    }
}
