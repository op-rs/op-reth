//! Block verification w.r.t. consensus rules new in Jovian hardfork.

use alloy_consensus::BlockHeader;
use reth_consensus::ConsensusError;
use reth_execution_types::BlockExecutionResult;
use reth_optimism_primitives::DepositReceipt;
use reth_primitives_traits::GotExpected;

/// Validates that the blob gas used is present and correctly computed if Jovian is active.
///
/// After Jovian activation, blocks must include the `blob_gas_used` field in the header,
/// and it must match the computed blob gas used from execution.
pub fn validate_blob_gas_used<R: DepositReceipt>(
    header: impl BlockHeader,
    result: &BlockExecutionResult<R>,
) -> Result<(), ConsensusError> {
    let computed_blob_gas_used = result.blob_gas_used;
    let header_blob_gas_used = header.blob_gas_used().ok_or(ConsensusError::BlobGasUsedMissing)?;

    if computed_blob_gas_used != header_blob_gas_used {
        return Err(ConsensusError::BlobGasUsedDiff(GotExpected {
            got: computed_blob_gas_used,
            expected: header_blob_gas_used,
        }));
    }

    Ok(())
}
