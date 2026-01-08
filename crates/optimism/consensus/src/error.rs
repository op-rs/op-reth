//! Optimism consensus errors

use alloc::sync::Arc;
use alloy_primitives::B256;
use reth_consensus::ConsensusError;
use reth_storage_errors::provider::ProviderError;

/// Optimism consensus error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OpConsensusError {
    /// Block body has non-empty withdrawals list (l1 withdrawals).
    #[error("non-empty block body withdrawals list")]
    WithdrawalsNonEmpty,
    /// Failed to compute L2 withdrawals storage root.
    #[error("compute L2 withdrawals root failed: {_0}")]
    L2WithdrawalsRootCalculationFail(#[from] ProviderError),
    /// L2 withdrawals root missing in block header.
    #[error("L2 withdrawals root missing from block header")]
    L2WithdrawalsRootMissing,
    /// L2 withdrawals root in block header, doesn't match local storage root of predeploy.
    #[error("L2 withdrawals root mismatch, header: {header}, exec_res: {exec_res}")]
    L2WithdrawalsRootMismatch {
        /// Storage root of pre-deploy in block.
        header: B256,
        /// Storage root of pre-deploy loaded from local state.
        exec_res: B256,
    },
    /// L1 [`ConsensusError`], that also occurs on L2.
    #[error(transparent)]
    Eth(ConsensusError),
}

impl From<OpConsensusError> for ConsensusError {
    fn from(error: OpConsensusError) -> Self {
        match error {
            OpConsensusError::Eth(err) => err,
            _ => Self::Custom(Arc::new(error)),
        }
    }
}

impl From<ConsensusError> for OpConsensusError {
    fn from(error: ConsensusError) -> Self {
        if let ConsensusError::Custom(ref err) = error &&
            let Some(op_err) = err.downcast_ref::<Self>()
        {
            return op_err.clone()
        }
        Self::Eth(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_error_from_op_consensus_error() {
        let consensus_err = ConsensusError::BaseFeeMissing;
        let op_err = OpConsensusError::Eth(consensus_err);
        let converted: ConsensusError = op_err.into();
        assert!(matches!(converted, ConsensusError::BaseFeeMissing));

        let op_specific_err = OpConsensusError::WithdrawalsNonEmpty;
        let converted: ConsensusError = op_specific_err.into();
        assert!(matches!(converted, ConsensusError::Custom(_)));
    }

    #[test]
    fn op_consensus_error_from_consensus_error() {
        let consensus_err = ConsensusError::BaseFeeMissing;
        let op_err: OpConsensusError = consensus_err.into();
        assert!(matches!(op_err, OpConsensusError::Eth(_)));

        let original = OpConsensusError::WithdrawalsNonEmpty;
        let as_consensus: ConsensusError = original.into();
        let back_to_op: OpConsensusError = as_consensus.into();

        assert!(matches!(back_to_op, OpConsensusError::WithdrawalsNonEmpty));
    }
}
