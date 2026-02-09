//! Helper traits to wrap generic l1 errors, in network specific error type configured in
//! `reth_rpc_eth_api::EthApiTypes`.

use crate::{simulate::EthSimulateError, EthApiError, RevertError};
use alloy_primitives::Bytes;
use reth_errors::ProviderError;
use reth_evm::{ConfigureEvm, EvmErrorFor, HaltReasonFor};
use revm::{context::result::ExecutionResult, context_interface::result::HaltReason};

use super::RpcInvalidTransactionError;

/// Helper trait to convert from revm errors.
pub trait FromEvmError<Evm: ConfigureEvm>:
    From<EvmErrorFor<Evm, ProviderError>> + FromEvmHalt<HaltReasonFor<Evm>> + FromRevert
{
    /// Converts from EVM error to this type.
    fn from_evm_err(err: EvmErrorFor<Evm, ProviderError>) -> Self {
        err.into()
    }

    /// Ensures the execution result is successful or returns an error,
    fn ensure_success(result: ExecutionResult<HaltReasonFor<Evm>>) -> Result<Bytes, Self> {
        match result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data()),
            ExecutionResult::Revert { output, .. } => Err(Self::from_revert(output)),
            ExecutionResult::Halt { reason, gas_used } => {
                Err(Self::from_evm_halt(reason, gas_used))
            }
        }
    }
}

impl<T, Evm> FromEvmError<Evm> for T
where
    T: From<EvmErrorFor<Evm, ProviderError>> + FromEvmHalt<HaltReasonFor<Evm>> + FromRevert,
    Evm: ConfigureEvm,
{
}

/// Helper trait to convert from revm errors.
pub trait FromEvmHalt<Halt> {
    /// Converts from EVM halt to this type.
    fn from_evm_halt(halt: Halt, gas_limit: u64) -> Self;
}

impl FromEvmHalt<HaltReason> for EthApiError {
    fn from_evm_halt(halt: HaltReason, gas_limit: u64) -> Self {
        RpcInvalidTransactionError::halt(halt, gas_limit).into()
    }
}

/// Helper trait to construct errors from unexpected reverts.
pub trait FromRevert {
    /// Constructs an error from revert bytes.
    ///
    /// This is only invoked when revert was unexpected (`eth_call`, `eth_estimateGas`, etc).
    fn from_revert(output: Bytes) -> Self;
}

impl FromRevert for EthApiError {
    fn from_revert(output: Bytes) -> Self {
        RpcInvalidTransactionError::Revert(RevertError::new(output)).into()
    }
}
