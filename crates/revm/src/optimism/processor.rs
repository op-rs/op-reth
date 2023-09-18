//! Optimism-specific execution logic.

use crate::processor::EVMProcessor;
use reth_interfaces::executor::{BlockExecutionError, BlockValidationError};
use reth_primitives::{bytes::BytesMut, Address, Block, Hardfork, Receipt, U256};
use reth_revm_primitives::into_reth_log;
use revm::{
    primitives::{ExecutionResult, ResultAndState},
    Database, DatabaseCommit,
};
use std::{sync::Arc, time::Instant};
use tracing::trace;

impl<'a> EVMProcessor<'a> {
    /// Runs the provided transactions and commits their state to the run-time database.
    ///
    /// The returned [BundleStateWithReceipts] can be used to persist the changes to disk, and
    /// contains the changes made by each transaction.
    ///
    /// The changes in [BundleStateWithReceipts] have a transition ID associated with them: there is
    /// one transition ID for each transaction (with the first executed tx having transition ID
    /// 0, and so on).
    ///
    /// The second returned value represents the total gas used by this block of transactions.
    pub fn execute_transactions(
        &mut self,
        block: &Block,
        total_difficulty: U256,
        senders: Option<Vec<Address>>,
    ) -> Result<(Vec<Receipt>, u64), BlockExecutionError> {
        // perf: do not execute empty blocks
        if block.body.is_empty() {
            return Ok((Vec::new(), 0))
        }

        let senders = self.recover_senders(&block.body, senders)?;
        self.init_env(&block.header, total_difficulty);

        let l1_block_info =
            self.chain_spec.optimism.then(|| super::L1BlockInfo::try_from(block)).transpose()?;

        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body.len());
        for (transaction, sender) in block.body.iter().zip(senders) {
            let time = Instant::now();

            // The sum of the transaction’s gas limit, Tg, and the gas utilised in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;

            let is_regolith =
                self.chain_spec.fork(Hardfork::Regolith).active_at_timestamp(block.timestamp);

            // Before regolith, system transactions did not care about the block gas limit as
            // they did not contribute any gas usage to the block.
            if transaction.gas_limit() > block_available_gas &&
                (is_regolith || !transaction.is_system_transaction())
            {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }

            // Before regolith, deposit transaction gas accounting was as follows:
            // - System tx: 0 gas used
            // - Regular Deposit tx: gas used = gas limit
            //
            // After regolith, system transactions are deprecated and deposit transactions
            // report the gas used during execution. all deposit transactions receive a gas
            // refund, but still skip coinbase payments.
            //
            // Deposit transactions only report this gas - their gas is prepaid on L1 and
            // the gas price is always 0. Deposit txs should not be subject to any regular
            // balance checks, base fee checks, or block gas limit checks.
            if transaction.is_deposit() {
                self.evm.env.cfg.disable_base_fee = true;
                self.evm.env.cfg.disable_block_gas_limit = true;
                self.evm.env.cfg.disable_balance_check = true;

                if !is_regolith {
                    self.evm.env.cfg.disable_gas_refund = true;
                }
            }

            let chain_spec = Arc::clone(&self.chain_spec);

            if let Some(m) = transaction.mint() {
                // Add balance to the caler account equal to the minted amount.
                // Note: This is unconditional, and will not be reverted if the tx fails
                // (unless the block can't be built at all due to gas limit constraints)
                let mut sender_account = self
                    .db_mut()
                    .database
                    .basic(sender)
                    .map_err(|_| BlockExecutionError::ProviderError)?
                    .ok_or(BlockExecutionError::Validation(
                        BlockValidationError::SenderRecoveryError,
                    ))?;
                sender_account.balance += U256::from(m);
            }

            let mut encoded = BytesMut::default();
            transaction.encode_enveloped(&mut encoded);
            let l1_cost = l1_block_info.as_ref().map(|l1_block_info| {
                l1_block_info.calculate_tx_l1_cost(
                    chain_spec,
                    block.timestamp,
                    &encoded.freeze().into(),
                    transaction.is_deposit(),
                )
            });

            if let Some(l1_cost) = l1_cost {
                // Check if the sender balance can cover the L1 cost.
                // Deposits pay for their gas directly on L1 so they are exempt from the L2 tx fee.
                if !transaction.is_deposit() {
                    let mut sender_account = self
                        .db_mut()
                        .database
                        .basic(sender)
                        .map_err(|_| BlockExecutionError::ProviderError)?
                        .ok_or(BlockExecutionError::Validation(
                            BlockValidationError::SenderRecoveryError,
                        ))?;
                    if sender_account.balance.cmp(&l1_cost) == std::cmp::Ordering::Less {
                        return Err(BlockExecutionError::InsufficientFundsForL1Cost {
                            have: sender_account.balance.to::<u64>(),
                            want: l1_cost.to::<u64>(),
                        })
                    }

                    // Safely take l1_cost from sender (the rest will be deducted by the
                    // internal EVM execution and included in result.gas_used())
                    // How to handle calls with `disable_balance_check` flag set?
                    sender_account.balance -= U256::from(l1_cost);
                }
            }

            // Execute transaction.
            let ResultAndState { result, state } = match self.transact(transaction, sender) {
                Ok(res) => res,
                Err(err) => {
                    // If the Deposited transaction failed, the deposit must still be included. In
                    // this case, we need to increment the sender nonce and
                    // disregard the state changes. The transaction is also recorded
                    // as using all gas unless it is a system transaction.
                    if transaction.is_deposit() {
                        fail_deposit_tx!(
                            self.db_mut(),
                            sender,
                            block.number,
                            transaction,
                            &mut receipts,
                            &mut cumulative_gas_used,
                            is_regolith,
                            BlockExecutionError::ProviderError
                        );
                        let mut sender_account = self
                            .db_mut()
                            .database
                            .basic(sender)
                            .map_err(|_| BlockExecutionError::ProviderError)?
                            .ok_or(BlockExecutionError::Validation(
                                BlockValidationError::SenderRecoveryError,
                            ))?;
                        let deposit_nonce = sender_account.nonce;
                        sender_account.nonce += 1;
                        self.db_mut().insert_account(sender, sender_account);

                        if is_regolith || transaction.is_system_transaction() {
                            cumulative_gas_used += transaction.gas_limit();
                        }

                        receipts.push(Receipt {
                            tx_type: transaction.tx_type(),
                            success: false,
                            cumulative_gas_used,
                            logs: vec![],
                            // Deposit nonces are only recorded after Regolith
                            deposit_nonce: is_regolith.then_some(deposit_nonce),
                        });

                        // Reset all revm configuration flags for the next iteration.
                        self.evm.env.cfg.disable_base_fee = false;
                        self.evm.env.cfg.disable_block_gas_limit = false;
                        self.evm.env.cfg.disable_balance_check = false;
                        self.evm.env.cfg.disable_gas_refund = false;
                        continue
                    }
                    return Err(err)
                }
            };

            trace!(
                target: "evm",
                ?transaction, ?result, ?state,
                "Executed transaction"
            );
            self.stats.execution_duration += time.elapsed();
            let time = Instant::now();

            // commit changes
            self.db_mut().commit(state);

            self.stats.apply_state_duration += time.elapsed();

            if self.chain_spec.optimism {
                // Before Regolith, system transactions were a special type of deposit transaction
                // that contributed no gas usage to the block. Regular deposits reported their gas
                // usage as the gas limit of their transaction. After Regolith, system transactions
                // are deprecated and all deposit transactions report the gas used during execution
                // regardless of whether or not the transaction reverts.
                if is_regolith &&
                    transaction.is_deposit() &&
                    matches!(result, ExecutionResult::Halt { .. })
                {
                    // Manually bump the nonce if the transaction was a contract creation.
                    if transaction.to().is_none() {
                        let mut sender_account = self
                            .db_mut()
                            .basic(sender)
                            .map_err(|_| BlockExecutionError::ProviderError)?
                            .ok_or(BlockExecutionError::Validation(
                                BlockValidationError::SenderRecoveryError,
                            ))?;
                        sender_account.nonce += 1;
                        self.db_mut().insert_account(sender, sender_account);
                    }

                    cumulative_gas_used += transaction.gas_limit();
                } else if is_regolith || !transaction.is_deposit() {
                    cumulative_gas_used += result.gas_used();
                } else if transaction.is_deposit() &&
                    (!result.is_success() || !transaction.is_system_transaction())
                {
                    cumulative_gas_used += transaction.gas_limit();
                }

                // Pay out fees to Optimism vaults if the transaction is not a deposit. Deposits
                // are exempt from vault fees.
                if !transaction.is_deposit() {
                    let db = self.db_mut();
                    // Route the l1 cost and base fee to the appropriate optimism vaults
                    if let Some(l1_cost) = l1_cost {
                        db.basic(*super::L1_FEE_RECIPIENT)
                            .map_err(|_| BlockExecutionError::ProviderError)?
                            .ok_or(BlockExecutionError::Validation(
                                BlockValidationError::SenderRecoveryError,
                            ))?
                            .balance += l1_cost;
                    }
                    db.basic(*super::BASE_FEE_RECIPIENT)
                        .map_err(|_| BlockExecutionError::ProviderError)?
                        .ok_or(BlockExecutionError::Validation(
                            BlockValidationError::SenderRecoveryError,
                        ))?
                        .balance += U256::from(
                        block
                            .base_fee_per_gas
                            .unwrap_or_default()
                            .saturating_mul(result.gas_used()),
                    );
                }
            } else {
                cumulative_gas_used += result.gas_used();
            }

            let sender_nonce = self
                .db_mut()
                .database
                .basic(sender)
                .map_err(|_| BlockExecutionError::ProviderError)?
                .ok_or(BlockExecutionError::Validation(BlockValidationError::SenderRecoveryError))?
                .nonce;

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Receipt {
                tx_type: transaction.tx_type(),
                // Success flag was added in `EIP-658: Embedding transaction status code in
                // receipts`.
                success: result.is_success(),
                cumulative_gas_used,
                logs: result.logs().into_iter().map(into_reth_log).collect(),
                // Deposit nonce is only recorded after Regolith for deposit transactions.
                deposit_nonce: (is_regolith && transaction.is_deposit()).then_some(sender_nonce),
            });

            // Reset all revm configuration flags for the next iteration.
            if transaction.is_deposit() {
                self.evm.env.cfg.disable_base_fee = false;
                self.evm.env.cfg.disable_block_gas_limit = false;
                self.evm.env.cfg.disable_balance_check = false;
                self.evm.env.cfg.disable_gas_refund = false;
            }
        }

        Ok((receipts, cumulative_gas_used))
    }
}

/// If the Deposited transaction failed, the deposit must still be included. In this case, we need
/// to increment the sender nonce and disregard the state changes. The transaction is also recorded
/// as using all gas unless it is a system transaction.
#[macro_export]
macro_rules! fail_deposit_tx {
    (
        $db:expr,
        $sender:ident,
        $block_number:expr,
        $transaction:ident,
        $receipts:expr,
        $cumulative_gas_used:expr,
        $is_regolith:ident,
        $error:expr
    ) => {
        let mut sender_account = $db.basic($sender).ok().flatten().ok_or($error)?;
        let old_nonce = sender_account.nonce;
        sender_account.nonce += 1;

        $db.insert_account($sender, sender_account);

        if $is_regolith || !$transaction.is_system_transaction() {
            *$cumulative_gas_used += $transaction.gas_limit();
        }

        $receipts.push(Receipt {
            tx_type: $transaction.tx_type(),
            success: false,
            cumulative_gas_used: *$cumulative_gas_used,
            logs: vec![],
            // Deposit nonces are only recorded after Regolith
            deposit_nonce: $is_regolith.then_some(old_nonce),
        });
    };
}

pub use fail_deposit_tx;
