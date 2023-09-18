//! Optimism's [PayloadBuilder] implementation.

use super::*;
use reth_primitives::{Block, Hardfork, Header, Receipt, U256};
use reth_revm::optimism;
use revm::{
    primitives::{ExecutionResult, ResultAndState},
    State,
};
// use revm_interpreter::primitives::{Database, DatabaseRef, WrapDatabaseRef};

/// Constructs an Ethereum transaction payload from the transactions sent through the
/// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
/// the payload attributes, the transaction pool will be ignored and the only transactions
/// included in the payload will be those sent through the attributes.
///
/// Given build arguments including an Ethereum client, transaction pool,
/// and configuration, this function creates a transaction payload. Returns
/// a result indicating success with the payload or an error in case of failure.
#[inline]
pub(crate) fn optimism_payload_builder<Pool, Client>(
    args: BuildArguments<Pool, Client>,
) -> Result<BuildOutcome, PayloadBuilderError>
where
    Client: StateProviderFactory,
    Pool: TransactionPool,
{
    let BuildArguments { client, pool, mut cached_reads, config, cancel, best_payload } = args;

    let extra_data = config.extra_data();
    let state_provider = client.state_by_block_hash(config.parent_block.hash)?;
    let state = StateProviderDatabase::new(&state_provider);
    let mut db =
        State::builder().with_database_ref(cached_reads.as_db(&state)).with_bundle_update().build();

    let PayloadConfig {
        initialized_block_env,
        initialized_cfg,
        parent_block,
        attributes,
        chain_spec,
        ..
    } = config;

    debug!(parent_hash=?parent_block.hash, parent_number=parent_block.number, "building new payload");
    let mut cumulative_gas_used = 0;
    let mut sum_blob_gas_used = 0;
    let block_gas_limit: u64 = attributes
        .gas_limit
        .unwrap_or(initialized_block_env.gas_limit.try_into().unwrap_or(u64::MAX));
    let base_fee = initialized_block_env.basefee.to::<u64>();

    let mut executed_txs = Vec::new();
    let mut best_txs = pool.best_transactions_with_base_fee(base_fee);

    let mut total_fees = U256::ZERO;

    let block_number = initialized_block_env.number.to::<u64>();

    let mut receipts = Vec::new();

    let is_regolith =
        chain_spec.is_fork_active_at_timestamp(Hardfork::Regolith, attributes.timestamp);

    // Parse the L1 block info from the first transaction in the payload attributes. This
    // transaction should always be the L1 info tx. We skip the first 4 bytes of the calldata
    // because the first 4 bytes are the function selector.
    let l1_block_info = (!attributes.transactions.is_empty())
        .then(|| optimism::L1BlockInfo::try_from(&attributes.transactions[0].input()[4..]))
        .transpose()
        .map_err(|_| PayloadBuilderError::L1BlockInfoParseFailed)?;

    // Transactions sent via the payload attributes are force included at the top of the block, in
    // the order that they were sent in.
    for sequencer_tx in attributes.transactions {
        // Check if the job was cancelled, if so we can exit early.
        if cancel.is_cancelled() {
            return Ok(BuildOutcome::Cancelled)
        }

        // Convert the transaction to a [TransactionSignedEcRecovered]. This is
        // purely for the purposes of utilizing the [tx_env_with_recovered] function.
        // Deposit transactions do not have signatures, so if the tx is a deposit, this
        // will just pull in its `from` address.
        let sequencer_tx = sequencer_tx
            .clone()
            .try_into_ecrecovered()
            .map_err(|_| PayloadBuilderError::TransactionEcRecoverFailed)?;

        // Compute the L1 cost of the transaction. This is the amount of ETH that it will cost to
        // post the entire encoded typed transaction to L1.
        let mut encoded = BytesMut::default();
        sequencer_tx.encode_enveloped(&mut encoded);
        let l1_cost = l1_block_info.as_ref().map(|l1_block_info| {
            l1_block_info.calculate_tx_l1_cost(
                Arc::clone(&chain_spec),
                attributes.timestamp,
                &encoded.freeze().into(),
                sequencer_tx.is_deposit(),
            )
        });

        let mut cfg = initialized_cfg.clone();
        let mut tx_env = tx_env_with_recovered(&sequencer_tx);

        let sender = db
            .basic(sequencer_tx.signer())?
            .ok_or(PayloadBuilderError::AccountLoadFailed(sequencer_tx.signer()))?;
        let mut sender_new = sender.clone();

        // Before regolith, deposit transaction gas accounting was as follows:
        // - System tx: 0 gas used
        // - Regular Deposit tx: gas used = gas limit
        //
        // After regolith, system transactions are deprecated and deposit transactions report the
        // gas used during execution. All deposit transactions execute the gas refund for
        // accounting (it is a noop because of the gas price), but still skip coinbase payments.
        //
        // Deposit transactions only report this gas - their gas is prepaid on L1 and
        // the gas price is always 0. Deposit txs should not be subject to any regular
        // balance checks, base fee checks, or block gas limit checks.
        if sequencer_tx.is_deposit() {
            cfg.disable_base_fee = true;
            cfg.disable_balance_check = true;
            cfg.disable_block_gas_limit = true;

            if is_regolith {
                tx_env.nonce = Some(sender.nonce);
            } else {
                cfg.disable_gas_refund = true;
            }

            // Increase the sender's balance in the database if the deposit transaction mints eth.
            if let Some(m) = sequencer_tx.mint() {
                sender_new.balance += U256::from(m);
                db.increment_balances(vec![(sequencer_tx.signer(), m)])?;
            }
        } else if let Some(l1_cost) = l1_cost {
            // Decrement the sender's balance by the L1 cost of the transaction prior to execution.
            sender_new.balance -= l1_cost;
            db.insert_account(sequencer_tx.signer(), sender_new);

            // Send the l1 cost to the sequencer signer.
            let mut sequencer_signer = db
                .basic(sequencer_tx.signer())?
                .ok_or(PayloadBuilderError::AccountLoadFailed(sequencer_tx.signer()))?;
            sequencer_signer.balance += l1_cost;
            db.insert_account(sequencer_tx.signer(), sequencer_signer);
        }

        // Configure the environment for the block.
        let env = Env { cfg, block: initialized_block_env.clone(), tx: tx_env };

        let mut evm = revm::EVM::with_env(env);
        evm.database(&mut db);

        let ResultAndState { result, state } = match evm.transact() {
            Ok(res) => res,
            Err(err) => {
                if sequencer_tx.is_deposit() {
                    // Manually bump the nonce and include a receipt for the deposit transaction.
                    let tx_signer = sequencer_tx.signer();
                    fail_deposit_tx!(
                        db,
                        tx_signer,
                        block.number,
                        sequencer_tx,
                        &mut receipts,
                        &mut cumulative_gas_used,
                        is_regolith,
                        PayloadBuilderError::AccountLoadFailed(tx_signer)
                    );
                    executed_txs.push(sequencer_tx.into_signed());
                    continue
                }

                match err {
                    EVMError::Transaction(err) => {
                        if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                            // if the nonce is too low, we can skip this transaction
                            trace!(?err, ?sequencer_tx, "skipping nonce too low transaction");
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            trace!(
                                ?err,
                                ?sequencer_tx,
                                "skipping invalid transaction and its descendants"
                            );
                        }
                        continue
                    }
                    err => {
                        // this is an error that we should treat as fatal for this attempt
                        return Err(PayloadBuilderError::EvmExecutionError(err))
                    }
                }
            }
        };

        // commit changes
        db.commit(state);

        if chain_spec.optimism {
            // Before Regolith, system transactions were a special type of deposit transaction
            // that contributed no gas usage to the block. Regular deposits reported their gas
            // usage as the gas limit of their transaction. After Regolith, system transactions
            // are deprecated and all deposit transactions report the gas used during execution
            // regardless of whether or not the transaction reverts.
            if is_regolith &&
                sequencer_tx.is_deposit() &&
                matches!(result, ExecutionResult::Halt { .. })
            {
                // Manually bump the nonce if the transaction was a contract creation.
                if sequencer_tx.to().is_none() {
                    let mut sender_account = db
                        .basic(sequencer_tx.signer())?
                        .ok_or(PayloadBuilderError::AccountLoadFailed(sequencer_tx.signer()))?;
                    sender_account.nonce += 1;
                    db.insert_account(sequencer_tx.signer(), sender_account);
                }

                cumulative_gas_used += sequencer_tx.gas_limit();
            } else if is_regolith || !sequencer_tx.is_deposit() {
                cumulative_gas_used += result.gas_used();
            } else if sequencer_tx.is_deposit() &&
                (!result.is_success() || !sequencer_tx.is_system_transaction())
            {
                cumulative_gas_used += sequencer_tx.gas_limit();
            }

            // If the transaction is not a deposit, we route the l1 cost and base fee to the
            // appropriate optimism vaults.
            if !sequencer_tx.is_deposit() {
                // Route the l1 cost and base fee to the appropriate optimism vaults
                if let Some(l1_cost) = l1_cost {
                    let ucost: u128 = l1_cost.try_into().unwrap_or(u128::MAX);
                    db.increment_balances(vec![(*optimism::L1_FEE_RECIPIENT, ucost)])?;
                }
                let base_cost = base_fee.saturating_mul(result.gas_used()) as u128;
                db.increment_balances(vec![(*optimism::BASE_FEE_RECIPIENT, base_cost)])?;
            }
        } else {
            cumulative_gas_used += result.gas_used();
        }

        // Push transaction changeset and calculate header bloom filter for receipt.
        receipts.push(Some(Receipt {
            tx_type: sequencer_tx.tx_type(),
            success: result.is_success(),
            cumulative_gas_used,
            logs: result.logs().into_iter().map(into_reth_log).collect(),
            deposit_nonce: (is_regolith && sequencer_tx.is_deposit()).then_some(sender.nonce),
        }));

        // append transaction to the list of executed transactions
        executed_txs.push(sequencer_tx.into_signed());
    }

    if !attributes.no_tx_pool {
        while let Some(pool_tx) = best_txs.next() {
            // ensure we still have capacity for this transaction
            if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
                // we can't fit this transaction into the block, so we need to mark it as invalid
                // which also removes all dependent transaction from the iterator before we can
                // continue
                best_txs.mark_invalid(&pool_tx);
                continue
            }

            // check if the job was cancelled, if so we can exit early
            if cancel.is_cancelled() {
                return Ok(BuildOutcome::Cancelled)
            }

            // convert tx to a signed transaction
            let tx = pool_tx.to_recovered_transaction();

            // There's only limited amount of blob space available per block, so we need to check if
            // the EIP-4844 can still fit in the block
            if let Some(blob_tx) = tx.transaction.as_eip4844() {
                let tx_blob_gas = blob_tx.blob_gas();
                if sum_blob_gas_used + tx_blob_gas > MAX_DATA_GAS_PER_BLOCK {
                    // we can't fit this _blob_ transaction into the block, so we mark it as
                    // invalid, which removes its dependent transactions from
                    // the iterator. This is similar to the gas limit condition
                    // for regular transactions above.
                    best_txs.mark_invalid(&pool_tx);
                    continue
                } else {
                    // add to the data gas if we're going to execute the transaction
                    sum_blob_gas_used += tx_blob_gas;

                    // if we've reached the max data gas per block, we can skip blob txs entirely
                    if sum_blob_gas_used == MAX_DATA_GAS_PER_BLOCK {
                        best_txs.skip_blobs();
                    }
                }
            }

            // Configure the environment for the block.
            let env = Env {
                cfg: initialized_cfg.clone(),
                block: initialized_block_env.clone(),
                tx: tx_env_with_recovered(&tx),
            };

            let mut evm = revm::EVM::with_env(env);
            evm.database(&mut db);

            let ResultAndState { result, state } = match evm.transact() {
                Ok(res) => res,
                Err(err) => {
                    match err {
                        EVMError::Transaction(err) => {
                            if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                                // if the nonce is too low, we can skip this transaction
                                trace!(?err, ?tx, "skipping nonce too low transaction");
                            } else {
                                // if the transaction is invalid, we can skip it and all of its
                                // descendants
                                trace!(
                                    ?err,
                                    ?tx,
                                    "skipping invalid transaction and its descendants"
                                );
                                best_txs.mark_invalid(&pool_tx);
                            }
                            continue
                        }
                        err => {
                            // this is an error that we should treat as fatal for this attempt
                            return Err(PayloadBuilderError::EvmExecutionError(err))
                        }
                    }
                }
            };

            let gas_used = result.gas_used();

            // commit changes
            db.commit(state);

            // add gas used by the transaction to cumulative gas used, before creating the receipt
            cumulative_gas_used += gas_used;

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Some(Receipt {
                tx_type: tx.tx_type(),
                success: result.is_success(),
                cumulative_gas_used,
                logs: result.logs().into_iter().map(into_reth_log).collect(),
                #[cfg(feature = "optimism")]
                deposit_nonce: None,
            }));

            // update add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            total_fees += U256::from(miner_fee) * U256::from(gas_used);

            // append transaction to the list of executed transactions
            executed_txs.push(tx.into_signed());
        }
    }

    // check if we have a better block
    if !is_better_payload(best_payload.as_deref(), total_fees) {
        // can skip building the block
        return Ok(BuildOutcome::Aborted { fees: total_fees, cached_reads })
    }

    let WithdrawalsOutcome { withdrawals_root, withdrawals } =
        commit_withdrawals(&mut db, &chain_spec, attributes.timestamp, attributes.withdrawals)?;

    // merge all transitions into bundle state.
    db.merge_transitions(BundleRetention::PlainState);

    let bundle = BundleStateWithReceipts::new(db.take_bundle(), vec![receipts], block_number);
    let receipts_root = bundle.receipts_root_slow(block_number).expect("Number is in range");
    let logs_bloom = bundle.block_logs_bloom(block_number).expect("Number is in range");

    // calculate the state root
    let state_root = state_provider.state_root(bundle)?;

    // create the block header
    let transactions_root = proofs::calculate_transaction_root(&executed_txs);

    // initialize empty blob sidecars at first. If cancun is active then this will
    let mut blob_sidecars = Vec::new();
    let mut excess_blob_gas = None;
    let mut blob_gas_used = None;

    // only determine cancun fields when active
    if chain_spec.is_cancun_activated_at_timestamp(attributes.timestamp) {
        // grab the blob sidecars from the executed txs
        blob_sidecars = pool.get_all_blobs_exact(
            executed_txs.iter().filter(|tx| tx.is_eip4844()).map(|tx| tx.hash).collect(),
        )?;

        excess_blob_gas = if chain_spec.is_cancun_activated_at_timestamp(parent_block.timestamp) {
            let parent_excess_blob_gas = parent_block.excess_blob_gas.unwrap_or_default();
            let parent_blob_gas_used = parent_block.blob_gas_used.unwrap_or_default();
            Some(calculate_excess_blob_gas(parent_excess_blob_gas, parent_blob_gas_used))
        } else {
            // for the first post-fork block, both parent.blob_gas_used and parent.excess_blob_gas
            // are evaluated as 0
            Some(calculate_excess_blob_gas(0, 0))
        };

        blob_gas_used = Some(sum_blob_gas_used);
    }

    let header = Header {
        parent_hash: parent_block.hash,
        ommers_hash: EMPTY_OMMER_ROOT,
        beneficiary: initialized_block_env.coinbase,
        state_root,
        transactions_root,
        receipts_root,
        withdrawals_root,
        logs_bloom,
        timestamp: attributes.timestamp,
        mix_hash: attributes.prev_randao,
        nonce: BEACON_NONCE,
        base_fee_per_gas: Some(base_fee),
        number: parent_block.number + 1,
        gas_limit: block_gas_limit,
        difficulty: U256::ZERO,
        gas_used: cumulative_gas_used,
        extra_data,
        parent_beacon_block_root: attributes.parent_beacon_block_root,
        blob_gas_used,
        excess_blob_gas,
    };

    // seal the block
    let block = Block { header, body: executed_txs, ommers: vec![], withdrawals };

    let sealed_block = block.seal_slow();

    let mut payload = BuiltPayload::new(attributes.id, sealed_block, total_fees);

    if !blob_sidecars.is_empty() {
        // extend the payload with the blob sidecars from the executed txs
        payload.extend_sidecars(blob_sidecars);
    }

    Ok(BuildOutcome::Better { payload, cached_reads })
}

/// Optimism's payload builder
#[derive(Clone)]
pub struct OptimismPayloadBuilder;

/// Implementation of the [PayloadBuilder] trait for [OptimismPayloadBuilder].
impl<Pool, Client> PayloadBuilder<Pool, Client> for OptimismPayloadBuilder
where
    Client: StateProviderFactory,
    Pool: TransactionPool,
{
    fn try_build(
        &self,
        args: BuildArguments<Pool, Client>,
    ) -> Result<BuildOutcome, PayloadBuilderError> {
        optimism_payload_builder(args)
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

        $receipts.push(Some(Receipt {
            tx_type: $transaction.tx_type(),
            success: false,
            cumulative_gas_used: *$cumulative_gas_used,
            logs: vec![],
            // Deposit nonces are only recorded after Regolith
            deposit_nonce: $is_regolith.then_some(old_nonce),
        }));
    };
}
