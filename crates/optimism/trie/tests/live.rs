//! End-to-end test of the live trie collector.

#[cfg(test)]
mod tests {
    use alloy_consensus::{constants::ETH_TO_WEI, BlockHeader, Header, TxEip2930};
    use alloy_genesis::{Genesis, GenesisAccount};
    use alloy_primitives::{Address, TxKind, B256, U256};
    use reth_chainspec::{
        ChainSpec, ChainSpecBuilder, EthereumHardfork, MAINNET, MIN_TRANSACTION_GAS,
    };
    use reth_db::Database;
    use reth_db_common::init::init_genesis;
    use reth_ethereum_primitives::{Block, BlockBody, Transaction};
    use reth_evm::{execute::Executor, ConfigureEvm};
    use reth_evm_ethereum::EthEvmConfig;
    use reth_node_api::NodeTypesWithDB;
    use reth_optimism_trie::{
        backfill::BackfillJob, in_memory::InMemoryProofsStorage, live::LiveTrieCollector,
    };
    use reth_primitives_traits::{
        crypto::secp256k1::public_key_to_address, Block as _, RecoveredBlock,
    };
    use reth_provider::{
        providers::{BlockchainProvider, ProviderNodeTypes},
        test_utils::create_test_provider_factory_with_chain_spec,
        HashedPostStateProvider, LatestStateProviderRef, ProviderFactory, StateRootProvider,
    };
    use reth_revm::database::StateProviderDatabase;
    use reth_testing_utils::generators::sign_tx_with_key_pair;
    use secp256k1::{rand::thread_rng, Keypair, Secp256k1};
    use std::sync::Arc;

    /// Helper to create a chain spec with a genesis account funded
    fn chain_spec_with_address(address: Address) -> Arc<ChainSpec> {
        Arc::new(
            ChainSpecBuilder::default()
                .chain(MAINNET.chain)
                .genesis(Genesis {
                    alloc: [(
                        address,
                        GenesisAccount {
                            balance: U256::from(10 * ETH_TO_WEI),
                            ..Default::default()
                        },
                    )]
                    .into(),
                    ..MAINNET.genesis.clone()
                })
                .paris_activated()
                .build(),
        )
    }

    async fn create_test_blockchain_and_block() -> (
        Arc<ChainSpec>,
        ProviderFactory<impl NodeTypesWithDB + ProviderNodeTypes>,
        RecoveredBlock<Block>,
    ) {
        // Create a keypair for signing transactions
        let secp = Secp256k1::new();
        let key_pair = Keypair::new(&secp, &mut thread_rng());
        let sender = public_key_to_address(key_pair.public_key());

        // Create chain spec with the sender address funded in genesis
        let chain_spec = chain_spec_with_address(sender);

        // Create test database and provider factory
        let provider_factory = create_test_provider_factory_with_chain_spec(chain_spec.clone());

        // Insert genesis state into the database
        let genesis_hash = init_genesis(&provider_factory).unwrap();

        // Create a block with a transaction that transfers ETH to a new address
        let recipient = Address::repeat_byte(0x42);
        let mut block = Block {
            header: Header {
                parent_hash: genesis_hash,
                receipts_root: alloy_primitives::b256!(
                    "0xd3a6acf9a244d78b33831df95d472c4128ea85bf079a1d41e32ed0b7d2244c9e"
                ),
                difficulty: chain_spec.fork(EthereumHardfork::Paris).ttd().expect("Paris TTD"),
                number: 1,
                gas_limit: MIN_TRANSACTION_GAS,
                gas_used: MIN_TRANSACTION_GAS,
                state_root: B256::ZERO, // Will be calculated by executor
                ..Default::default()
            },
            body: BlockBody {
                transactions: vec![sign_tx_with_key_pair(
                    key_pair,
                    Transaction::Eip2930(TxEip2930 {
                        chain_id: chain_spec.chain.id(),
                        nonce: 0,
                        gas_limit: MIN_TRANSACTION_GAS,
                        gas_price: 1_500_000_000,
                        to: TxKind::Call(recipient),
                        value: U256::from(1), // Transfer 1 ETH
                        ..Default::default()
                    }),
                )],
                ..Default::default()
            },
        }
        .try_into_recovered()
        .unwrap();

        let state_provider = provider_factory.provider().unwrap();

        let db = StateProviderDatabase::new(LatestStateProviderRef::new(&state_provider));
        let evm_config = EthEvmConfig::ethereum(chain_spec.clone());
        let block_executor = evm_config.batch_executor(db);

        let execution_result = block_executor.execute(&block.clone()).unwrap().clone();

        let hashed_state =
            LatestStateProviderRef::new(&state_provider).hashed_post_state(&execution_result.state);
        let state_root =
            LatestStateProviderRef::new(&state_provider).state_root(hashed_state.clone()).unwrap();

        block.header_mut().state_root = state_root;
        (chain_spec, provider_factory, block)
    }

    /// End-to-end test of a single live collector iteration.
    /// (1) Creates a chain with some state
    /// (2) Stores the genesis state into storage
    /// (3) Executes a block and calculates the state root using the stored state
    #[tokio::test]
    async fn test_execute_and_store_block_updates() {
        let storage = Arc::new(InMemoryProofsStorage::new());

        let (chain_spec, provider_factory, block) = create_test_blockchain_and_block().await;

        let genesis_hash = block.parent_hash();

        {
            let provider = provider_factory.db_ref();
            let tx = provider.tx().unwrap();
            let backfill_job = BackfillJob::new(storage.clone(), &tx);
            backfill_job.run(0, genesis_hash).await.unwrap();
        }

        let blockchain_db = BlockchainProvider::new(provider_factory.clone()).unwrap();

        let evm_config = EthEvmConfig::ethereum(chain_spec);

        let live_trie_collector =
            LiveTrieCollector::new(evm_config, blockchain_db, storage.clone());
        live_trie_collector.execute_and_store_block_updates(&block).await.unwrap();
    }
}
