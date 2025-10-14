#![allow(missing_docs, rustdoc::missing_crate_level_docs)]

use clap::Parser;
use reth_exex_external_proofs::OpProofsExEx;
use reth_optimism_cli::{chainspec::OpChainSpecParser, Cli};
use reth_optimism_node::{args::RollupArgs, OpNode};
use tracing::info;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

/// The storage DB for proofs history.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum)]
enum ProofsHistoryStorage {
    /// MDBX
    Mdbx,
}

impl std::fmt::Display for ProofsHistoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx => f.write_str("mdbx"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "Proofs History")]
struct Args {
    #[command(flatten)]
    pub rollup_args: RollupArgs,

    /// If true, initialize external-proofs exex to save and serve trie nodes to provide proofs
    /// faster.
    #[arg(long = "proofs-history", value_name = "PROOFS_HISTORY")]
    pub proofs_history: bool,

    /// The storage DB for proofs history.
    #[arg(
        long = "proofs-history.storage",
        default_value_t = ProofsHistoryStorage::Mdbx,
        value_name = "PROOFS_HISTORY_STORAGE"
    )]
    pub proofs_history_storage: ProofsHistoryStorage,

    /// The path to the storage DB for proofs history.
    #[arg(long = "proofs-history.storage-path", value_name = "PROOFS_HISTORY_STORAGE_PATH")]
    pub proofs_history_storage_path: Option<String>,

    /// The window to span blocks for proofs history. Value is the number of blocks.
    /// Default is 1 month of blocks based on 2 seconds block time.
    /// 30 * 24 * 60 * 60 / 2 = `1_296_000`
    #[arg(
        long = "proofs-history.window",
        default_value_t = 1_296_000,
        value_name = "PROOFS_HISTORY_WINDOW"
    )]
    pub proofs_history_window: u64,
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
    }

    if let Err(err) = Cli::<OpChainSpecParser, Args>::parse().run(async move |builder, args| {
        info!(target: "reth::cli", "Launching node");

        let rollup_args = args.rollup_args;

        let handle = builder
            .node(OpNode::new(rollup_args))
            .install_exex_if(args.proofs_history, "proofs-history", async move |exex_context| {
                let proofs_helper = OpProofsExEx::new(exex_context);
                Ok(proofs_helper.run())
            })
            .launch_with_debug_capabilities()
            .await?;
        handle.node_exit_future.await
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
