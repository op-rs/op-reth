//! Node builder with proof history support.

use crate::{args::RollupArgs, OpNode};
use eyre::ErrReport;
use futures_util::FutureExt;
use reth_db::DatabaseEnv;
use reth_db_api::database_metrics::DatabaseMetrics;
use reth_node_builder::{
    FullNodeComponents, Node, NodeBuilder, NodeBuilderWithComponents, RethFullAdapter,
    WithLaunchContext,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_exex::OpProofsExEx;
use reth_optimism_rpc::{
    debug::{DebugApiExt, DebugApiOverrideServer},
    eth::proofs::{EthApiExt, EthApiOverrideServer},
};
use reth_optimism_trie::{db::MdbxProofsStorage, OpProofsStorage};
use reth_tasks::TaskExecutor;
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::info;

/// Single entry that handles:
/// - no proofs history (plain node),
/// - in-mem proofs storage,
/// - MDBX proofs storage.
pub async fn node_builder_with_proof_history(
    builder: WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, OpChainSpec>>,
    args: RollupArgs,
) -> eyre::Result<
    WithLaunchContext<
        NodeBuilderWithComponents<
            RethFullAdapter<Arc<DatabaseEnv>, OpNode>,
            <OpNode as Node<RethFullAdapter<Arc<DatabaseEnv>, OpNode>>>::ComponentsBuilder,
            <OpNode as Node<RethFullAdapter<Arc<DatabaseEnv>, OpNode>>>::AddOns,
        >,
    >,
    ErrReport,
> {
    let proofs_history_enabled = args.proofs_history;
    let proofs_history_window = args.proofs_history_window;
    let proofs_history_prune_interval = args.proofs_history_prune_interval;
    let proofs_history_verification_interval = args.proofs_history_verification_interval;

    // Start from a plain OpNode builder
    let mut node_builder = builder.node(OpNode::new(args.clone()));

    if !proofs_history_enabled {
        return Ok(node_builder)
    }

    let path = args
        .proofs_history_storage_path
        .expect("Path must be provided if not using in-memory storage");
    info!(target: "reth::cli", "Using on-disk storage for proofs history");

    let mdbx = Arc::new(
        MdbxProofsStorage::new(&path)
            .map_err(|e| eyre::eyre!("Failed to create MdbxProofsStorage: {e}"))?,
    );
    let storage: OpProofsStorage<Arc<MdbxProofsStorage>> = mdbx.clone().into();

    let storage_exec = storage.clone();

    node_builder = node_builder
        .on_node_started(move |node| {
            spawn_proofs_db_metrics(
                node.task_executor,
                mdbx,
                node.config.metrics.push_gateway_interval,
            );
            Ok(())
        })
        .install_exex("proofs-history", async move |exex_context| {
            Ok(OpProofsExEx::new(
                exex_context,
                storage_exec,
                proofs_history_window,
                proofs_history_prune_interval,
                proofs_history_verification_interval,
            )
            .run()
            .boxed())
        })
        .extend_rpc_modules(move |ctx| {
            let api_ext = EthApiExt::new(ctx.registry.eth_api().clone(), storage.clone());
            let debug_ext = DebugApiExt::new(
                ctx.node().provider().clone(),
                ctx.registry.eth_api().clone(),
                storage,
                Box::new(ctx.node().task_executor().clone()),
                ctx.node().evm_config().clone(),
            );
            ctx.modules.replace_configured(api_ext.into_rpc())?;
            ctx.modules.replace_configured(debug_ext.into_rpc())?;
            Ok(())
        });
    Ok(node_builder)
}

/// Spawns a task that periodically reports metrics for the proofs DB.
fn spawn_proofs_db_metrics(
    executor: TaskExecutor,
    storage: Arc<MdbxProofsStorage>,
    metrics_report_interval: Duration,
) {
    executor.spawn_critical("op-proofs-storage-metrics", async move {
        info!(
            target: "reth::cli",
            ?metrics_report_interval,
            "Starting op-proofs-storage metrics task"
        );

        loop {
            sleep(metrics_report_interval).await;
            storage.report_metrics();
        }
    });
}
