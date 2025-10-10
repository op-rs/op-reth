use external_proofs::OpProofsExEx;
use op_reth::node::OpNode;

fn main() -> eyre::Result<()> {
    op_reth::cli::Cli::parse_args().run(async move |builder, _| {
        let handle = builder
            .node(OpNode::default())
            .install_exex("proof-helper", async move |ctx| {
                let proof_helper = OpProofsExEx::new(ctx);
                Ok(proof_helper.run())
            })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}
