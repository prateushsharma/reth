//! ExternEVM — Modified Reth node with API_CALL precompile + extern/1 p2p subprotocol

mod extern_p2p;

use reth::cli::Cli;
use reth_evm_ethereum::externevm::ExternEvmFactory;
use reth_network::NetworkProtocols;
use reth_network::protocol::IntoRlpxSubProtocol;
use reth_node_builder::{
    components::ExecutorBuilder, BuilderContext, FullNodeTypes,
};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};

use reth_evm_ethereum::EthEvmConfig;
use alloy_primitives::Address;

use crate::extern_p2p::ExternEvmProtoHandler;

// ---------------------------------------------------------------------------
// Executor builder
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct ExternEvmExecutorBuilder;

impl<Node: FullNodeTypes<Types: reth_node_api::NodeTypes<ChainSpec = reth_chainspec::ChainSpec, Primitives = reth_ethereum_primitives::EthPrimitives>>> ExecutorBuilder<Node> for ExternEvmExecutorBuilder {
    type EVM = EthEvmConfig<reth_chainspec::ChainSpec, ExternEvmFactory>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<Self::EVM> {
        let chain_spec = ctx.chain_spec();
        Ok(EthEvmConfig::new_with_evm_factory(
            chain_spec,
            ExternEvmFactory::new(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Validator address from env
// ---------------------------------------------------------------------------

fn get_validator_address() -> Address {
    if let Ok(hex_str) = std::env::var("EXTERNEVM_VALIDATOR_ADDRESS") {
        let hex_str = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        if hex_str.len() == 40 {
            let mut addr = [0u8; 20];
            let mut valid = true;
            for i in 0..20 {
                match u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                    Ok(b) => addr[i] = b,
                    Err(_) => { valid = false; break; }
                }
            }
            if valid {
                return Address::new(addr);
            }
        }
        eprintln!("[ExternEVM] Invalid EXTERNEVM_VALIDATOR_ADDRESS env var, using default");
    }
    let mut addr = [0u8; 20];
    addr[0] = 0xf3; addr[1] = 0x9F; addr[2] = 0xd6; addr[3] = 0xe5;
    addr[4] = 0x1a; addr[5] = 0xad; addr[6] = 0x88; addr[7] = 0xF6;
    addr[8] = 0xF4; addr[9] = 0xce; addr[10] = 0x6a; addr[11] = 0xB8;
    addr[12] = 0x82; addr[13] = 0x72; addr[14] = 0x79; addr[15] = 0xcf;
    addr[16] = 0xfF; addr[17] = 0xb9; addr[18] = 0x22; addr[19] = 0x66;
    Address::new(addr)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let validator_addr = get_validator_address();
    eprintln!("[ExternEVM] Node validator address: {:?}", validator_addr);

    Cli::parse_args()
        .run(|builder, _| async move {
            let handle = builder
                .with_types::<EthereumNode>()
                .with_components(
                    EthereumNode::components()
                        .executor(ExternEvmExecutorBuilder),
                )
                .with_add_ons(EthereumAddOns::default())
                .launch()
                .await?;

            // Register extern/1 subprotocol after launch
            let network = handle.node.network.clone();
            network.add_rlpx_sub_protocol(
                ExternEvmProtoHandler::new(validator_addr).into_rlpx_sub_protocol()
            );
            eprintln!(
                "[ExternEVM] Registered extern/1 subprotocol for p2p value broadcasting"
            );

            handle.wait_for_node_exit().await
        })
        .unwrap();
}