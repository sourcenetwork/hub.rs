//! hubd — SourceHub validator node.

use clap::Parser;
use tracing_subscriber::prelude::*;

mod cli;
mod testnet;

fn main() -> eyre::Result<()> {
    hub_cli::Backtracing::enable();
    hub_cli::SigsegvHandler::install();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    cli::Cli::parse().run()
}
