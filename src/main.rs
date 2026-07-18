mod config;
mod control;
mod dns;
mod docker;
mod domain;
mod enforcement;
mod history;
mod host;
pub use egressy::isolation;
mod natpmp;
mod notifications;
mod probe;
mod profile_manager;
mod profiles;
mod recovery;
mod runtime;
mod state;
mod telemetry;
mod vpn_server;
mod web;
mod wireguard;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::Config;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(
        short,
        long,
        env = "EGRESSY_CONFIG",
        default_value = "/etc/egressy/config.yaml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the VPN gateway, Docker observer, DNS forwarder, and dashboard.
    Run,
    /// Validate configuration without changing networking.
    Check,
    /// Render the idempotent script that installs host policy routing.
    RenderHostSetup,
    /// Render the nftables rules installed inside the gateway container.
    RenderGatewayFirewall,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config =
        Config::load(&cli.config).with_context(|| format!("loading {}", cli.config.display()))?;
    config.validate()?;
    let telemetry = telemetry::build::<tracing_subscriber::Registry>(&config.otel)?;
    let telemetry_guard = if let Some(telemetry) = telemetry {
        tracing_subscriber::registry()
            .with(telemetry.trace)
            .with(telemetry.logs)
            .with(tracing_subscriber::fmt::layer())
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "egressy=info".into()))
            .init();
        Some(telemetry.guard)
    } else {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "egressy=info".into()))
            .init();
        None
    };

    match cli.command {
        Command::Run => runtime::run(config, telemetry_guard).await,
        Command::Check => {
            println!("configuration is valid");
            Ok(())
        }
        Command::RenderHostSetup => {
            print!("{}", host::render_host_setup(&config));
            Ok(())
        }
        Command::RenderGatewayFirewall => {
            print!("{}", host::render_gateway_firewall(&config, &[], &[]));
            Ok(())
        }
    }
}
