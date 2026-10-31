//! clap CLI for `lodeline-proxy`. No secret is ever accepted as an argument.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "lodeline-proxy",
    version,
    about = "Lodeline Proxy: standalone MCP relay with audit"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the proxy. `--config` is required: there is no default path, no
    /// auto-discovery and no environment override, so nothing starts by accident.
    Run {
        /// Path to proxy.yaml.
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate the config and exit (0 valid, 2 invalid).
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Read the local status file; opens no listener.
    Health {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print the version.
    Version,
    /// Downstream client token operations.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCommand {
    /// Generate a 256-bit bearer token. Prints it ONCE to stdout, plus its
    /// SHA-256 verifier, which is what the operator submits. Nothing is stored.
    New {
        #[arg(long)]
        config: PathBuf,
        /// Principal the token is for (id pattern).
        #[arg(long)]
        principal: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn run_requires_config() {
        assert!(Cli::try_parse_from(["lodeline-proxy", "run"]).is_err());
        assert!(Cli::try_parse_from(["lodeline-proxy", "run", "--config", "x"]).is_ok());
    }

    #[test]
    fn no_secret_arguments() {
        assert!(Cli::try_parse_from([
            "lodeline-proxy",
            "token",
            "new",
            "--config",
            "c",
            "--principal",
            "p",
            "--token",
            "x"
        ])
        .is_err());
    }
}
