use clap::{error::ErrorKind, CommandFactory, Parser};
use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::cli::{Cli, Command, TokenCommand};
use lodeline_proxy::{lifecycle, token};
use std::process::ExitCode;

/// Exit code for an invalid config (`check-config`, and any start error caused
/// by the config).
const EXIT_INVALID_CONFIG: u8 = 2;

fn usage_help_path() -> String {
    let cli = Cli::command();
    let mut path = cli.get_name().to_owned();
    let mut command = &cli;
    let mut args = std::env::args_os().skip(1).peekable();
    while command.has_subcommands() {
        // The built-in `help` takes a command path as its topic.
        args.next_if(|arg| arg == "help");
        let Some(subcommand) = args.next().and_then(|arg| command.find_subcommand(arg)) else {
            break;
        };
        path.push(' ');
        path.push_str(subcommand.get_name());
        command = subcommand;
    }
    path
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        // Missing-item diagnostics name the CLI's own options and commands.
        Err(e)
            if e.use_stderr()
                && !matches!(
                    e.kind(),
                    ErrorKind::MissingRequiredArgument
                        | ErrorKind::MissingSubcommand
                        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
                ) =>
        {
            let path = usage_help_path();
            clap::Error::raw(
                e.kind(),
                format!(
                    "{path}: invalid arguments (not echoed, they may hold a token). \
                     Run `{path} --help`"
                ),
            )
            .exit();
        }
        Err(e) => e.exit(),
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match cli.command {
        Command::Version => {
            println!("lodeline-proxy {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::CheckConfig { config } => match Bootstrap::load(&config) {
            Ok(_) => {
                println!("config ok");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("config invalid: {e}");
                ExitCode::from(EXIT_INVALID_CONFIG)
            }
        },
        Command::Health { config } => {
            let b = match Bootstrap::load(&config) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("config invalid: {e}");
                    return ExitCode::from(EXIT_INVALID_CONFIG);
                }
            };
            let h = lifecycle::health(&b.state_dir);
            match &h.status {
                Some(s) => {
                    println!("alive: {}", h.alive);
                    println!("proxy_id: {}", s.proxy_id);
                    println!("epoch_id: {}", s.epoch_id);
                    println!("run_state: {:?}", s.run_state);
                    println!("config_state: {:?}", s.config_state);
                    println!("forwarding: {}", s.forwarding);
                    println!("ingest_stopped: {}", s.ingest_stopped);
                    match s.spool {
                        Some(v) => match v.reason {
                            Some(r) => println!("spool: {:?} ({r:?})", v.state),
                            None => println!("spool: {:?}", v.state),
                        },
                        None => println!("spool: unknown"),
                    }
                    println!("updated_at: {}", s.updated_at);
                }
                None => println!("alive: {}\nstatus: unavailable", h.alive),
            }
            // OPEN: healthy = process alive and status readable. A running proxy
            // that is not forwarding (no valid config) is reported, not failed.
            if h.alive && h.status.is_some() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Command::Token {
            command: TokenCommand::New { config, principal },
        } => {
            if let Err(e) = Bootstrap::load(&config) {
                eprintln!("config invalid: {e}");
                return ExitCode::from(EXIT_INVALID_CONFIG);
            }
            if lodeline_proxy_api::Id::new(principal.clone()).is_err() {
                eprintln!("--principal does not match the id pattern");
                return ExitCode::from(EXIT_INVALID_CONFIG);
            }
            let t = match token::generate_token() {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("OS random source unavailable");
                    return ExitCode::from(1);
                }
            };
            // The token is printed exactly once and stored nowhere.
            println!("token: {t}");
            println!("verifier_sha256: {}", lodeline_proxy_api::verifier_for(&t));
            eprintln!(
                "principal={principal}: submit only the verifier; the token cannot be shown again"
            );
            ExitCode::SUCCESS
        }
        Command::Snippet {
            client,
            name,
            url,
            route,
            token_env,
        } => match lodeline_proxy::snippet::render(client, &name, &url, &route, &token_env) {
            Ok(s) => {
                print!("{}", s.entry);
                eprintln!("{}", s.note);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(EXIT_INVALID_CONFIG)
            }
        },
        Command::Run { config } => {
            let b = match Bootstrap::load(&config) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("config invalid: {e}");
                    return ExitCode::from(EXIT_INVALID_CONFIG);
                }
            };
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            match rt.block_on(lifecycle::run(&b)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("lodeline-proxy: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
