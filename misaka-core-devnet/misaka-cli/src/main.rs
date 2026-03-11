// ============================================================
// MISAKA CLI — Unified Command-Line Interface
// ============================================================
//
// Usage: misaka <command> <subcommand> [flags]
//
// Commands:
//   node     Node lifecycle (init, start, status, reset, config)
//   wallet   Wallet operations (create, balance, scan, list-enotes, send)
//   chain    Chain inspection (height, tip, block, tx, status)
//   devnet   Devnet utilities (faucet, genesis-info)
//   testnet  Multi-node testnet (start, stop, status)
//
// ============================================================

mod commands;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        process::exit(0);
    }

    let result = match args[1].as_str() {
        "node" => commands::node::run(&args[2..]),
        "wallet" => commands::wallet::run(&args[2..]),
        "chain" => commands::chain::run(&args[2..]),
        "devnet" => commands::devnet::run(&args[2..]),
        "testnet" => commands::testnet::run(&args[2..]),
        "help" | "--help" | "-h" => { print_help(); Ok(()) }
        "version" | "--version" | "-V" => { print_version(); Ok(()) }
        other => {
            eprintln!("Unknown command: {}", other);
            eprintln!("Run 'misaka help' for usage.");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn print_help() {
    println!("MISAKA — Post-Quantum Privacy Blockchain");
    println!();
    println!("USAGE: misaka <COMMAND> [SUBCOMMAND] [FLAGS]");
    println!();
    println!("COMMANDS:");
    println!("  node      Node lifecycle (init, start, status, reset, config)");
    println!("  wallet    Wallet operations (create, balance, scan, list-enotes, send)");
    println!("  chain     Chain inspection (height, tip, block, tx, status)");
    println!("  devnet    Devnet utilities (faucet, genesis-info)");
    println!("  testnet   Multi-node testnet orchestration");
    println!("  help      Print this help");
    println!("  version   Print version");
    println!();
    println!("QUICK START:");
    println!("  misaka node init --chain misaka-devnet-1");
    println!("  misaka node start");
    println!("  misaka wallet create");
    println!("  misaka wallet scan");
    println!("  misaka wallet balance");
    println!();
    println!("Use 'misaka <command> help' for per-command help.");
}

fn print_version() {
    println!("misaka {}", env!("CARGO_PKG_VERSION"));
}
