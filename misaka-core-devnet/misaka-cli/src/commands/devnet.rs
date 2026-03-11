// ============================================================
// misaka devnet — Devnet utilities
// ============================================================

use super::{parse_flag, has_flag};
use misaka_node::genesis::{GenesisConfig, GenesisAllocation, genesis_info};

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "faucet" => cmd_faucet(args),
        "genesis-info" => cmd_genesis_info(args),
        "help" | "--help" => { print_help(); Ok(()) }
        other => Err(format!("Unknown devnet subcommand: {}", other)),
    }
}

fn print_help() {
    println!("misaka devnet — Devnet utilities");
    println!();
    println!("SUBCOMMANDS:");
    println!("  faucet        Request devnet funds");
    println!("  genesis-info  Show genesis configuration metadata");
    println!();
    println!("FLAGS:");
    println!("  --address <addr>  Recipient address for faucet");
    println!("  --amount <u64>    Faucet amount (default: 10000)");
    println!("  --json            Output as JSON");
}

fn cmd_faucet(args: &[String]) -> Result<(), String> {
    let address = parse_flag(args, "--address");
    if address.is_none() {
        return Err("Usage: misaka devnet faucet --address <hex_address>".into());
    }
    let addr = address.unwrap();
    let amount = parse_flag(args, "--amount")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10_000);

    println!("Faucet request:");
    println!("  Address: {}", addr);
    println!("  Amount:  {}", amount);
    println!();
    println!("Faucet service not yet running. For devnet, use genesis allocations:");
    println!("  Add allocations to genesis config before node init.");

    Ok(())
}

fn cmd_genesis_info(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");

    // Show default devnet genesis config metadata
    let config = default_devnet_genesis();
    let info = genesis_info(&config);

    if json {
        let j = serde_json::to_string_pretty(&info)
            .map_err(|e| format!("JSON error: {}", e))?;
        println!("{}", j);
    } else {
        println!("Genesis Info:");
        println!("  Chain ID:     {}", info.chain_id);
        println!("  Genesis Time: {}", info.genesis_time);
        println!("  Genesis Hash: {}", info.genesis_hash);
        println!("  Allocations:  {}", info.allocation_count);
        println!("  Total Supply: {}", info.total_supply);
    }

    Ok(())
}

/// Default devnet genesis config for demonstration.
fn default_devnet_genesis() -> GenesisConfig {
    GenesisConfig {
        chain_id: "misaka-devnet-1".into(),
        genesis_time: 1700000000,
        allocations: vec![
            GenesisAllocation {
                address: [0x01; 32],
                amount: 10_000_000,
                asset_id: None,
                memo: Some("faucet".into()),
            },
            GenesisAllocation {
                address: [0x02; 32],
                amount: 1_000_000,
                asset_id: None,
                memo: Some("validator-fund".into()),
            },
            GenesisAllocation {
                address: [0x03; 32],
                amount: 1_000_000,
                asset_id: None,
                memo: Some("dev".into()),
            },
        ],
        initial_height: 0,
    }
}
