// ============================================================
// misaka testnet — Multi-node testnet orchestration
// ============================================================

use super::{parse_flag, has_flag};
use misaka_testnet::runner::TestnetRunner;

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "start" => cmd_start(args),
        "status" => cmd_status(args),
        "produce" => cmd_produce(args),
        "help" | "--help" => { print_help(); Ok(()) }
        other => Err(format!("Unknown testnet subcommand: {}", other)),
    }
}

fn print_help() {
    println!("misaka testnet — Multi-node testnet orchestration");
    println!();
    println!("SUBCOMMANDS:");
    println!("  start     Launch in-process testnet and produce blocks");
    println!("  produce   Produce N blocks on a running testnet");
    println!("  status    Show testnet status");
    println!();
    println!("FLAGS:");
    println!("  --validators <n>  Number of validators (default: 10)");
    println!("  --observers <n>   Number of observers (default: 1)");
    println!("  --blocks <n>      Number of blocks to produce (default: 5)");
    println!("  --json            Output as JSON");
}

fn cmd_start(args: &[String]) -> Result<(), String> {
    let validators: usize = parse_flag(args, "--validators")
        .and_then(|s| s.parse().ok()).unwrap_or(10);
    let observers: usize = parse_flag(args, "--observers")
        .and_then(|s| s.parse().ok()).unwrap_or(1);
    let blocks: u64 = parse_flag(args, "--blocks")
        .and_then(|s| s.parse().ok()).unwrap_or(5);
    let json = has_flag(args, "--json");

    println!("Launching MISAKA testnet...");
    println!("  Validators: {}", validators);
    println!("  Observers:  {}", observers);
    println!();

    let mut testnet = TestnetRunner::launch(validators, observers)
        .map_err(|e| format!("Testnet launch failed: {}", e))?;

    println!("Testnet running. Producing {} blocks...", blocks);

    testnet.produce_blocks(blocks)
        .map_err(|e| format!("Block production failed: {}", e))?;

    let status = testnet.status();

    if json {
        let j = serde_json::to_string_pretty(&status)
            .map_err(|e| format!("JSON error: {}", e))?;
        println!("{}", j);
    } else {
        println!();
        println!("Testnet Status:");
        println!("  Blocks produced: {}", status.blocks_produced);
        println!("  Min height:      {}", status.min_height);
        println!("  Max height:      {}", status.max_height);
        println!("  Nodes:           {}", status.nodes.len());
        for ns in &status.nodes {
            println!("    Node {}: height={} consensus={} role={:?}",
                ns.node_id, ns.chain_height, ns.consensus_height, ns.role);
        }
    }

    println!();
    println!("Testnet completed successfully.");

    Ok(())
}

fn cmd_produce(args: &[String]) -> Result<(), String> {
    let blocks: u64 = parse_flag(args, "--blocks")
        .and_then(|s| s.parse().ok()).unwrap_or(1);
    println!("Produce {} blocks on the in-process testnet.", blocks);
    println!("(Testnet state is not persistent between CLI invocations.)");
    println!("Use 'misaka testnet start --blocks {}' for a complete run.", blocks);
    Ok(())
}

fn cmd_status(_args: &[String]) -> Result<(), String> {
    println!("Testnet Status:");
    println!("  (In-process testnet has no persistent state between CLI calls.)");
    println!("  Use 'misaka testnet start' for a complete run.");
    Ok(())
}
