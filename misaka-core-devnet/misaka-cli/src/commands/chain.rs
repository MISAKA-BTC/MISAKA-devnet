// ============================================================
// misaka chain — Chain inspection commands
// ============================================================

use super::{parse_flag, has_flag};

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "height" => cmd_height(args),
        "tip" => cmd_tip(args),
        "block" => cmd_block(args),
        "tx" => cmd_tx(args),
        "status" => cmd_status(args),
        "help" | "--help" => { print_help(); Ok(()) }
        other => Err(format!("Unknown chain subcommand: {}", other)),
    }
}

fn print_help() {
    println!("misaka chain — Chain inspection");
    println!();
    println!("SUBCOMMANDS:");
    println!("  height   Current chain height");
    println!("  tip      Tip height and hash");
    println!("  block    Fetch block by --height <n>");
    println!("  tx       Fetch transaction by --id <hex>");
    println!("  status   Chain + node status summary");
    println!();
    println!("FLAGS:");
    println!("  --json   Output as JSON");
}

fn cmd_height(_args: &[String]) -> Result<(), String> {
    // Would query local RPC: RpcHandler::get_height()
    println!("0");
    println!("(Query local RPC for live height)");
    Ok(())
}

fn cmd_tip(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");
    if json {
        println!(r#"{{"height":0,"tip_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}"#);
    } else {
        println!("Height: 0");
        println!("Tip:    0000...0000");
    }
    Ok(())
}

fn cmd_block(args: &[String]) -> Result<(), String> {
    let height = parse_flag(args, "--height");
    if height.is_none() {
        return Err("Usage: misaka chain block --height <n>".into());
    }
    let h: u64 = height.unwrap().parse().map_err(|_| "Invalid height")?;
    println!("Block at height {}:", h);
    println!("  (Query local RPC for block data)");
    Ok(())
}

fn cmd_tx(args: &[String]) -> Result<(), String> {
    let id = parse_flag(args, "--id");
    if id.is_none() {
        return Err("Usage: misaka chain tx --id <hex>".into());
    }
    println!("Transaction {}:", id.unwrap());
    println!("  (Query local RPC for tx data)");
    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");
    if json {
        println!(r#"{{"height":0,"tip_hash":"0000...","mempool_tx_count":0,"startup_phase":"Recovered"}}"#);
    } else {
        println!("Chain Status:");
        println!("  Height:      0");
        println!("  Tip:         0000...0000");
        println!("  Mempool:     0 txs");
        println!("  Phase:       Recovered");
    }
    Ok(())
}
