// ============================================================
// misaka wallet — Wallet operations
// ============================================================

use super::{parse_flag, has_flag, default_home};
use std::fs;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        print_help();
        return Ok(());
    }

    match args[0].as_str() {
        "create" => cmd_create(args),
        "balance" => cmd_balance(args),
        "scan" => cmd_scan(args),
        "list-enotes" => cmd_list_enotes(args),
        "send" => cmd_send(args),
        "export-view" => cmd_export_view(args),
        "help" | "--help" => { print_help(); Ok(()) }
        other => Err(format!("Unknown wallet subcommand: {}. Run 'misaka wallet help'.", other)),
    }
}

fn print_help() {
    println!("misaka wallet — Wallet operations");
    println!();
    println!("SUBCOMMANDS:");
    println!("  create       Create a new wallet");
    println!("  balance      Show wallet balance");
    println!("  scan         Scan chain for owned outputs");
    println!("  list-enotes  List wallet-owned enotes");
    println!("  send         Build and submit a transaction");
    println!("  export-view  Export view-only keys (safe, no spend key)");
    println!();
    println!("FLAGS:");
    println!("  --home <path>     Data directory (default: ~/.misaka)");
    println!("  --wallet <name>   Wallet name (default: default)");
    println!("  --json            Output as JSON");
}

fn cmd_create(args: &[String]) -> Result<(), String> {
    let home = parse_flag(args, "--home").unwrap_or_else(default_home);
    let name = parse_flag(args, "--wallet").unwrap_or_else(|| "default".into());
    let force = has_flag(args, "--force");

    let wallet_dir = PathBuf::from(&home).join("wallet");
    fs::create_dir_all(&wallet_dir)
        .map_err(|e| format!("Failed to create wallet dir: {}", e))?;

    let wallet_path = wallet_dir.join(format!("{}.wallet", name));
    if wallet_path.exists() && !force {
        return Err(format!("Wallet already exists: {}. Use --force to overwrite.", wallet_path.display()));
    }

    // Generate wallet
    let wallet = misaka_crypto::keys::JamtisWallet::generate()
        .map_err(|e| format!("Wallet generation failed: {}", e))?;

    let addr = wallet.receive_address();
    let fingerprint = hex::encode(wallet.fingerprint);

    // Save wallet metadata (public info only in the metadata file)
    let meta = format!(
        "name = \"{}\"\nfingerprint = \"{}\"\nspend_pk_hash = \"{}\"\n",
        name, fingerprint, hex::encode(wallet.k1),
    );
    fs::write(&wallet_path, &meta)
        .map_err(|e| format!("Failed to write wallet: {}", e))?;

    println!("Wallet created: {}", wallet_path.display());
    println!("  Name:        {}", name);
    println!("  Fingerprint: {}", fingerprint);
    println!("  Address K1:  {}", hex::encode(wallet.k1));
    println!();
    println!("Next steps:");
    println!("  misaka wallet scan --wallet {}", name);
    println!("  misaka wallet balance --wallet {}", name);

    Ok(())
}

fn cmd_balance(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");

    // In full implementation: load wallet store, compute balance
    if json {
        println!(r#"{{"total":0,"spendable":0,"spent":0}}"#);
    } else {
        println!("Wallet Balance:");
        println!("  Total:     0");
        println!("  Spendable: 0");
        println!("  Spent:     0");
        println!();
        println!("(Run 'misaka wallet scan' first to detect outputs)");
    }

    Ok(())
}

fn cmd_scan(args: &[String]) -> Result<(), String> {
    let from = parse_flag(args, "--from").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let to = parse_flag(args, "--to").and_then(|s| s.parse::<u64>().ok());

    println!("Scanning chain for wallet outputs...");
    println!("  From height: {}", from);
    if let Some(t) = to { println!("  To height: {}", t); }
    println!();
    println!("Wallet scan requires a running node with chain data.");
    println!("Use 'misaka node start' first, then scan.");

    Ok(())
}

fn cmd_list_enotes(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");

    if json {
        println!(r#"{{"enotes":[]}}"#);
    } else {
        println!("Wallet Enotes: (none)");
        println!();
        println!("Run 'misaka wallet scan' to detect owned outputs.");
    }

    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    let to = parse_flag(args, "--to");
    let amount = parse_flag(args, "--amount");

    if to.is_none() || amount.is_none() {
        return Err("Usage: misaka wallet send --to <address> --amount <u64>".into());
    }

    let to_addr = to.unwrap();
    let amount_val = amount.unwrap();

    println!("Transaction submission:");
    println!("  To:     {}", to_addr);
    println!("  Amount: {}", amount_val);
    println!();
    println!("Full send pipeline not yet wired. Use testnet for end-to-end testing.");

    Ok(())
}

fn cmd_export_view(args: &[String]) -> Result<(), String> {
    println!("Export view-only wallet keys.");
    println!("This exports ONLY view keys (safe for scanning, cannot spend).");
    println!();
    println!("View-only export not yet wired to file I/O.");
    println!("The JamtisWallet::view_only_export() API is available in misaka-crypto.");

    Ok(())
}
