// ============================================================
// misaka node — Node lifecycle commands
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
        "init" => cmd_init(args),
        "start" => cmd_start(args),
        "status" => cmd_status(args),
        "reset" => cmd_reset(args),
        "config" => cmd_config(args),
        "help" | "--help" => { print_help(); Ok(()) }
        other => Err(format!("Unknown node subcommand: {}. Run 'misaka node help'.", other)),
    }
}

fn print_help() {
    println!("misaka node — Node lifecycle");
    println!();
    println!("SUBCOMMANDS:");
    println!("  init      Initialize node data directory and config");
    println!("  start     Start the node");
    println!("  status    Show node status");
    println!("  reset     Wipe local chain state (devnet)");
    println!("  config    Print effective config");
    println!();
    println!("FLAGS:");
    println!("  --home <path>       Data directory (default: ~/.misaka)");
    println!("  --chain <chain_id>  Chain ID (default: misaka-devnet-1)");
    println!("  --validator         Generate validator key on init");
    println!("  --force             Overwrite existing config on init");
}

fn cmd_init(args: &[String]) -> Result<(), String> {
    let home = parse_flag(args, "--home").unwrap_or_else(default_home);
    let chain_id = parse_flag(args, "--chain").unwrap_or_else(|| "misaka-devnet-1".into());
    let validator = has_flag(args, "--validator");
    let force = has_flag(args, "--force");

    let home_path = PathBuf::from(&home);

    if home_path.exists() && !force {
        println!("Data directory already exists: {}", home);
        println!("Use --force to overwrite.");
        return Ok(());
    }

    // Create directory structure
    fs::create_dir_all(home_path.join("chain"))
        .map_err(|e| format!("Failed to create chain dir: {}", e))?;
    fs::create_dir_all(home_path.join("wal"))
        .map_err(|e| format!("Failed to create wal dir: {}", e))?;
    fs::create_dir_all(home_path.join("wallet"))
        .map_err(|e| format!("Failed to create wallet dir: {}", e))?;
    fs::create_dir_all(home_path.join("logs"))
        .map_err(|e| format!("Failed to create logs dir: {}", e))?;

    // Write default config
    let config = format!(
        r#"# MISAKA Node Configuration
chain_id = "{}"
rpc_port = 31000
p2p_port = 30000
validator = {}
"#,
        chain_id, validator,
    );

    fs::write(home_path.join("config.toml"), &config)
        .map_err(|e| format!("Failed to write config: {}", e))?;

    // Generate validator key if requested
    if validator {
        match misaka_crypto::falcon::falcon_keygen() {
            Ok(kp) => {
                let key_path = home_path.join("validator.key");
                // Store fingerprint (public info) as hex
                let key_info = format!(
                    "fingerprint = \"{}\"\npk_size = {}\nsk_size = {}\n",
                    hex::encode(kp.fingerprint),
                    kp.public_key.len(),
                    kp.secret_key.len(),
                );
                fs::write(&key_path, &key_info)
                    .map_err(|e| format!("Failed to write validator key: {}", e))?;
                println!("Validator key generated: {}", key_path.display());
                println!("  Fingerprint: {}", hex::encode(kp.fingerprint));
            }
            Err(e) => return Err(format!("Failed to generate validator key: {}", e)),
        }
    }

    println!("Node initialized at: {}", home);
    println!("  Chain ID: {}", chain_id);
    println!("  Config: {}", home_path.join("config.toml").display());
    println!();
    println!("Next steps:");
    println!("  misaka node start --home {}", home);
    println!("  misaka wallet create --home {}", home);

    Ok(())
}

fn cmd_start(args: &[String]) -> Result<(), String> {
    let home = parse_flag(args, "--home").unwrap_or_else(default_home);
    let home_path = PathBuf::from(&home);

    if !home_path.join("config.toml").exists() {
        return Err(format!(
            "Config not found at {}. Run 'misaka node init' first.",
            home_path.join("config.toml").display()
        ));
    }

    println!("Starting MISAKA node...");
    println!("  Home: {}", home);
    println!("  Config: {}", home_path.join("config.toml").display());
    println!();
    println!("Node runtime not yet implemented as a long-running process.");
    println!("Use 'misaka testnet start' for local multi-node testing.");

    Ok(())
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let json = has_flag(args, "--json");

    // In a full implementation, this would query the local RPC.
    // For now, show a placeholder with the expected format.
    if json {
        println!(r#"{{"height":0,"tip_hash":"0000...","startup_phase":"Recovered","mempool_tx_count":0}}"#);
    } else {
        println!("Node Status:");
        println!("  Height:        0");
        println!("  Tip Hash:      0000...");
        println!("  Phase:         Recovered");
        println!("  Mempool TXs:   0");
        println!();
        println!("(Connect to local RPC for live data)");
    }

    Ok(())
}

fn cmd_reset(args: &[String]) -> Result<(), String> {
    let home = parse_flag(args, "--home").unwrap_or_else(default_home);
    let yes = has_flag(args, "--yes");
    let home_path = PathBuf::from(&home);

    if !yes {
        println!("This will wipe chain state, WAL, and mempool in: {}", home);
        println!("Wallet data will be preserved.");
        println!("Add --yes to confirm.");
        return Ok(());
    }

    // Wipe chain and WAL dirs
    let chain_dir = home_path.join("chain");
    let wal_dir = home_path.join("wal");

    if chain_dir.exists() {
        fs::remove_dir_all(&chain_dir)
            .map_err(|e| format!("Failed to remove chain dir: {}", e))?;
        fs::create_dir_all(&chain_dir)
            .map_err(|e| format!("Failed to recreate chain dir: {}", e))?;
    }
    if wal_dir.exists() {
        fs::remove_dir_all(&wal_dir)
            .map_err(|e| format!("Failed to remove wal dir: {}", e))?;
        fs::create_dir_all(&wal_dir)
            .map_err(|e| format!("Failed to recreate wal dir: {}", e))?;
    }

    println!("Node state reset complete: {}", home);

    Ok(())
}

fn cmd_config(args: &[String]) -> Result<(), String> {
    let home = parse_flag(args, "--home").unwrap_or_else(default_home);
    let config_path = PathBuf::from(&home).join("config.toml");

    if !config_path.exists() {
        return Err(format!("Config not found: {}. Run 'misaka node init'.", config_path.display()));
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    println!("{}", content);

    Ok(())
}
