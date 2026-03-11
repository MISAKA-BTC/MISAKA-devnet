pub mod node;
pub mod wallet;
pub mod chain;
pub mod devnet;
pub mod testnet;

/// Parse a flag value from args: --key value
pub fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Check if a boolean flag is present: --flag
pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Default home directory.
pub fn default_home() -> String {
    std::env::var("MISAKA_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.misaka", home)
    })
}
