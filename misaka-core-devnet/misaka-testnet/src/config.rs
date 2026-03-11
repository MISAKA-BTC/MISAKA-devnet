// ============================================================
// MISAKA Testnet — Configuration Generation
// ============================================================

use crate::{NodeId, NodeRole};
use serde::{Serialize, Deserialize};

/// Configuration for a single testnet node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub seed_peers: Vec<NodeId>,
    pub chain_id: String,
}

/// Configuration for the entire testnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetConfig {
    pub validator_count: usize,
    pub observer_count: usize,
    pub chain_id: String,
    pub p2p_base_port: u16,
    pub rpc_base_port: u16,
    /// Maximum ticks to wait for a single block.
    pub max_ticks_per_block: u64,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            validator_count: 10,
            observer_count: 1,
            chain_id: "misaka-testnet-1".into(),
            p2p_base_port: 30000,
            rpc_base_port: 31000,
            max_ticks_per_block: 200,
        }
    }
}

impl TestnetConfig {
    /// Generate per-node configs from testnet config.
    pub fn generate_node_configs(&self) -> Vec<NodeConfig> {
        let total = self.validator_count + self.observer_count;
        let mut configs = Vec::with_capacity(total);

        for i in 0..self.validator_count {
            let node_id = (i + 1) as NodeId;
            configs.push(NodeConfig {
                node_id,
                role: NodeRole::Validator,
                p2p_port: self.p2p_base_port + i as u16,
                rpc_port: self.rpc_base_port + i as u16,
                seed_peers: if i == 0 { vec![] } else { vec![1] }, // seed from node 1
                chain_id: self.chain_id.clone(),
            });
        }

        for i in 0..self.observer_count {
            let node_id = (self.validator_count + i + 1) as NodeId;
            configs.push(NodeConfig {
                node_id,
                role: NodeRole::Observer,
                p2p_port: self.p2p_base_port + 10 + i as u16,
                rpc_port: self.rpc_base_port + 10 + i as u16,
                seed_peers: vec![1], // seed from node 1
                chain_id: self.chain_id.clone(),
            });
        }

        configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_generation() {
        let cfg = TestnetConfig::default();
        let nodes = cfg.generate_node_configs();

        assert_eq!(nodes.len(), 11); // 10 validators + 1 observer
        assert_eq!(nodes[0].role, NodeRole::Validator);
        assert_eq!(nodes[0].node_id, 1);
        assert!(nodes[0].seed_peers.is_empty()); // node 1 has no seed
        assert_eq!(nodes[1].seed_peers, vec![1]); // node 2 seeds from 1
        assert_eq!(nodes[10].role, NodeRole::Observer);
    }
}
