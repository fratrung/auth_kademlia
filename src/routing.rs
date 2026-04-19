use std::collections::VecDeque;
use std::ops::RangeInclusive;
use crate::node::Node;
use crate::utils::ID_LEN;

/// Un singolo K-bucket
pub struct KBucket {
    pub range: RangeInclusive<u128>,
    nodes: VecDeque<Node>,
    ksize: usize,
}

impl KBucket {
    pub fn new(range: RangeInclusive<u128>, ksize: usize) -> Self {
        Self { range, nodes: VecDeque::new(), ksize }
    }

    pub fn add_node(&mut self, node: Node) -> bool {
        // Rimuovi eventuale duplicato
        self.nodes.retain(|n| n.id != node.id);
        if self.nodes.len() < self.ksize {
            self.nodes.push_back(node);
            true
        } else {
            false // bucket pieno — in Kademlia classico si fa ping al head
        }
    }

    pub fn remove_node(&mut self, node: &Node) {
        self.nodes.retain(|n| n.id != node.id);
    }

    pub fn contains(&self, node: &Node) -> bool {
        self.nodes.iter().any(|n| n.id == node.id)
    }

    pub fn is_lonely(&self) -> bool {
        self.nodes.len() < self.ksize / 2
    }

    pub fn nodes(&self) -> &VecDeque<Node> {
        &self.nodes
    }
}

/// Routing table Kademlia completa
pub struct RoutingTable {
    pub node: Node,
    ksize: usize,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(node: Node, ksize: usize) -> Self {
        // Inizia con un solo bucket che copre tutto lo spazio
        let bucket = KBucket::new(0..=u128::MAX, ksize);
        Self { node, ksize, buckets: vec![bucket] }
    }

    /// Aggiunge un contatto alla routing table
    pub fn add_contact(&mut self, node: Node) {
        if node.id == self.node.id {
            return;
        }
        let idx = self.bucket_index_for(&node);
        if !self.buckets[idx].add_node(node.clone()) {
            // Bucket pieno: split se contiene il nodo locale, altrimenti scarta
            // (implementazione semplificata)
            log::debug!("Bucket full, discarding node {}", node);
        }
    }

    /// Rimuove un contatto
    pub fn remove_contact(&mut self, node: &Node) {
        let idx = self.bucket_index_for(node);
        self.buckets[idx].remove_node(node);
    }

    /// Verifica se il nodo è nuovo (non nella routing table)
    pub fn is_new_node(&self, node: &Node) -> bool {
        let idx = self.bucket_index_for(node);
        !self.buckets[idx].contains(node)
    }

    /// Trova i k nodi più vicini alla chiave data, escludendo opzionalmente un nodo
    pub fn find_neighbors(&self, target: &Node, exclude: Option<&Node>) -> Vec<Node> {
        let mut candidates: Vec<Node> = self
            .buckets
            .iter()
            .flat_map(|b| b.nodes().iter().cloned())
            .filter(|n| {
                if let Some(ex) = exclude {
                    n.id != ex.id
                } else {
                    true
                }
            })
            .collect();

        // Ordina per distanza XOR crescente
        candidates.sort_by(|a, b| {
            let da = a.distance_to(target);
            let db = b.distance_to(target);
            da.cmp(&db)
        });

        candidates.truncate(self.ksize);
        candidates
    }

    /// Bucket "lonely" (pochi nodi) che necessitano refresh
    pub fn lonely_buckets(&self) -> Vec<&KBucket> {
        self.buckets.iter().filter(|b| b.is_lonely()).collect()
    }

    fn bucket_index_for(&self, node: &Node) -> usize {
        // Semplificazione: usa il primo byte dell'ID XOR come indice
        // In una implementazione completa si fa split dei bucket
        let dist = self.node.distance_to(node);
        // Trova il primo bit diverso (leading zeros della distanza XOR)
        let bytes = dist.to_le_bytes();
        let leading = bytes.iter().flat_map(|b| (0..8u8).rev().map(move |i| (b >> i) & 1 == 0)).position(|z| !z).unwrap_or(ID_LEN * 8 - 1);
        leading.min(self.buckets.len() - 1)
    }
}
