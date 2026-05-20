// ---------------------------------------------------------------------------
// Application-level fragmentation
// ---------------------------------------------------------------------------
//
// Post-quantum signed records (Dilithium-2 signature alone is 2420 bytes,
// plus the JSON DID Document with base64-encoded Kyber/Dilithium public keys)
// routinely produce UDP payloads of ~6 KB. Relying on kernel-level IP
// fragmentation is unreliable on UDP: losing a single fragment causes the
// whole datagram to be silently dropped, and middleboxes often filter
// fragmented IP traffic. We therefore implement explicit, application-level
// fragmentation so that every wire packet stays well below the Ethernet MTU.
//
// Wire format of every UDP datagram sent by this module:
//
//   [magic: 4][frag_id: u32][index: u16][total: u16][payload...]
//
// All multi-byte integers are big-endian. `magic` lets the receiver detect
// stray non-fragmented traffic and reject it. `frag_id` is unique per logical
// message and per sender. `index` is 0-based; `total` is the number of
// fragments composing the logical message (>= 1). When `total == 1` the
// payload is the entire serialized frame.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

const FRAG_MAGIC: u32 = 0x4B41_4446; // "KADF"
const FRAG_HEADER_LEN: usize = 4 + 4 + 2 + 2; // 12 bytes
/// Maximum payload bytes per UDP datagram (after our header).
/// 1400 leaves headroom for IP (20) + UDP (8) + VLAN tag (4) + tunnel overhead.
pub const FRAG_CHUNK_SIZE: usize = 1400;
/// Reassembly buffers older than this are discarded.
pub const REASSEMBLY_TTL: Duration = Duration::from_secs(10);
/// Hard cap on a logical message size to bound memory usage per peer.
pub const MAX_MESSAGE_SIZE: usize = 256 * 1024;

/// Reassembly state for a single in-flight logical message.
pub struct ReassemblyEntry {
    pub(crate) total: u16,
    pub(crate) received: u16,
    pub(crate) chunks: Vec<Option<Vec<u8>>>,
    pub(crate) created_at: Instant,
}

impl ReassemblyEntry {
    pub fn new(total: u16) -> Self {
        Self {
            total,
            received: 0,
            chunks: (0..total as usize).map(|_| None).collect(),
            created_at: Instant::now(),
        }
    }

    pub fn insert(&mut self, index: u16, payload: Vec<u8>) -> bool {
        let idx = index as usize;
        if idx >= self.chunks.len() {
            return false;
        }
        if self.chunks[idx].is_none() {
            self.chunks[idx] = Some(payload);
            self.received += 1;
        }
        self.received == self.total
    }

    pub fn assemble(self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for c in self.chunks {
            out.extend_from_slice(&c?);
        }
        Some(out)
    }
}

/// Reassembly buffers keyed by (peer, frag_id).
pub type ReassemblyMap = Arc<Mutex<HashMap<(SocketAddr, u32), ReassemblyEntry>>>;

/// Encode a complete serialized message into one or more fragment datagrams.
pub fn encode_fragments(frag_id: u32, payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        // Send an empty single-fragment datagram so the peer still observes
        // the message; in practice this branch is unreachable for our RPCs.
        let mut buf = Vec::with_capacity(FRAG_HEADER_LEN);
        buf.extend_from_slice(&FRAG_MAGIC.to_be_bytes());
        buf.extend_from_slice(&frag_id.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        return vec![buf];
    }

    let total = payload.len().div_ceil(FRAG_CHUNK_SIZE) as u16;
    let mut datagrams = Vec::with_capacity(total as usize);

    for (i, chunk) in payload.chunks(FRAG_CHUNK_SIZE).enumerate() {
        let mut buf = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
        buf.extend_from_slice(&FRAG_MAGIC.to_be_bytes());
        buf.extend_from_slice(&frag_id.to_be_bytes());
        buf.extend_from_slice(&(i as u16).to_be_bytes());
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(chunk);
        datagrams.push(buf);
    }
    datagrams
}

/// Parsed fragment header.
pub struct FragHeader {
    pub(crate) frag_id: u32,
    pub(crate) index: u16,
    pub(crate) total: u16,
}

/// Parse a fragment header. Returns `None` if the datagram is malformed or
/// does not carry our magic.
pub fn parse_fragment(data: &[u8]) -> Option<(FragHeader, &[u8])> {
    if data.len() < FRAG_HEADER_LEN {
        return None;
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if magic != FRAG_MAGIC {
        return None;
    }
    let frag_id = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let index = u16::from_be_bytes(data[8..10].try_into().ok()?);
    let total = u16::from_be_bytes(data[10..12].try_into().ok()?);
    if total == 0 || index >= total {
        return None;
    }
    Some((
        FragHeader {
            frag_id,
            index,
            total,
        },
        &data[FRAG_HEADER_LEN..],
    ))
}
