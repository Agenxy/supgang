//! Protected owner policy for optional fixed-loopback application transport.

use std::{fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{artifact, record::ServiceName, storage};

pub const FILE_NAME: &str = "tunnels.json";
const MAX_BYTES: usize = 4_096;
pub const MAX_PER_PEER: usize = 64;
pub const MAX_TOTAL: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exposure {
    pub name: ServiceName,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelPolicy {
    pub version: u16,
    pub per_peer: usize,
    pub total: usize,
    pub idle_seconds: u64,
    pub exposures: Vec<Exposure>,
    #[serde(default)]
    pub mapped: Vec<std::net::SocketAddr>,
}

impl Default for TunnelPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            per_peer: 4,
            total: 16,
            idle_seconds: 7_200,
            exposures: Vec::new(),
            mapped: Vec::new(),
        }
    }
}

impl TunnelPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || !(1..=MAX_PER_PEER).contains(&self.per_peer)
            || !(1..=MAX_TOTAL).contains(&self.total)
            || !(60..=86_400).contains(&self.idle_seconds)
            || self.exposures.len() > 4
            || self.mapped.len() > 4
        {
            return Err("tunnel policy exceeds its version or safety bounds");
        }
        let mut names = std::collections::BTreeSet::new();
        for exposure in &self.exposures {
            ServiceName::new(exposure.name.as_str()).map_err(|_| "tunnel service name is invalid")?;
            if exposure.port == 0 || !names.insert(exposure.name.clone()) {
                return Err("tunnel exposures contain a zero port or duplicate name");
            }
        }
        let mut addresses = std::collections::BTreeSet::new();
        for address in &self.mapped {
            crate::candidate::EndpointCandidate::new(
                crate::candidate::CandidateKind::Mapped,
                crate::candidate::CandidateTransport::QuicV1,
                *address,
            )
            .map_err(|_| "mapped endpoint must be a global nonzero UDP socket")?;
            if !address.is_ipv4() || !addresses.insert(*address) {
                return Err("mapped endpoints must be distinct public IPv4 sockets");
            }
        }
        Ok(())
    }

    pub fn port(&self, name: &ServiceName) -> Option<u16> {
        self.exposures
            .iter()
            .find(|entry| &entry.name == name)
            .map(|entry| entry.port)
    }

    pub fn set(&mut self, name: ServiceName, port: u16) -> Result<(), &'static str> {
        self.exposures.retain(|entry| entry.name != name);
        if port != 0 {
            self.exposures.push(Exposure { name, port });
        }
        self.validate()
    }
}

pub fn load(directory: &Path) -> Result<TunnelPolicy, String> {
    let directory = storage::validate_directory(directory).map_err(|_| "tunnel state directory is unsafe")?;
    let path = directory.join(FILE_NAME);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(TunnelPolicy::default()),
        Err(_) => return Err("tunnel policy metadata failed".to_owned()),
        Ok(_) => {}
    }
    let bytes = artifact::read(&path, MAX_BYTES).map_err(|_| "tunnel policy is not a bounded owner-only file")?;
    let policy: TunnelPolicy = serde_json::from_slice(&bytes).map_err(|_| "tunnel policy is malformed")?;
    policy.validate()?;
    Ok(policy)
}

pub fn save(directory: &Path, policy: &TunnelPolicy) -> Result<(), String> {
    policy.validate()?;
    let directory = storage::validate_directory(directory).map_err(|_| "tunnel state directory is unsafe")?;
    let _existing = load(&directory)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| "tunnel policy encoding failed")?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "tunnel replacement allocation failed")?;
    let temporary = directory.join(format!(".tunnels-{}.tmp", hex::encode(random)));
    artifact::write_new(&temporary, &bytes, MAX_BYTES).map_err(|_| "tunnel replacement write failed")?;
    let result = (|| {
        fs::rename(&temporary, directory.join(FILE_NAME)).map_err(|_| "tunnel policy commit failed")?;
        storage::sync_directory(&directory).map_err(|_| "tunnel policy directory sync failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = fs::remove_file(temporary);
    }
    result
}

pub fn encoded_name(name: &ServiceName) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    for (target, source) in bytes.iter_mut().zip(name.as_str().bytes()) {
        *target = source;
    }
    bytes
}

pub fn decoded_name(bytes: [u8; 16]) -> Result<ServiceName, &'static str> {
    let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if bytes.iter().skip(length).any(|byte| *byte != 0) {
        return Err("tunnel service name has invalid padding");
    }
    let text = std::str::from_utf8(bytes.get(..length).ok_or("tunnel service name is invalid")?)
        .map_err(|_| "tunnel service name is invalid")?;
    ServiceName::new(text).map_err(|_| "tunnel service name is invalid")
}

#[cfg(test)]
mod tests;
