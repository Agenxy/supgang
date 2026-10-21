//! Deterministic Internet uplink impairments for simulator calibration.

use std::{io, net::IpAddr, time::Duration};

use super::{MAX_DATAGRAM_BYTES, Network, SiteId};

/// Which address family a simulated Internet impairment affects.
#[derive(Clone, Copy, Debug)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::V4 => 0,
            Self::V6 => 1,
        }
    }

    pub(super) const fn from_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Impairment {
    pub(super) loss_permille: u16,
    pub(super) latency: Duration,
    pub(super) max_datagram_bytes: Option<usize>,
}

impl Network {
    /// Sets the one-way delay across a site's Internet uplink; a path between
    /// two sites takes the sum of both, and on-link traffic takes none.
    pub fn set_latency(&self, site: SiteId, one_way: Duration) -> io::Result<()> {
        if one_way > Duration::from_secs(2) {
            return Err(io::Error::other("simulated latency above two seconds"));
        }
        self.lock()?
            .site_mut(site)?
            .impairment
            .iter_mut()
            .for_each(|value| value.latency = one_way);
        Ok(())
    }

    /// Changes one family's one-way Internet uplink delay.
    pub fn set_family_latency(&self, site: SiteId, family: IpFamily, one_way: Duration) -> io::Result<()> {
        if one_way > Duration::from_secs(2) {
            return Err(io::Error::other("simulated latency above two seconds"));
        }
        self.lock()?
            .site_mut(site)?
            .impairment
            .get_mut(family.index())
            .ok_or_else(|| io::Error::other("unknown simulated address family"))?
            .latency = one_way;
        Ok(())
    }

    pub fn set_loss_permille(&self, site: SiteId, permille: u16) -> io::Result<()> {
        if permille > 1000 {
            return Err(io::Error::other("loss above 1000 per mille"));
        }
        self.lock()?
            .site_mut(site)?
            .impairment
            .iter_mut()
            .for_each(|value| value.loss_permille = permille);
        Ok(())
    }

    /// Changes one family's Internet uplink loss rate.
    pub fn set_family_loss_permille(&self, site: SiteId, family: IpFamily, permille: u16) -> io::Result<()> {
        if permille > 1000 {
            return Err(io::Error::other("loss above 1000 per mille"));
        }
        self.lock()?
            .site_mut(site)?
            .impairment
            .get_mut(family.index())
            .ok_or_else(|| io::Error::other("unknown simulated address family"))?
            .loss_permille = permille;
        Ok(())
    }

    /// Silently discards this family's oversized Internet datagrams at a site.
    pub fn set_family_mtu(&self, site: SiteId, family: IpFamily, max_datagram_bytes: Option<usize>) -> io::Result<()> {
        if max_datagram_bytes.is_some_and(|limit| !(1200..=MAX_DATAGRAM_BYTES).contains(&limit)) {
            return Err(io::Error::other("simulated MTU outside UDP payload bounds"));
        }
        self.lock()?
            .site_mut(site)?
            .impairment
            .get_mut(family.index())
            .ok_or_else(|| io::Error::other("unknown simulated address family"))?
            .max_datagram_bytes = max_datagram_bytes;
        Ok(())
    }
}
