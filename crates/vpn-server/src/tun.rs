//! TUN device management for Linux.
//!
//! Creates and manages a TUN interface using `/dev/net/tun` via ioctl.
//! Handles IP assignment from a pool and provides async read/write.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use dashmap::DashSet;
use parking_lot::Mutex;
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

/// TUN interface name max length (IFNAMSIZ on Linux).
const IFNAMSIZ: usize = 16;

/// ioctl request codes for TUN/TAP.
const TUNSETIFF: libc::c_ulong = 0x400454CA;

/// TUN device flags.
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("failed to open /dev/net/tun: {0}")]
    OpenDevice(std::io::Error),
    #[error("ioctl TUNSETIFF failed: {0}")]
    SetInterface(std::io::Error),
    #[error("failed to set non-blocking: {0}")]
    NonBlocking(std::io::Error),
    #[error("IP pool exhausted — no available addresses")]
    PoolExhausted,
    #[error("IP address {0} is not in the pool")]
    NotInPool(Ipv4Addr),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Raw ifreq structure for ioctl.
#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22], // pad to struct ifreq size
}

/// A Linux TUN device.
pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given name prefix.
    ///
    /// The kernel will append a number if the name ends with `%d`.
    /// Returns the device and its actual interface name.
    pub fn create(name: &str) -> Result<Self, TunError> {
        // Open /dev/net/tun
        let fd = unsafe {
            let raw_fd = libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_NONBLOCK,
            );
            if raw_fd < 0 {
                return Err(TunError::OpenDevice(std::io::Error::last_os_error()));
            }
            OwnedFd::from_raw_fd(raw_fd)
        };

        // Prepare ifreq
        let mut ifr = IfReq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };

        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(IFNAMSIZ - 1);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // ioctl TUNSETIFF
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, &mut ifr) };
        if ret < 0 {
            return Err(TunError::SetInterface(std::io::Error::last_os_error()));
        }

        // Extract the actual interface name
        let actual_name = ifr.ifr_name
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect::<String>();

        info!(interface = %actual_name, "TUN device created");

        let async_fd = AsyncFd::new(fd).map_err(TunError::NonBlocking)?;

        Ok(Self {
            fd: async_fd,
            name: actual_name,
        })
    }

    /// Get the interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read a packet from the TUN device.
    ///
    /// Returns the number of bytes read into `buf`.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|fd| {
                let n = unsafe {
                    libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Io),
                Err(_would_block) => continue,
            }
        }
    }

    /// Write a packet to the TUN device.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, TunError> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| {
                let n = unsafe {
                    libc::write(fd.as_raw_fd(), buf.as_ptr() as *const libc::c_void, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Io),
                Err(_would_block) => continue,
            }
        }
    }
}

/// IP address pool for assigning tunnel IPs to clients.
pub struct IpPool {
    /// All available IPs (those not currently assigned).
    available: Mutex<Vec<Ipv4Addr>>,
    /// Currently assigned IPs.
    assigned: DashSet<Ipv4Addr>,
}

impl IpPool {
    /// Create a new IP pool from a range.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        let available: Vec<Ipv4Addr> = (start_u32..=end_u32)
            .map(Ipv4Addr::from)
            .collect();

        let capacity = available.len();
        info!(
            pool_start = %start,
            pool_end = %end,
            capacity = capacity,
            "IP pool created"
        );

        Self {
            available: Mutex::new(available),
            assigned: DashSet::new(),
        }
    }

    /// Allocate an IP from the pool.
    pub fn allocate(&self) -> Result<Ipv4Addr, TunError> {
        let mut available = self.available.lock();
        let ip = available.pop().ok_or(TunError::PoolExhausted)?;
        self.assigned.insert(ip);
        debug!(ip = %ip, remaining = available.len(), "IP allocated");
        Ok(ip)
    }

    /// Release an IP back to the pool.
    pub fn release(&self, ip: Ipv4Addr) -> Result<(), TunError> {
        if self.assigned.remove(&ip).is_some() {
            let mut available = self.available.lock();
            available.push(ip);
            debug!(ip = %ip, remaining = available.len(), "IP released");
            Ok(())
        } else {
            warn!(ip = %ip, "Attempted to release unassigned IP");
            Err(TunError::NotInPool(ip))
        }
    }

    /// Number of available IPs.
    #[allow(dead_code)]
    pub fn available_count(&self) -> usize {
        self.available.lock().len()
    }

    /// Number of assigned IPs.
    #[allow(dead_code)]
    pub fn assigned_count(&self) -> usize {
        self.assigned.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_pool_allocate_release() {
        let pool = IpPool::new(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 5),
        );
        assert_eq!(pool.available_count(), 4);
        assert_eq!(pool.assigned_count(), 0);

        let ip1 = pool.allocate().unwrap();
        assert_eq!(pool.available_count(), 3);
        assert_eq!(pool.assigned_count(), 1);

        let ip2 = pool.allocate().unwrap();
        assert_ne!(ip1, ip2);

        pool.release(ip1).unwrap();
        assert_eq!(pool.available_count(), 3);
        assert_eq!(pool.assigned_count(), 1);
    }

    #[test]
    fn test_ip_pool_exhaustion() {
        let pool = IpPool::new(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 3),
        );

        let _ip1 = pool.allocate().unwrap();
        let _ip2 = pool.allocate().unwrap();
        let result = pool.allocate();
        assert!(matches!(result, Err(TunError::PoolExhausted)));
    }

    #[test]
    fn test_release_unassigned_ip() {
        let pool = IpPool::new(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(10, 8, 0, 5),
        );

        let result = pool.release(Ipv4Addr::new(192, 168, 1, 1));
        assert!(result.is_err());
    }
}
