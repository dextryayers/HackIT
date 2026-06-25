use std::io;

#[cfg(target_os = "linux")]
use std::mem;

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

#[cfg(not(target_os = "linux"))]
compile_error!("raw_injector requires Linux AF_PACKET sockets");

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub struct RawSocket {
        fd: RawFd,
        iface: String,
    }

    impl RawSocket {
        pub fn open(iface: &str) -> io::Result<Self> {
            let fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW,
                    (libc::ETH_P_ALL as u16).to_be() as i32,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let sock_addr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: 0,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0u8; 8],
            };

            let if_cstr = std::ffi::CString::new(iface).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name"))?;
            let ifindex = unsafe { libc::if_nametoindex(if_cstr.as_ptr()) };
            if ifindex == 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            let sock_addr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: ifindex as libc::c_int,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0u8; 8],
            };

            let res = unsafe {
                libc::bind(
                    fd,
                    &sock_addr as *const _ as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if res < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            Ok(RawSocket {
                fd,
                iface: iface.to_string(),
            })
        }

        pub fn send(&self, data: &[u8]) -> io::Result<usize> {
            let res = unsafe {
                libc::send(
                    self.fd,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    0,
                )
            };
            if res < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(res as usize)
            }
        }

        /// Send burst of frames with optional delay
        pub fn send_burst(&self, data: &[u8], count: u32, delay_ms: u64) -> io::Result<u32> {
            let mut sent = 0u32;
            for _ in 0..count {
                match self.send(data) {
                    Ok(_) => sent += 1,
                    Err(_) => break,
                }
                if delay_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
            }
            Ok(sent)
        }
    }

    impl Drop for RawSocket {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    fn ifreq_for(name: &str) -> libc::ifreq {
        unsafe { mem::zeroed::<libc::ifreq>() }
    }
}

#[cfg(target_os = "linux")]
pub use linux::RawSocket;
