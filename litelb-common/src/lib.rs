#![cfg_attr(not(feature = "std"), no_std)]

use core::net::Ipv4Addr;

#[repr(C)]
#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug, Copy, Clone))]
pub struct Config {
    pub vip: Ipv4Addr,
    pub port: u16,
    pub nr_svc: usize,
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for Config {}

#[repr(C)]
#[cfg_attr(feature = "std", derive(PartialEq, Eq, Debug, Copy, Clone))]
pub struct Service {
    pub mac: [u8; 6],
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for Service {}

#[repr(C)]
#[derive(Hash)]
pub struct Conn {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}
