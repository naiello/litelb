#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_PASS, XDP_TX},
    macros::xdp,
    programs::XdpContext,
};
use litelb_ebpf::mem::ptr_at;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const SELF: Ipv4Addr = Ipv4Addr::from_octets([192, 168, 16, 3]);
const LB_PORT: u16 = 1234;
const NEXT_HOP_MAC: [u8; 6] = [0xd4, 0x5d, 0x64, 0x26, 0x18, 0x12];

#[xdp]
pub fn litelb(ctx: XdpContext) -> u32 {
    handle(ctx).unwrap_or(XDP_ABORTED)
}

enum TransportHeader {
    Udp(*mut UdpHdr),
    Tcp(*mut TcpHdr),
}

impl TransportHeader {
    #[inline]
    fn dst_port(&self) -> u16 {
        use TransportHeader::*;

        match *self {
            Tcp(hdr) => u16::from_be_bytes(unsafe { (*hdr).dest }),
            Udp(hdr) => u16::from_be_bytes(unsafe { (*hdr).dst }),
        }
    }
}

#[inline]
fn get_l2_l3_hdr(ctx: &XdpContext) -> Result<Option<(*mut EthHdr, *mut Ipv4Hdr)>, &'static str> {
    let eth_hdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    let res = match unsafe { (*eth_hdr).ether_type() } {
        Ok(EtherType::Ipv4) => Some((eth_hdr, ptr_at(&ctx, EthHdr::LEN)?)),
        _ => None,
    };
    Ok(res)
}

#[inline]
fn get_l4_hdr(
    ctx: &XdpContext,
    ipv4_hdr: *const Ipv4Hdr,
) -> Result<Option<TransportHeader>, &'static str> {
    use TransportHeader::*;

    let hdr = match unsafe { (*ipv4_hdr).proto } {
        IpProto::Tcp => Some(Tcp(ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?)),
        IpProto::Udp => Some(Udp(ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?)),
        _ => None,
    };

    Ok(hdr)
}

#[inline]
fn route(eth_hdr: *mut EthHdr) -> u32 {
    unsafe {
        // Set the source MAC to ourselves
        (*eth_hdr).src_addr = (*eth_hdr).dst_addr;

        // Set the next-hop MAC towards the backend
        (*eth_hdr).dst_addr = NEXT_HOP_MAC;
    }

    XDP_TX
}

fn handle(ctx: XdpContext) -> Result<u32, &'static str> {
    if let Some((eth_hdr, ipv4_hdr)) = get_l2_l3_hdr(&ctx)? {
        let dst_ip = unsafe { (*ipv4_hdr).dst_addr() };
        if let Some(l4_hdr) = get_l4_hdr(&ctx, ipv4_hdr)?
            && l4_hdr.dst_port() == LB_PORT
            && dst_ip == SELF
        {
            return Ok(route(eth_hdr));
        }
    }

    Ok(XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
