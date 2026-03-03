#![no_std]
#![no_main]

use core::hash::{Hash, Hasher};

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX},
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use litelb_common::{Config, Conn, Service};
use litelb_ebpf::{hash::FxHasher, mem::ptr_at, packet::TransportHeader};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[map]
static SERVICES: Array<Service> = Array::with_max_entries(16, 0);

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[xdp]
pub fn litelb(ctx: XdpContext) -> u32 {
    handle(ctx).unwrap_or(XDP_ABORTED)
}

#[inline]
fn get_svc(conn: &Conn) -> Option<&'static Service> {
    get_cfg().filter(|cfg| cfg.nr_svc > 0).and_then(|cfg| {
        let mut hasher = FxHasher::default();
        conn.hash(&mut hasher);
        let conn_hash = hasher.finish();
        SERVICES.get((conn_hash % (cfg.nr_svc as u64)) as u32)
    })
}

#[inline]
fn get_cfg() -> Option<&'static Config> {
    CONFIG.get(0)
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
fn route(eth_hdr: *mut EthHdr, ip_hdr: *mut Ipv4Hdr, l4_hdr: &TransportHeader) -> u32 {
    let conn = Conn {
        src_ip: unsafe { (*ip_hdr).src_addr() },
        dst_ip: unsafe { (*ip_hdr).dst_addr() },
        src_port: l4_hdr.src_port(),
        dst_port: l4_hdr.dst_port(),
        proto: unsafe { (*ip_hdr).proto } as u8,
    };

    if let Some(svc) = get_svc(&conn) {
        unsafe {
            // Set the source MAC to ourselves
            (*eth_hdr).src_addr = (*eth_hdr).dst_addr;

            // Set the next-hop MAC towards the backend
            (*eth_hdr).dst_addr = svc.mac;
        }

        XDP_TX
    } else {
        XDP_DROP
    }
}

#[inline]
fn is_dst_lb(ipv4_hdr: *const Ipv4Hdr, l4_hdr: &TransportHeader) -> bool {
    get_cfg().is_some_and(|cfg| {
        cfg.vip == unsafe { (*ipv4_hdr).dst_addr() } && cfg.port == l4_hdr.dst_port()
    })
}

fn handle(ctx: XdpContext) -> Result<u32, &'static str> {
    if let Some((eth_hdr, ipv4_hdr)) = get_l2_l3_hdr(&ctx)? {
        if let Some(l4_hdr) = get_l4_hdr(&ctx, ipv4_hdr)?
            && is_dst_lb(ipv4_hdr, &l4_hdr)
        {
            return Ok(route(eth_hdr, ipv4_hdr, &l4_hdr));
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
