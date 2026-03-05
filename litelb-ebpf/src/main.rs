#![no_std]
#![no_main]

use core::hash::{Hash, Hasher};

use aya_ebpf::{
    bindings::xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX},
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
use aya_log_ebpf::{error, warn};
use litelb_common::{Config, Conn, Service};
use litelb_ebpf::{
    hash::FxHasher,
    packet::{Headers, get_l2_l3_hdr, get_l4_hdr},
};
use network_types::eth::EthHdr;

#[map]
static SERVICES: Array<Service> = Array::with_max_entries(16, 0);

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[xdp]
pub fn litelb(ctx: XdpContext) -> u32 {
    handle(&ctx)
        .inspect_err(|err| error!(&ctx, "abort: {}", *err))
        .unwrap_or(XDP_ABORTED)
}

#[inline]
fn handle(ctx: &XdpContext) -> Result<u32, &'static str> {
    let Some((conn, hdr)) = get_conn(&ctx)? else {
        return Ok(XDP_PASS);
    };

    let cfg = get_cfg()?;
    if cfg.vip != conn.dst_ip || cfg.port != conn.dst_port {
        return Ok(XDP_PASS);
    }

    let Some(svc) = get_svc(&cfg, &conn) else {
        warn!(&ctx, "no services available, dropping packet");
        return Ok(XDP_DROP);
    };

    Ok(route_dsr(&svc, hdr.eth_hdr))
}

#[inline]
fn get_conn(ctx: &XdpContext) -> Result<Option<(Conn, Headers)>, &'static str> {
    if let Some((eth_hdr, ipv4_hdr)) = get_l2_l3_hdr(&ctx)?
        && let Some(l4_hdr) = get_l4_hdr(ctx, ipv4_hdr)?
    {
        let conn = Conn {
            src_ip: unsafe { (*ipv4_hdr).src_addr() },
            dst_ip: unsafe { (*ipv4_hdr).dst_addr() },
            src_port: l4_hdr.src_port(),
            dst_port: l4_hdr.dst_port(),
            proto: unsafe { (*ipv4_hdr).proto } as u8,
        };

        let headers = Headers {
            eth_hdr,
            ipv4_hdr,
            l4_hdr,
        };

        return Ok(Some((conn, headers)));
    }

    Ok(None)
}

#[inline]
fn get_cfg() -> Result<&'static Config, &'static str> {
    CONFIG.get(0).ok_or("no config available")
}

#[inline]
fn get_svc(cfg: &Config, conn: &Conn) -> Option<&'static Service> {
    if cfg.nr_svc == 0 {
        return None;
    }

    let mut hasher = FxHasher::default();
    conn.hash(&mut hasher);
    let conn_hash = hasher.finish();
    SERVICES.get((conn_hash % (cfg.nr_svc as u64)) as u32)
}

#[inline]
fn route_dsr(svc: &Service, eth_hdr: *mut EthHdr) -> u32 {
    unsafe {
        // Set the source MAC to ourselves
        (*eth_hdr).src_addr = (*eth_hdr).dst_addr;

        // Set the next-hop MAC towards the backend
        (*eth_hdr).dst_addr = svc.mac;
    }

    XDP_TX
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
