use aya_ebpf::programs::XdpContext;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::mem::ptr_at;

pub enum TransportHeader {
    Udp(*mut UdpHdr),
    Tcp(*mut TcpHdr),
}

impl TransportHeader {
    #[inline]
    pub fn src_port(&self) -> u16 {
        use TransportHeader::*;

        match *self {
            Tcp(hdr) => u16::from_be_bytes(unsafe { (*hdr).source }),
            Udp(hdr) => u16::from_be_bytes(unsafe { (*hdr).src }),
        }
    }

    #[inline]
    pub fn dst_port(&self) -> u16 {
        use TransportHeader::*;

        match *self {
            Tcp(hdr) => u16::from_be_bytes(unsafe { (*hdr).dest }),
            Udp(hdr) => u16::from_be_bytes(unsafe { (*hdr).dst }),
        }
    }
}

pub struct Headers {
    pub eth_hdr: *mut EthHdr,
    pub ipv4_hdr: *mut Ipv4Hdr,
    pub l4_hdr: TransportHeader,
}

#[inline]
pub fn get_l2_l3_hdr(
    ctx: &XdpContext,
) -> Result<Option<(*mut EthHdr, *mut Ipv4Hdr)>, &'static str> {
    let eth_hdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    let res = match unsafe { (*eth_hdr).ether_type() } {
        Ok(EtherType::Ipv4) => Some((eth_hdr, ptr_at(&ctx, EthHdr::LEN)?)),
        _ => None,
    };
    Ok(res)
}

#[inline]
pub fn get_l4_hdr(
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
