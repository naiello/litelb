use network_types::{tcp::TcpHdr, udp::UdpHdr};

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
