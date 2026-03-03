use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::{
    maps::Array,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use litelb_common::{Config, Service};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/litelb"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let config = Config {
        vip: Ipv4Addr::new(192, 168, 16, 3),
        port: 1234,
        nr_svc: 3,
    };
    let mut configmap: Array<_, Config> = ebpf
        .map_mut("CONFIG")
        .context("expected to find CONFIG map")?
        .try_into()
        .context("expected CONFIG map to be an array")?;
    configmap
        .set(0, config, 0)
        .context("unable to load ebpf config")?;

    let mut svcmap: Array<_, Service> = ebpf
        .map_mut("SERVICES")
        .context("expected to find SERVICE map")?
        .try_into()
        .context("expected SERVICE map to be an array")?;

    // TODO: Make svc addresses configurable
    // TODO: Accept IPs, periodic arp for the L2 addrs
    let svc1 = Service { mac: [0; 6] };
    svcmap.set(0, svc1, 0).context("failed to set svc1")?;

    let svc2 = Service { mac: [0; 6] };
    svcmap.set(1, svc2, 0).context("failed to set svc2")?;

    let svc3 = Service { mac: [0; 6] };
    svcmap.set(2, svc3, 0).context("failed to set svc3")?;

    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf
        .program_mut("litelb")
        .context("could not load litelb ebpf program")?
        .try_into()
        .context("expected litelb to be ebpf program")?;

    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
