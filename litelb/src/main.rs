use std::{env, net::Ipv4Addr, time::Duration};

use anyhow::{Context as _, Result};
use clap::Parser;
use litelb::ebpf::Ebpf;
use litelb_common::{Config, Service};
use tokio_graceful::Shutdown;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    init_logging()?;
    try_set_rlimit();

    let config = Config {
        vip: Ipv4Addr::new(192, 168, 16, 3),
        port: 1234,
        nr_svc: 3,
    };
    // TODO: Make svc addresses configurable
    // TODO: Accept IPs, periodic arp for the L2 addrs
    let svc1 = Service { mac: [0; 6] };
    let svc2 = Service { mac: [0; 6] };
    let svc3 = Service { mac: [0; 6] };

    let Opt { iface } = opt;
    let shutdown = Shutdown::default();
    let _ebpf = Ebpf::start(config, vec![svc1, svc2, svc3], iface, shutdown.guard()).await?;

    log::info!("startup complete");

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("error while executing graceful shutdown")?;

    log::info!("shutdown complete");
    Ok(())
}

fn try_set_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::warn!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn init_logging() -> Result<()> {
    if env::var("LITELB_LOG").is_err() {
        unsafe {
            env::set_var("LITELB_LOG", "info");
        }
    }

    pretty_env_logger::try_init_timed_custom_env("LITELB_LOG")?;

    Ok(())
}
