use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    maps::Array,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use litelb_common::{Config, Service};
use tokio::{select, sync::oneshot, time};
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;

pub struct Ebpf {
    _task: AbortOnDropHandle<Result<()>>,
}

impl Ebpf {
    pub async fn start(
        mut config: Config,
        svcs: Vec<Service>,
        iface: String,
        shutdown: ShutdownGuard,
    ) -> Result<Self> {
        let (ready_tx, ready_rx) = oneshot::channel::<()>();

        let task = shutdown.into_spawn_task_fn(move |shutdown| async move {
            let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/litelb"
            )))?;

            // Start the log processors
            match EbpfLogger::init(&mut ebpf) {
                Err(e) => {
                    log::warn!("failed to initialize eBPF logger: {e}");
                }
                Ok(logger) => {
                    let mut logger = tokio::io::unix::AsyncFd::with_interest(
                        logger,
                        tokio::io::Interest::READABLE,
                    )?;
                    shutdown.spawn_task_fn(|shutdown| async move {
                        loop {
                            select! {
                                guard = logger.readable_mut() => {
                                    match guard {
                                        Ok(mut guard) => {
                                            guard.get_inner_mut().flush();
                                            guard.clear_ready();
                                        }
                                        Err(err) => {
                                            log::warn!("failed to obtain logger handle: {:?}", err);
                                            break;
                                        }
                                    }
                                },
                                _ = shutdown.cancelled() => break,
                            }
                        }
                    });
                }
            }

            let mut configmap: Array<_, Config> = ebpf
                .map_mut("CONFIG")
                .context("expected to find CONFIG map")?
                .try_into()
                .context("expected CONFIG map to be an array")?;
            config.nr_svc = svcs.len();
            configmap
                .set(0, config, 0)
                .context("unable to load ebpf config")?;

            let mut svcmap: Array<_, Service> = ebpf
                .map_mut("SERVICES")
                .context("expected to find SERVICE map")?
                .try_into()
                .context("expected SERVICE map to be an array")?;

            for (i, svc) in svcs.iter().enumerate() {
                svcmap.set(i as u32, svc, 0)?;
            }

            let program: &mut Xdp = ebpf
                .program_mut("litelb")
                .context("could not load litelb ebpf program")?
                .try_into()
                .context("expected litelb to be xdp program")?;

            program.load()?;
            program
                .attach(&iface, XdpFlags::default())
                .context("failed to attach XDP program to interface")?;

            log::info!("eBPF program running on interface {}", iface);
            ready_tx
                .send(())
                .map_err(|_| anyhow!("failed to send ready signal"))?;

            shutdown.cancelled().await;
            log::info!("eBPF program shutting down");

            Ok(())
        });

        match time::timeout(Duration::from_secs(5), ready_rx).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                bail!("eBPF program failed to start: {:?}", err);
            }
            Err(_) => {
                bail!("eBPF program did not complete initialization within timeout");
            }
        }

        Ok(Self {
            _task: AbortOnDropHandle::new(task),
        })
    }
}
