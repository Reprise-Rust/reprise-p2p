pub mod tcp;
pub mod udp;
pub mod server;
pub mod config;

pub mod ctrlc_reg {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    #[derive(Clone)]
    pub struct ShutdownListener(Arc<AtomicBool>, tokio::sync::watch::Receiver<bool>);
    #[derive(Clone)]
    pub struct ShutdownSignal(Arc<AtomicBool>, tokio::sync::watch::Sender<bool>);
    impl ShutdownSignal {
        pub fn trigger(&self) {
            self.0.store(true, Ordering::Relaxed);
            self.1.send(true).unwrap();
        }
    }

    impl ShutdownListener {
        pub fn register_ctrl_c() -> Self {
            let (manual, shutdown_req) = Self::register_manual();
            ctrlc::set_handler(move || {
                manual.trigger();
            }).unwrap();

            shutdown_req
        }

        pub fn register_manual() -> (ShutdownSignal, Self) {
            let sig = Arc::new(AtomicBool::new(false));
            let (watch_tx, watch_rx) = tokio::sync::watch::channel(false);
            let sig_clone = sig.clone();

            let manual = ShutdownSignal(sig_clone.clone(), watch_tx);

            (manual, Self(sig_clone, watch_rx))
        }

        pub fn is_shutdown(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }

        pub async fn wait(&mut self) {
            let _ = self.1.wait_for(|t| *t).await;
        }
    }
}