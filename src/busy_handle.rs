#![allow(dead_code)]
use log::warn;
use crate::errstr::*;
use std::result::Result;
use std::sync::{Arc, RwLock};
const FBHSEND: &str = "Failed to send a BusyHandle message";
pub struct RxBusyHandle {
    rx_done: Arc<aevent::Event>,
    is_busy_lock: Arc<RwLock<bool>>,
}

impl RxBusyHandle {
    pub async fn wait(&mut self) {
        {
            let busy = match self.is_busy_lock.read() {
                Ok(guard) => guard,
                Err(_poison) => {
                    warn!("{}", WPOISON);
                    return},
            };
            if !*busy {
                return;
            }
        }
        self.rx_done.listen().await;
    }
}

pub struct TxBusyHandle {
    tx_done: Arc<aevent::Event>,
    is_busy_lock: Arc<RwLock<bool>>,
}

impl TxBusyHandle {
    pub fn busy(&self) -> Result<(), ()> {
        let mut busy = match self.is_busy_lock.write() {
            Ok(g) => g,
            Err(_poison) => unreachable!(FPOISON),
        };
        if !*busy {
            *busy = true;
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn done(&self) -> Result<(), ()> {
        let mut busy = match self.is_busy_lock.write() {
            Ok(g) => g,
            Err(_poison) => unreachable!(FPOISON),
        };
        if *busy {
            *busy = false;
            self.tx_done.notify(usize::MAX);
            Ok(())
        } else {
            Err(())
        }
    }
}
pub fn busy_handle() -> (TxBusyHandle, RxBusyHandle) {
    let is_busy_lock = Arc::new(RwLock::new(false));
    let ev = Arc::new(aevent::Event::new());
    (
        TxBusyHandle {
            tx_done: Arc::clone(&ev),
            is_busy_lock: Arc::clone(&is_busy_lock),
        },
        RxBusyHandle {
            rx_done: ev,
            is_busy_lock,
        },
    )
}
