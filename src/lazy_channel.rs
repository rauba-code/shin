use log::warn;
use crate::errstr::*;
use std::collections::VecDeque;
use std::result::Result;
use std::sync::{Arc, Mutex, RwLock};
use std::vec::Vec;

pub struct RxLazyChannel<T> {
    rx_done: Arc<aevent::Event>,
    is_busy_lock: Arc<RwLock<bool>>,
    channel_lock: Arc<Mutex<VecDeque<T>>>,
}

impl<T> RxLazyChannel<T> {
    pub async fn wait(&mut self) -> Vec<T> {
        let res = {
            // AREKON: We Avoid Deadlocks!
            *(match self.is_busy_lock.read() {
                Ok(guard) => guard,
                Err(_poison) => {
                    warn!("{}", WPOISON);
                    return Vec::<T>::new();
                }
            })
        };
        if res {
            self.rx_done.listen().await;
        }
        self.dump()
    }
    fn dump(&mut self) -> Vec<T> {
        let mut chan = match self.channel_lock.lock() {
            Ok(guard) => guard,
            Err(_poison) => {
                warn!("{}", WPOISON);
                return Vec::<T>::new();
            }
        };
        let mut result = Vec::<T>::with_capacity((*chan).len());
        while let Some(item) = (*chan).pop_front() {
            result.push(item)
        }
        result
    }
}

pub struct TxLazyChannel<T> {
    tx_done: Arc<aevent::Event>,
    is_busy_lock: Arc<RwLock<bool>>,
    channel_lock: Arc<Mutex<VecDeque<T>>>,
}

impl<T> TxLazyChannel<T> {
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
    pub fn done(&self, retv: T) -> Result<(), ()> {
        let mut busy = match self.is_busy_lock.write() {
            Ok(g) => g,
            Err(_poison) => unreachable!(FPOISON),
        };
        if *busy {
            *busy = false;
            let mut chan = match self.channel_lock.lock() {
                Ok(g) => g,
                Err(_poison) => unreachable!(FPOISON),
            };
            (*chan).push_back(retv);
            self.tx_done.notify(usize::MAX);
            Ok(())
        } else {
            Err(())
        }
    }
}

pub fn lazy_channel<T>() -> (TxLazyChannel<T>, RxLazyChannel<T>) {
    let is_busy_lock = Arc::new(RwLock::new(false));
    let channel_lock = Arc::new(Mutex::new(VecDeque::<T>::new()));
    let ev = Arc::new(aevent::Event::new());
    (
        TxLazyChannel {
            tx_done: Arc::clone(&ev),
            is_busy_lock: Arc::clone(&is_busy_lock),
            channel_lock: Arc::clone(&channel_lock),
        },
        RxLazyChannel {
            rx_done: ev,
            is_busy_lock,
            channel_lock,
        },
    )
}
