/// smoltcp `Device` backed by the Yggdrasil `ReadWriteCloser`.
///
/// Incoming IPv6 packets (from Yggdrasil) are pushed into `rx_queue`.
/// Outgoing IPv6 packets (from smoltcp) are collected in `tx_queue` and
/// sent to Yggdrasil by the poll loop.
use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub struct YggDevice {
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub mtu: usize,
}

impl YggDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(64),
            tx_queue: VecDeque::with_capacity(64),
            mtu,
        }
    }
}

// ── smoltcp tokens ────────────────────────────────────────────────────────────

pub struct YggRxToken(Vec<u8>);

pub struct YggTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for YggRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

impl<'a> TxToken for YggTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for YggDevice {
    type RxToken<'a> = YggRxToken where Self: 'a;
    type TxToken<'a> = YggTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx_queue.pop_front()?;
        Some((YggRxToken(pkt), YggTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(YggTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
