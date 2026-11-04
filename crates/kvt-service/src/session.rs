//! Сеанс — от «Подключить» до «Отключить»: время и трафик через адаптер KVT.
//!
//! Счётчики адаптера обнуляются, когда ядро пересоздаёт его (замена сервера,
//! переподключение после сна), поэтому сеанс складывает приращения: если новое
//! значение меньше прежнего — адаптер новый, и считается всё его значение.

use kvt_core::ipc::Session as Info;
use std::time::Instant;

pub struct Session {
    started: Instant,
    rx: u64,
    tx: u64,
    /// Последнее прочитанное значение счётчиков адаптера.
    last: Option<(u64, u64)>,
    /// Был ли адаптер хоть раз за сеанс (в режиме Zapret его нет).
    tunnel: bool,
}

impl Session {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            rx: 0,
            tx: 0,
            last: None,
            tunnel: false,
        }
    }

    /// Учитывает очередное значение счётчиков (`None` — адаптера сейчас нет).
    pub fn absorb(&mut self, counters: Option<(u64, u64)>) {
        let Some((rx, tx)) = counters else {
            self.last = None;
            return;
        };
        self.tunnel = true;
        let (drx, dtx) = match self.last {
            Some((lrx, ltx)) if rx >= lrx && tx >= ltx => (rx - lrx, tx - ltx),
            _ => (rx, tx),
        };
        self.rx = self.rx.saturating_add(drx);
        self.tx = self.tx.saturating_add(dtx);
        self.last = Some((rx, tx));
    }

    /// Читает счётчики адаптера KVT.
    pub fn sample(&mut self) {
        self.absorb(crate::win::adapter_octets(kvt_core::compile::TUN_INTERFACE));
    }

    pub fn info(&self) -> Info {
        Info {
            secs: self.started.elapsed().as_secs(),
            rx: self.tunnel.then_some(self.rx),
            tx: self.tunnel.then_some(self.tx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_increments_and_survives_new_adapter() {
        let mut s = Session::new();
        s.absorb(Some((100, 10)));
        s.absorb(Some((250, 30)));
        // Ядро пересоздало адаптер: счётчики с нуля.
        s.absorb(None);
        s.absorb(Some((40, 5)));
        s.absorb(Some((60, 9)));
        let info = s.info();
        assert_eq!((info.rx, info.tx), (Some(310), Some(39)));
    }

    #[test]
    fn counter_drop_without_gap_means_new_adapter() {
        let mut s = Session::new();
        s.absorb(Some((500, 50)));
        s.absorb(Some((20, 2)));
        assert_eq!(s.info().rx, Some(520));
    }

    #[test]
    fn zapret_session_has_no_traffic() {
        let mut s = Session::new();
        s.absorb(None);
        let info = s.info();
        assert_eq!((info.rx, info.tx), (None, None));
    }
}
