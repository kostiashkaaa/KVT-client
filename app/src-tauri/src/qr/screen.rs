//! «С экрана» для панели «+»: выделение области отдаём системному инструменту
//! снимков (тот же, что на Win+Shift+S, протокол `ms-screenclip:`) — он сам
//! справляется с несколькими мониторами и разным масштабом. Окно KVT на это время
//! сворачивается, чтобы не закрывать код и не попасть в кадр. Снимок инструмент
//! кладёт в буфер обмена, как и по Win+Shift+S (прежнее содержимое буфера он
//! заменяет); читает его и ищет код окно — тем же путём, что и «Вставить из
//! буфера». Здесь только дождаться снимка и вернуть окно.
//!
//! Клавиатуру и чужие окна не опрашиваем: отмену ловим по тому, что пользователь
//! сам вернул окно KVT, и по таймауту. Окно возвращается на любом выходе.

use super::clipboard;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

/// Адрес системного инструмента выделения области. Константа: окно своего адреса
/// передать не может.
const SNIP_URI: &str = "ms-screenclip:";
/// Пауза после сворачивания: без неё в замороженный кадр попадёт анимация.
const MINIMIZE_DELAY: Duration = Duration::from_millis(300);
/// Как часто смотрим на буфер и окно.
const POLL: Duration = Duration::from_millis(200);
/// Дольше не ждём: окно KVT не должно оставаться свёрнутым, если снимок бросили
/// крестиком на панели инструмента (отмену он нам не сообщает).
const TIMEOUT: Duration = Duration::from_secs(60);

/// Чем кончилось выделение. Сам снимок окно читает из буфера после `Captured`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenClip {
    /// В буфере появилась картинка.
    Captured,
    /// Пользователь вернул окно KVT, ничего не выделив.
    Cancelled,
    /// За минуту ничего не выделили.
    TimedOut,
    /// Инструмента снимков нет (Windows без него, например LTSC).
    Unsupported,
    /// Выделение уже идёт.
    Busy,
}

/// Что видно на очередном опросе.
#[derive(Debug, Clone, Copy)]
struct Poll {
    /// Номер изменения буфера обмена.
    seq: u32,
    /// В буфере есть картинка.
    image: bool,
    /// Окно KVT, свёрнутое нами, пользователь вернул сам.
    window_back: bool,
    /// Сколько прошло с запуска инструмента.
    waited: Duration,
}

/// Решение по итогам опроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Wait,
    Captured,
    Cancelled,
    TimedOut,
}

/// Чистое решение: снимок важнее всего (в том числе вернувшегося окна), затем
/// отмена возвратом окна, затем таймаут. Снимок — это картинка в буфере при номере,
/// отличном от номера на старте; сравниваем именно со стартом, а не с последним
/// виденным: картинка может появиться без нового номера (формат достроила система).
/// Чужой текст в буфере снимком не считается — просто ждём дальше.
fn decide(start_seq: u32, poll: &Poll) -> Step {
    if poll.seq != start_seq && poll.image {
        Step::Captured
    } else if poll.window_back {
        Step::Cancelled
    } else if poll.waited >= TIMEOUT {
        Step::TimedOut
    } else {
        Step::Wait
    }
}

/// Идёт ли выделение: второй запуск не нужен, а окно в ожидании не защита —
/// кнопку можно нажать из другого экземпляра страницы.
static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunningGuard;

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Возвращает окно KVT на любом выходе, в том числе при отмене самой команды.
struct RestoreWindow(AppHandle);

impl Drop for RestoreWindow {
    fn drop(&mut self) {
        crate::tray::show_main_window(&self.0);
    }
}

/// Выделить область экрана и дождаться снимка. Аргументов нет — адрес инструмента
/// окну не подменить.
#[tauri::command]
pub async fn qr_screen_clip(app: AppHandle) -> ScreenClip {
    if RUNNING.swap(true, Ordering::AcqRel) {
        return ScreenClip::Busy;
    }
    let _running = RunningGuard;
    run(&app).await
}

/// Запускает инструмент снимков из главного потока: `ShellExecute` ждёт COM, а он
/// есть там (так `open_link` и работает), но не на рабочих потоках tokio. `false` —
/// запустить не вышло.
async fn open_snipper(app: &AppHandle) -> bool {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let queued = app.run_on_main_thread(move || {
        let _ = tx.send(crate::about::shell_open(SNIP_URI).is_ok());
    });
    queued.is_ok() && rx.await.unwrap_or(false)
}

async fn run(app: &AppHandle) -> ScreenClip {
    let window = app.get_webview_window("main");
    let minimized = window.as_ref().is_some_and(|w| w.minimize().is_ok());
    let _restore = RestoreWindow(app.clone());
    if minimized {
        tokio::time::sleep(MINIMIZE_DELAY).await;
    }
    // Вернувшееся окно считаем отменой, только если мы его действительно свернули.
    let is_minimized = || {
        window
            .as_ref()
            .and_then(|w| w.is_minimized().ok())
            .unwrap_or(false)
    };
    let was_minimized = is_minimized();

    let start_seq = clipboard::sequence();
    if !open_snipper(app).await {
        return ScreenClip::Unsupported;
    }
    let started = Instant::now();
    loop {
        tokio::time::sleep(POLL).await;
        let poll = Poll {
            seq: clipboard::sequence(),
            image: clipboard::has_image(),
            window_back: was_minimized && !is_minimized(),
            waited: started.elapsed(),
        };
        match decide(start_seq, &poll) {
            Step::Wait => {}
            Step::Captured => return ScreenClip::Captured,
            Step::Cancelled => return ScreenClip::Cancelled,
            Step::TimedOut => return ScreenClip::TimedOut,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poll(seq: u32, image: bool, window_back: bool, secs: u64) -> Poll {
        Poll {
            seq,
            image,
            window_back,
            waited: Duration::from_secs(secs),
        }
    }

    #[test]
    fn waits_while_nothing_happens() {
        assert_eq!(decide(7, &poll(7, false, false, 5)), Step::Wait);
        // Картинка, лежавшая в буфере до снимка, номера не меняет — это не снимок.
        assert_eq!(decide(7, &poll(7, true, false, 5)), Step::Wait);
    }

    #[test]
    fn new_picture_in_the_clipboard_is_the_capture() {
        assert_eq!(decide(7, &poll(8, true, false, 5)), Step::Captured);
        // Окно вернулось в тот же опрос — снимок важнее отмены.
        assert_eq!(decide(7, &poll(9, true, true, 5)), Step::Captured);
        // И на самой границе таймаута.
        assert_eq!(decide(7, &poll(8, true, false, 60)), Step::Captured);
    }

    #[test]
    fn foreign_text_copy_is_not_a_capture() {
        assert_eq!(decide(7, &poll(8, false, false, 5)), Step::Wait);
        // Картинка появилась позже и без нового номера (формат достроила система) —
        // всё равно снимок: сравниваем со стартом, а не с последним виденным.
        assert_eq!(decide(7, &poll(8, true, false, 6)), Step::Captured);
    }

    #[test]
    fn returned_window_cancels() {
        assert_eq!(decide(7, &poll(7, false, true, 3)), Step::Cancelled);
        // Чужое копирование текста при вернувшемся окне — тоже отмена.
        assert_eq!(decide(7, &poll(8, false, true, 3)), Step::Cancelled);
        // Картинка, лежавшая в буфере с самого начала, окно не удерживает.
        assert_eq!(decide(7, &poll(7, true, true, 3)), Step::Cancelled);
    }

    #[test]
    fn times_out_after_a_minute() {
        assert_eq!(decide(7, &poll(7, false, false, 59)), Step::Wait);
        assert_eq!(decide(7, &poll(7, false, false, 60)), Step::TimedOut);
        assert_eq!(decide(7, &poll(7, false, false, 600)), Step::TimedOut);
    }

    #[test]
    fn serializes_as_snake_case_words() {
        let words: Vec<String> = [
            ScreenClip::Captured,
            ScreenClip::Cancelled,
            ScreenClip::TimedOut,
            ScreenClip::Unsupported,
            ScreenClip::Busy,
        ]
        .iter()
        .map(|v| serde_json::to_string(v).unwrap_or_default())
        .collect();
        assert_eq!(
            words,
            [
                "\"captured\"",
                "\"cancelled\"",
                "\"timed_out\"",
                "\"unsupported\"",
                "\"busy\""
            ]
        );
    }
}
