//! Распознавание QR-кода на картинке — для панели «+»: ключ или ссылку подписки
//! можно взять с экрана телефона или из файла. Работает локально, без сети.
//! Картинку в яркости (по байту на пиксель) отдаёт окно: файл, буфер обмена или
//! область экрана оно разбирает само. Здесь — проверка размеров и сам поиск кода.
//!
//! Картинка — недоверенный ввод, а текст кода — секрет (ключ сервера или ссылка с
//! токеном): он уходит только в поле добавления, в журнал и ошибки не попадает —
//! `Debug` у итога его скрывает.

use rqrr::PreparedImage;
use serde::Serialize;
use std::fmt;

/// Сторона картинки не больше: окно уменьшает её заранее, предел — защита от
/// чужого вызова и от нехватки памяти.
pub const MAX_SIDE: usize = 8192;
/// Пикселей не больше: поиск держит несколько копий картинки.
pub const MAX_PIXELS: usize = 16_000_000;
/// Сколько кодов на одной картинке разбираем: дальше — это уже не ключи.
const MAX_CODES: usize = 8;

/// Итог поиска. Код итога окно сравнивает, текст для пользователя — его дело.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// Коды прочитаны: тексты по порядку на картинке, без повторов.
    Found { texts: Vec<String> },
    /// Кода на картинке нет.
    NotFound,
    /// Код виден, но не читается: размыт, мелкий или повреждён.
    Unreadable,
    /// Размеры не подходят: нулевая сторона, больше предела или длина данных не сходится.
    BadImage,
}

impl fmt::Debug for Outcome {
    /// Тексты — секрет: в отладочный вывод попадает только их число.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found { texts } => write!(f, "Found({} шт.)", texts.len()),
            Self::NotFound => f.write_str("NotFound"),
            Self::Unreadable => f.write_str("Unreadable"),
            Self::BadImage => f.write_str("BadImage"),
        }
    }
}

/// Ищет QR-коды на картинке `width`×`height`, `gray` — яркость по строкам,
/// 0 — чёрный, 255 — белый. Сначала как есть, затем в негативе: светлый код на
/// тёмном фоне (тёмная тема, скриншот с инверсией) обычным поиском не находится.
pub fn decode(width: usize, height: usize, gray: &[u8]) -> Outcome {
    if !size_ok(width, height, gray.len()) {
        return Outcome::BadImage;
    }
    let mut seen = false;
    for invert in [false, true] {
        let (texts, found) = pass(width, height, gray, invert);
        if !texts.is_empty() {
            return Outcome::Found { texts };
        }
        seen |= found > 0;
    }
    if seen {
        Outcome::Unreadable
    } else {
        Outcome::NotFound
    }
}

/// Размеры в пределах и данных ровно на всю картинку.
fn size_ok(width: usize, height: usize, len: usize) -> bool {
    if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
        return false;
    }
    width
        .checked_mul(height)
        .is_some_and(|pixels| pixels <= MAX_PIXELS && pixels == len)
}

/// Один проход поиска: прочитанные тексты и сколько кодов нашлось.
fn pass(width: usize, height: usize, gray: &[u8], invert: bool) -> (Vec<String>, usize) {
    let mut image = PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let value = gray.get(y * width + x).copied().unwrap_or(255);
        if invert {
            255 - value
        } else {
            value
        }
    });
    let grids = image.detect_grids();
    let found = grids.len();
    let mut texts: Vec<String> = Vec::new();
    for grid in grids.into_iter().take(MAX_CODES) {
        // Не читается — этот код пропускаем, остальные могут быть в порядке.
        if let Ok((_, text)) = grid.decode() {
            let text = text.trim().to_string();
            if !text.is_empty() && !texts.contains(&text) {
                texts.push(text);
            }
        }
    }
    (texts, found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use qrcode::{Color, QrCode};

    /// Картинка с кодом: белое поле в 4 модуля, масштаб `scale` пикселей на модуль.
    struct Img {
        width: usize,
        height: usize,
        gray: Vec<u8>,
    }

    fn render(text: &str, scale: usize) -> Img {
        let code = QrCode::new(text.as_bytes()).expect("текст помещается в код");
        let modules = code.width();
        let side = (modules + 8) * scale;
        let colors = code.to_colors();
        let mut gray = vec![255u8; side * side];
        for my in 0..modules {
            for mx in 0..modules {
                if colors[my * modules + mx] == Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            gray[((my + 4) * scale + dy) * side + (mx + 4) * scale + dx] = 0;
                        }
                    }
                }
            }
        }
        Img {
            width: side,
            height: side,
            gray,
        }
    }

    fn decode_img(img: &Img) -> Outcome {
        decode(img.width, img.height, &img.gray)
    }

    fn texts(outcome: Outcome) -> Vec<String> {
        match outcome {
            Outcome::Found { texts } => texts,
            other => panic!("ожидался код, получено {other:?}"),
        }
    }

    /// Детерминированный «шум» без внешних источников случайности.
    fn noise(len: usize, mut seed: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (seed >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn reads_a_key_link() {
        let link =
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality#Server";
        assert_eq!(texts(decode_img(&render(link, 4))), vec![link.to_string()]);
    }

    #[test]
    fn reads_cyrillic_and_long_subscription_link() {
        let name = "vless://id@example.com:443#Нидерланды 🇳🇱";
        assert_eq!(texts(decode_img(&render(name, 4))), vec![name.to_string()]);

        let long = format!("https://example.com/sub/{}", "a1b2c3d4".repeat(60));
        assert_eq!(texts(decode_img(&render(&long, 3))), vec![long]);
    }

    #[test]
    fn reads_light_code_on_dark_background() {
        let link = "trojan://secret@example.com:443#Night";
        let mut img = render(link, 4);
        for px in &mut img.gray {
            *px = 255 - *px;
        }
        assert_eq!(texts(decode_img(&img)), vec![link.to_string()]);
    }

    #[test]
    fn reads_two_codes_in_one_picture_and_skips_repeats() {
        let (a, b) = ("vless://a@example.com:443#A", "vless://b@example.com:443#B");
        let (left, right) = (render(a, 4), render(b, 4));
        let width = left.width + right.width + 40;
        let height = left.height.max(right.height) + 20;
        let mut gray = vec![255u8; width * height];
        for (img, x0) in [(&left, 10), (&right, left.width + 30)] {
            for y in 0..img.height {
                let row = &img.gray[y * img.width..(y + 1) * img.width];
                gray[(y + 10) * width + x0..(y + 10) * width + x0 + img.width].copy_from_slice(row);
            }
        }
        let found = texts(decode(width, height, &gray));
        assert_eq!(found.len(), 2);
        assert!(found.contains(&a.to_string()) && found.contains(&b.to_string()));

        // Один и тот же код дважды — один текст.
        let mut twice = vec![255u8; width * height];
        for (img, x0) in [(&left, 10), (&left, left.width + 30)] {
            for y in 0..img.height {
                let row = &img.gray[y * img.width..(y + 1) * img.width];
                twice[(y + 10) * width + x0..(y + 10) * width + x0 + img.width]
                    .copy_from_slice(row);
            }
        }
        assert_eq!(texts(decode(width, height, &twice)), vec![a.to_string()]);
    }

    #[test]
    fn reads_code_on_a_busy_background() {
        // Код не на всю картинку, вокруг — серый фон с полосами, как скриншот окна.
        let link = "ss://YWVzLTI1Ni1nY206cGFzcw@example.com:8388#Home";
        let code = render(link, 5);
        let (width, height) = (code.width + 300, code.height + 200);
        let mut gray = vec![200u8; width * height];
        for (i, px) in gray.iter_mut().enumerate() {
            if (i / width) % 17 < 3 {
                *px = 140;
            }
        }
        for y in 0..code.height {
            let row = &code.gray[y * code.width..(y + 1) * code.width];
            gray[(y + 100) * width + 150..(y + 100) * width + 150 + code.width]
                .copy_from_slice(row);
        }
        assert_eq!(texts(decode(width, height, &gray)), vec![link.to_string()]);
    }

    #[test]
    fn blank_and_noisy_pictures_have_no_code() {
        assert_eq!(decode(64, 64, &vec![255u8; 64 * 64]), Outcome::NotFound);
        assert_eq!(decode(64, 64, &vec![0u8; 64 * 64]), Outcome::NotFound);
        let noisy = decode(300, 300, &noise(300 * 300, 7));
        assert!(
            matches!(noisy, Outcome::NotFound | Outcome::Unreadable),
            "{noisy:?}"
        );
    }

    #[test]
    fn a_destroyed_code_is_not_read_as_something_else() {
        let mut img = render("vless://id@example.com:443#Broken", 4);
        // Данные внутри перебиты шумом, три угловых «глаза» остались.
        let mid = img.width / 4..img.width * 3 / 4;
        let junk = noise(img.width * img.height, 99);
        for y in mid.clone() {
            for x in mid.clone() {
                img.gray[y * img.width + x] = junk[y * img.width + x];
            }
        }
        let outcome = decode_img(&img);
        assert!(
            matches!(outcome, Outcome::NotFound | Outcome::Unreadable),
            "{outcome:?}"
        );
    }

    #[test]
    fn rejects_bad_sizes() {
        assert_eq!(decode(0, 10, &[]), Outcome::BadImage);
        assert_eq!(decode(10, 0, &[]), Outcome::BadImage);
        // Длина данных не сходится с размерами.
        assert_eq!(decode(10, 10, &[255; 99]), Outcome::BadImage);
        assert_eq!(decode(10, 10, &[255; 101]), Outcome::BadImage);
        // Больше предела по стороне и по числу пикселей, переполнение умножения.
        assert_eq!(decode(MAX_SIDE + 1, 1, &[]), Outcome::BadImage);
        assert_eq!(decode(MAX_SIDE, MAX_SIDE, &[]), Outcome::BadImage);
        assert_eq!(decode(usize::MAX, 2, &[]), Outcome::BadImage);
    }

    #[test]
    fn debug_output_hides_the_text() {
        let secret = "vless://секретный-ключ@example.com:443#X";
        let found = Outcome::Found {
            texts: vec![secret.to_string()],
        };
        let shown = format!("{found:?}");
        assert!(
            !shown.contains("секретный") && !shown.contains("vless"),
            "{shown}"
        );
    }

    #[test]
    fn serializes_with_kind_for_the_window() {
        let found = Outcome::Found {
            texts: vec!["x".into()],
        };
        assert_eq!(
            serde_json::to_string(&found).unwrap_or_default(),
            r#"{"kind":"found","texts":["x"]}"#
        );
        assert_eq!(
            serde_json::to_string(&Outcome::NotFound).unwrap_or_default(),
            r#"{"kind":"not_found"}"#
        );
    }

    proptest! {
        // Случайные байты любой формы: ни паники, ни выдуманного текста. В релизе
        // паника — это `abort` всего окна, поэтому проверяем её отсутствие здесь.
        #[test]
        fn random_pictures_never_panic(
            width in 1usize..80,
            height in 1usize..80,
            seed in any::<u32>(),
            threshold in 0u8..=255,
        ) {
            let gray: Vec<u8> = noise(width * height, seed)
                .into_iter()
                .map(|v| if v > threshold { 255 } else { 0 })
                .collect();
            let outcome = decode(width, height, &gray);
            prop_assert!(!matches!(outcome, Outcome::BadImage));
        }

        #[test]
        fn random_lengths_are_rejected_or_handled(
            width in 0usize..40,
            height in 0usize..40,
            len in 0usize..2000,
        ) {
            let _ = decode(width, height, &noise(len, 1));
        }

        // Код с испорченными пикселями (как плохая фотография) либо читается
        // правильно, либо не читается — другого текста не бывает.
        #[test]
        fn damaged_code_gives_the_right_text_or_nothing(
            hits in proptest::collection::vec((0usize..400, 0usize..400), 0..60)
        ) {
            let link = "vless://id@example.com:443#Damaged";
            let mut img = render(link, 4);
            for (x, y) in hits {
                let (x, y) = (x % img.width, y % img.height);
                img.gray[y * img.width + x] = 255 - img.gray[y * img.width + x];
            }
            if let Outcome::Found { texts } = decode_img(&img) {
                prop_assert_eq!(texts, vec![link.to_string()]);
            }
        }
    }
}
