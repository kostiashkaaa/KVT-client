//! Значок трея рисуется кодом под размер значков Windows (16 px × масштаб экрана),
//! поэтому он чёткий на любом DPI и не зависит от файлов значка.
//!
//! Главное — цвет плитки с «K» из логотипа: серая — ничего не работает, синяя —
//! VPN, бирюзовая — zapret без VPN. Метка в углу появляется, только когда нужно
//! внимание: жёлтая пульсирует при подключении, жёлтая «!» — подключено, но сайты
//! не открываются, красная «!» — ошибка, kill switch закрыл интернет или служба
//! не запущена. Метка отделена прозрачным зазором и читается на любой панели.

use tauri::image::Image;

/// Что показывает значок.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Off,
    Connecting,
    Vpn,
    Zapret,
    /// Подключено, но данные через сервер не идут.
    Warn,
    /// Ошибка, kill switch закрыл интернет, службы нет.
    Error,
}

impl Tone {
    /// Значок меняется сам по себе (пульс метки) — нужен таймер.
    pub fn animated(self) -> bool {
        self == Tone::Connecting
    }
}

type Rgb = [u8; 3];

/// Фирменный синий (`--accent` в окне) и голубой уголок «K» из логотипа.
const BLUE: Rgb = [0x00, 0x5F, 0xB8];
const SKY: Rgb = [0x60, 0xCD, 0xFF];
const TEAL: Rgb = [0x00, 0x85, 0x78];
const MINT: Rgb = [0x8C, 0xF0, 0xDF];
/// Серый виден и на тёмной, и на светлой панели задач.
const GRAY: Rgb = [0x6E, 0x76, 0x82];
const GRAY_LIGHT: Rgb = [0xD2, 0xD6, 0xDC];
const WHITE: Rgb = [0xFF; 3];
const AMBER: Rgb = [0xF7, 0xA8, 0x1B];
const RED: Rgb = [0xE5, 0x3E, 0x3E];

/// Геометрия в долях стороны значка (по логотипу 128×128).
const CORNER: f32 = 0.22;
const STROKE: f32 = 0.056;
const BAR: [(f32, f32); 2] = [(0.336, 0.266), (0.336, 0.734)];
const CHEVRON: [(f32, f32); 3] = [(0.688, 0.266), (0.469, 0.5), (0.688, 0.734)];
const BADGE_R: f32 = 0.17;
const BADGE_GAP: f32 = 0.06;
/// Подвыборок на сторону пикселя: сглаживание краёв.
const SAMPLES: u32 = 4;

#[derive(Clone, Copy)]
enum Badge {
    /// Точка; число — доля радиуса (пульс).
    Dot(f32),
    Alert,
}

struct Look {
    tile: Rgb,
    chevron: Rgb,
    badge: Option<(Rgb, Badge)>,
}

fn look(tone: Tone, frame: u32) -> Look {
    let off = |badge| Look {
        tile: GRAY,
        chevron: GRAY_LIGHT,
        badge,
    };
    match tone {
        Tone::Off => off(None),
        // Кадры пульса: полная точка — уменьшенная.
        Tone::Connecting => off(Some((
            AMBER,
            Badge::Dot(if frame.is_multiple_of(2) { 1.0 } else { 0.62 }),
        ))),
        Tone::Error => off(Some((RED, Badge::Alert))),
        Tone::Vpn => Look {
            tile: BLUE,
            chevron: SKY,
            badge: None,
        },
        Tone::Zapret => Look {
            tile: TEAL,
            chevron: MINT,
            badge: None,
        },
        Tone::Warn => Look {
            tile: BLUE,
            chevron: SKY,
            badge: Some((AMBER, Badge::Alert)),
        },
    }
}

/// Значок `size`×`size` для состояния; `frame` — кадр анимации.
pub fn render(tone: Tone, frame: u32, size: u32) -> Image<'static> {
    let look = look(tone, frame);
    // «!» мельче 20 px сливается в пятно — там метка просто цветная точка.
    let glyph = size >= 20;
    #[allow(clippy::cast_precision_loss)]
    let (side, n) = (size as f32, SAMPLES as f32);
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            // Сумма с умноженной на прозрачность яркостью — без тёмной каймы.
            let mut acc = [0.0_f32; 4];
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    #[allow(clippy::cast_precision_loss)]
                    let p = (
                        (x as f32 + (sx as f32 + 0.5) / n) / side,
                        (y as f32 + (sy as f32 + 0.5) / n) / side,
                    );
                    if let Some(c) = sample(&look, glyph, p) {
                        for (a, v) in acc.iter_mut().zip(c) {
                            *a += f32::from(v);
                        }
                        acc[3] += 255.0;
                    }
                }
            }
            let count = n * n;
            let alpha = acc[3] / count;
            for v in &acc[..3] {
                let c = if alpha > 0.0 { v / acc[3] * 255.0 } else { 0.0 };
                rgba.push(to_u8(c));
            }
            rgba.push(to_u8(alpha));
        }
    }
    Image::new_owned(rgba, size, size)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn to_u8(v: f32) -> u8 {
    v.round().clamp(0.0, 255.0) as u8
}

/// Цвет точки значка или `None` — прозрачно.
fn sample(look: &Look, glyph: bool, p: (f32, f32)) -> Option<Rgb> {
    if let Some((color, badge)) = look.badge {
        let center = (1.0 - BADGE_R, 1.0 - BADGE_R);
        let d = dist(p, center);
        let radius = match badge {
            Badge::Dot(k) => BADGE_R * k,
            Badge::Alert => BADGE_R,
        };
        if d <= radius {
            return Some(match badge {
                Badge::Alert if glyph && in_alert(p, center) => WHITE,
                _ => color,
            });
        }
        if d <= BADGE_R + BADGE_GAP {
            return None;
        }
    }
    if !in_tile(p) {
        return None;
    }
    if segment_dist(p, BAR[0], BAR[1]) <= STROKE {
        return Some(WHITE);
    }
    if segment_dist(p, CHEVRON[0], CHEVRON[1]) <= STROKE
        || segment_dist(p, CHEVRON[1], CHEVRON[2]) <= STROKE
    {
        return Some(look.chevron);
    }
    Some(look.tile)
}

/// «!» в метке: черта и точка.
fn in_alert(p: (f32, f32), (cx, cy): (f32, f32)) -> bool {
    let w = BADGE_R * 0.16;
    segment_dist(p, (cx, cy - BADGE_R * 0.5), (cx, cy + BADGE_R * 0.1)) <= w
        || dist(p, (cx, cy + BADGE_R * 0.5)) <= w * 1.1
}

/// Плитка со скруглёнными углами на весь значок.
fn in_tile((x, y): (f32, f32)) -> bool {
    let nearest = (x.clamp(CORNER, 1.0 - CORNER), y.clamp(CORNER, 1.0 - CORNER));
    dist((x, y), nearest) <= CORNER
}

fn dist(a: (f32, f32), b: (f32, f32)) -> f32 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

fn segment_dist(p: (f32, f32), a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let len = dx * dx + dy * dy;
    let t = if len > 0.0 {
        (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / len).clamp(0.0, 1.0)
    } else {
        0.0
    };
    dist(p, (a.0 + t * dx, a.1 + t * dy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn px(img: &Image<'_>, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * img.width() + x) * 4) as usize;
        let s = &img.rgba()[i..i + 4];
        [s[0], s[1], s[2], s[3]]
    }

    #[test]
    fn tile_color_tells_state() {
        for size in [16, 20, 24, 32] {
            let vpn = render(Tone::Vpn, 0, size);
            assert_eq!((vpn.width(), vpn.height()), (size, size));
            // Левый край посередине — плитка, угол — прозрачный.
            assert_eq!(px(&vpn, 1, size / 2), [BLUE[0], BLUE[1], BLUE[2], 255]);
            assert_eq!(px(&vpn, 0, 0)[3], 0);
            let off = render(Tone::Off, 0, size);
            assert_eq!(px(&off, 1, size / 2), [GRAY[0], GRAY[1], GRAY[2], 255]);
            let zapret = render(Tone::Zapret, 0, size);
            assert_eq!(px(&zapret, 1, size / 2), [TEAL[0], TEAL[1], TEAL[2], 255]);
        }
    }

    #[test]
    fn badge_only_when_attention_needed() {
        let size = 32;
        let c = (size as f32 * (1.0 - BADGE_R)) as u32;
        // Метка: у ошибки красная с белой «!» посередине, у пульса — жёлтая точка.
        let error = render(Tone::Error, 0, size);
        assert_eq!(px(&error, c - 3, c)[..3], RED);
        assert_eq!(px(&error, c, c - 1)[..3], WHITE);
        // На 16 px «!» не рисуется.
        let small = render(Tone::Error, 0, 16);
        assert_eq!(px(&small, 13, 13)[..3], RED);
        let warn = render(Tone::Warn, 0, size);
        assert_eq!(px(&warn, c - 3, c)[..3], AMBER);
        assert_eq!(px(&render(Tone::Connecting, 0, size), c, c)[..3], AMBER);
        // Без метки угол — плитка.
        assert_eq!(px(&render(Tone::Vpn, 0, size), c - 3, c)[..3], BLUE);
        // Зазор между меткой и плиткой прозрачный.
        let gap = (size as f32 * (1.0 - 2.0 * BADGE_R - BADGE_GAP / 2.0)) as u32;
        assert_eq!(px(&error, gap, c)[3], 0);
    }

    #[test]
    fn connecting_pulses() {
        let a = render(Tone::Connecting, 0, 32);
        let b = render(Tone::Connecting, 1, 32);
        assert_ne!(a.rgba(), b.rgba());
        assert!(Tone::Connecting.animated() && !Tone::Vpn.animated());
    }
}
