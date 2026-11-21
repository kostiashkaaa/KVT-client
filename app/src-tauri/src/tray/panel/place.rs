//! Где встаёт мини-панель и когда клик по значку её не открывает. Чистые функции без
//! окон и событий — их проверяют тесты.

use std::time::{Duration, Instant};

/// Прямоугольник в физических пикселях экрана.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tray) struct Area {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Area {
    fn right(self) -> i32 {
        self.x + self.w
    }

    fn bottom(self) -> i32 {
        self.y + self.h
    }

    fn center(self) -> (i32, i32) {
        (self.x + self.w / 2, self.y + self.h / 2)
    }
}

/// У какого края рабочей области стоит панель задач.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Bottom,
    Top,
    Right,
    Left,
}

/// Край, у которого значок: ближайший к его центру. Панель задач лежит вне рабочей
/// области, поэтому для значка на ней расстояние до своего края отрицательное. Значок
/// в скрытой области («^») стоит внутри рабочей области, у того же края. При равенстве —
/// снизу, как чаще всего.
fn edge_of(icon: Area, work: Area) -> Edge {
    let (cx, cy) = icon.center();
    [
        (work.bottom() - cy, Edge::Bottom),
        (cy - work.y, Edge::Top),
        (work.right() - cx, Edge::Right),
        (cx - work.x, Edge::Left),
    ]
    .into_iter()
    .min_by_key(|(distance, _)| *distance)
    .map_or(Edge::Bottom, |(_, edge)| edge)
}

/// Верхний левый угол панели размером `size` (ширина, высота): у края, откуда нажат
/// значок, с отступом `margin`; вдоль края — против значка, но не за пределы рабочей
/// области. Если панель не помещается, она прижата к верхнему левому углу.
pub(super) fn panel_position(icon: Area, work: Area, size: (i32, i32), margin: i32) -> (i32, i32) {
    let (w, h) = size;
    let (cx, cy) = icon.center();
    let fit = |v: i32, lo: i32, hi: i32| v.min(hi).max(lo);
    let along_x = fit(cx - w / 2, work.x + margin, work.right() - w - margin);
    let along_y = fit(cy - h / 2, work.y + margin, work.bottom() - h - margin);
    match edge_of(icon, work) {
        Edge::Bottom => (
            along_x,
            fit(work.bottom() - h - margin, work.y + margin, i32::MAX),
        ),
        Edge::Top => (along_x, work.y + margin),
        Edge::Right => (
            fit(work.right() - w - margin, work.x + margin, i32::MAX),
            along_y,
        ),
        Edge::Left => (work.x + margin, along_y),
    }
}

/// Высота панели: не выше рабочей области с отступами и не ниже одного пикселя.
pub(super) fn fit_height(wanted: i32, work: Area, margin: i32) -> i32 {
    wanted.min(work.h - 2 * margin).max(1)
}

/// Сколько после скрытия панели из-за потери фокуса клик по значку её не открывает.
const REOPEN_GUARD: Duration = Duration::from_millis(300);

/// Нажатие на значок закрывает панель, а не открывает её. Клик по значку сначала
/// отнимает у панели фокус, она скрывается, и только потом приходит сам клик: без этой
/// защиты он открыл бы панель снова, и закрыть её значком было бы нельзя.
pub(super) fn click_closes(visible: bool, blurred_at: Option<Instant>, now: Instant) -> bool {
    visible
        || blurred_at.is_some_and(|at| {
            now.checked_duration_since(at)
                .is_some_and(|ago| ago < REOPEN_GUARD)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn area(x: i32, y: i32, w: i32, h: i32) -> Area {
        Area { x, y, w, h }
    }

    /// Экран 1920×1080, панель задач 48 px.
    const MARGIN: i32 = 12;
    const SIZE: (i32, i32) = (360, 540);

    #[test]
    fn taskbar_at_the_bottom_puts_the_panel_above_it() {
        let work = area(0, 0, 1920, 1032);
        let icon = area(1700, 1040, 16, 16);
        let (x, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(y, 1032 - 540 - MARGIN);
        // Против значка: центр значка — центр панели.
        assert_eq!(x, 1708 - 180);
    }

    #[test]
    fn taskbar_at_the_top_puts_the_panel_below_it() {
        let work = area(0, 48, 1920, 1032);
        let icon = area(1700, 16, 16, 16);
        let (_, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(y, 48 + MARGIN);
    }

    #[test]
    fn taskbar_on_the_right_puts_the_panel_to_its_left() {
        let work = area(0, 0, 1872, 1080);
        let icon = area(1890, 500, 16, 16);
        let (x, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(x, 1872 - 360 - MARGIN);
        assert_eq!(y, 508 - 270);
        // Значок у нижнего угла: панель прижата к низу рабочей области.
        let (_, y) = panel_position(area(1890, 1060, 16, 16), work, SIZE, MARGIN);
        assert_eq!(y, 1080 - 540 - MARGIN);
    }

    #[test]
    fn taskbar_on_the_left_puts_the_panel_to_its_right() {
        let work = area(48, 0, 1872, 1080);
        let icon = area(16, 1000, 16, 16);
        let (x, _) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(x, 48 + MARGIN);
    }

    #[test]
    fn icon_in_the_corner_keeps_the_panel_inside() {
        let work = area(0, 0, 1920, 1032);
        // Значок у самого правого края: панель не вылезает за него.
        let (x, _) = panel_position(area(1904, 1040, 16, 16), work, SIZE, MARGIN);
        assert_eq!(x, 1920 - 360 - MARGIN);
        // И у самого левого (панель задач у левого края снизу).
        let (x, _) = panel_position(area(0, 1040, 16, 16), work, SIZE, MARGIN);
        assert_eq!(x, MARGIN);
    }

    #[test]
    fn second_monitor_to_the_left_has_negative_coordinates() {
        // Левый монитор: x от -1920, панель задач снизу.
        let work = area(-1920, 0, 1920, 1032);
        let icon = area(-220, 1040, 16, 16);
        let (x, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(y, 1032 - 540 - MARGIN);
        assert_eq!(x, -212 - 180);
        // Значок у правого края левого монитора не вылезает на соседний.
        let (x, _) = panel_position(area(-16, 1040, 16, 16), work, SIZE, MARGIN);
        assert_eq!(x, 0 - 360 - MARGIN);
    }

    #[test]
    fn second_monitor_above_the_first_has_negative_y() {
        // Верхний монитор: y от -1080, панель задач снизу него.
        let work = area(0, -1080, 1920, 1032);
        let icon = area(1700, -40, 16, 16);
        let (_, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(y, -48 - 540 - MARGIN);
    }

    #[test]
    fn overflow_icon_inside_the_work_area_stays_at_the_bottom() {
        // Значок в окошке «^»: над панелью задач, внутри рабочей области.
        let work = area(0, 0, 1920, 1032);
        let icon = area(1800, 960, 16, 16);
        let (_, y) = panel_position(icon, work, SIZE, MARGIN);
        assert_eq!(y, 1032 - 540 - MARGIN);
    }

    #[test]
    fn a_panel_taller_than_the_screen_sticks_to_the_top() {
        let work = area(0, 0, 1920, 500);
        let (_, y) = panel_position(area(1700, 508, 16, 16), work, (360, 900), MARGIN);
        assert_eq!(y, MARGIN);
    }

    #[test]
    fn height_never_exceeds_the_work_area() {
        let work = area(0, 0, 1920, 600);
        assert_eq!(fit_height(540, work, MARGIN), 540);
        assert_eq!(fit_height(900, work, MARGIN), 600 - 2 * MARGIN);
        assert_eq!(fit_height(0, work, MARGIN), 1);
    }

    #[test]
    fn click_on_the_icon_closes_a_visible_or_just_hidden_panel() {
        let now = Instant::now();
        assert!(click_closes(true, None, now));
        // Фокус ушёл при нажатии, панель скрылась 40 мс назад, клик пришёл следом.
        assert!(click_closes(
            false,
            Some(now - Duration::from_millis(40)),
            now
        ));
        // Скрылась давно (клик мимо, Esc) — значок открывает её заново.
        assert!(!click_closes(
            false,
            Some(now - Duration::from_secs(2)),
            now
        ));
        assert!(!click_closes(false, None, now));
        // Часы идут назад — не паникуем и не считаем «только что».
        assert!(!click_closes(
            false,
            Some(now + Duration::from_secs(1)),
            now
        ));
    }
}
