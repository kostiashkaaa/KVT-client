//! Флаг страны в названии сервера. Провайдеры пишут флаг эмодзи (🇳🇱), но Windows
//! не рисует эмодзи-флаги — вместо них видны буквы. Поэтому флаг вынимается из
//! названия как код страны, а интерфейс рисует его картинкой.
//!
//! Как в обычных клиентах: флаг сервера — первый флаг-эмодзи в названии. Если
//! название с него начинается, он уходит из текста; всё остальное («→🇪🇪 для wifi ·
//! via RU») остаётся как в подписке, а прочие флаги интерфейс рисует прямо в тексте.

const RI_START: u32 = 0x1F1E6;
const RI_END: u32 = 0x1F1FF;
const VS16: char = '\u{FE0F}';

/// Коды, для которых в интерфейсе есть картинка (flag-icons, 4×3, двухбуквенные).
const KNOWN: &str = "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi \
    bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cp cr cu cv cw \
    cx cy cz de dg dj dk dm do dz ec ee eg eh er es et eu fi fj fk fm fo fr ga gb gd ge gf gg \
    gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu ic id ie il im in io iq ir is it \
    je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me \
    mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu \
    nz om pa pc pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh \
    si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz \
    ua ug um un us uy uz va vc ve vg vi vn vu wf ws xk ye yt za zm zw";

/// Флаг, разобранный из названия сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFlags {
    /// Страна по первому флагу в названии (`"ru"`).
    pub flag: Option<String>,
    /// Название как в подписке, без ведущего флага.
    pub name: String,
}

fn regional(c: char) -> Option<char> {
    let code = u32::from(c);
    (RI_START..=RI_END)
        .contains(&code)
        .then(|| char::from(b'a' + (code - RI_START) as u8))
}

fn known(code: &str) -> bool {
    KNOWN.split_whitespace().any(|k| k == code)
}

/// Флаг-эмодзи в начале `chars`: код страны (`"ru"`), даже если картинки для него нет.
fn flag_at(chars: &[char]) -> Option<String> {
    let a = regional(*chars.first()?)?;
    let b = regional(*chars.get(1)?)?;
    Some(format!("{a}{b}"))
}

/// Разделители между ведущим флагом и названием: «🇩🇰 | для wifi».
fn is_separator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '|' | '·' | ',' | ':' | VS16)
}

pub fn split_flags(name: &str) -> ServerFlags {
    let trimmed = name.trim();
    let chars: Vec<char> = trimmed.chars().collect();

    // Первый флаг, для которого есть картинка: незнакомая пара индикаторов — не страна.
    let mut first = None;
    let mut i = 0;
    while i < chars.len() {
        match flag_at(&chars[i..]) {
            Some(code) if known(&code) => {
                first = Some((i, code));
                break;
            }
            Some(_) => i += 2,
            None => i += 1,
        }
    }

    let Some((at, flag)) = first else {
        return ServerFlags {
            flag: None,
            name: trimmed.to_owned(),
        };
    };
    // Флаг посреди названия («Fast 🇩🇪 Frankfurt») остаётся в тексте: это часть названия.
    let rest: String = if at == 0 {
        chars.iter().skip(2).collect()
    } else {
        trimmed.to_owned()
    };
    let rest = rest.trim_start_matches(is_separator).trim_end();
    // Название из одного флага — показываем его же, а не пустую строку.
    let name = if rest.is_empty() { trimmed } else { rest };
    ServerFlags {
        flag: Some(flag),
        name: name.to_owned(),
    }
}

/// Код страны по первому флагу и название без ведущего флага.
pub fn split_flag(name: &str) -> (Option<String>, String) {
    let f = split_flags(name);
    (f.flag, f.name)
}

/// Название для трея и уведомлений, где картинку не нарисовать: флаги-эмодзи
/// заменяются кодами стран — «RU→EE для wifi · via RU». Windows всё равно показала
/// бы их буквами, но в рамках и вплотную к тексту.
pub fn plain_name(name: &str) -> String {
    let chars: Vec<char> = name.trim().chars().collect();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < chars.len() {
        if let Some(code) = flag_at(&chars[i..]) {
            out.push_str(&code.to_ascii_uppercase());
            i += 2;
        } else {
            if chars[i] != VS16 && regional(chars[i]).is_none() {
                out.push(chars[i]);
            }
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want(flag: Option<&str>, name: &str) -> (Option<String>, String) {
        (flag.map(Into::into), name.into())
    }

    #[test]
    fn leading_flag() {
        assert_eq!(split_flag("🇳🇱 Нидерланды"), want(Some("nl"), "Нидерланды"));
        assert_eq!(
            split_flag("🇩🇰 | DK для wifi"),
            want(Some("dk"), "DK для wifi")
        );
        assert_eq!(
            split_flag("🇪🇪\u{FE0F} для wifi"),
            want(Some("ee"), "для wifi")
        );
        assert_eq!(split_flag("  🇷🇺Москва "), want(Some("ru"), "Москва"));
    }

    #[test]
    fn first_flag_wins_rest_of_name_stays() {
        // Цепочка: флаг — первый (страна входа), остальное — как в подписке.
        assert_eq!(
            split_flag("🇷🇺→🇪🇪 для wifi · via RU"),
            want(Some("ru"), "→🇪🇪 для wifi · via RU")
        );
        assert_eq!(
            split_flag("🇷🇺 🇪🇪 для wifi · прямой"),
            want(Some("ru"), "🇪🇪 для wifi · прямой")
        );
    }

    #[test]
    fn flag_in_the_middle_stays_in_name() {
        assert_eq!(
            split_flag("Fast 🇩🇪 Frankfurt ⚡"),
            want(Some("de"), "Fast 🇩🇪 Frankfurt ⚡")
        );
    }

    #[test]
    fn words_are_not_flags() {
        // Код страны словом — обычный текст, как в других клиентах.
        assert_eq!(split_flag("DK для wifi"), want(None, "DK для wifi"));
        assert_eq!(split_flag("Таллин via RU"), want(None, "Таллин via RU"));
    }

    #[test]
    fn no_flag() {
        assert_eq!(split_flag("  Server 1 "), want(None, "Server 1"));
        assert_eq!(split_flag("🚀 Turbo"), want(None, "🚀 Turbo"));
        assert_eq!(
            split_flag("📶 LTE сервера 👇"),
            want(None, "📶 LTE сервера 👇")
        );
        assert_eq!(split_flag(""), want(None, ""));
    }

    #[test]
    fn broken_indicators() {
        // Одинокий индикатор и пара без страны (🇽🇽) — не флаг, текст не теряется.
        assert_eq!(split_flag("\u{1F1F7} x"), want(None, "\u{1F1F7} x"));
        assert_eq!(split_flag("🇽🇽 тест"), want(None, "🇽🇽 тест"));
        assert_eq!(split_flag("🇽🇽 🇳🇱 тест"), want(Some("nl"), "🇽🇽 🇳🇱 тест"));
    }

    #[test]
    fn only_flag_keeps_something_readable() {
        assert_eq!(split_flag("🇯🇵"), want(Some("jp"), "🇯🇵"));
    }

    #[test]
    fn every_known_code_round_trips() {
        for code in KNOWN.split_whitespace() {
            let emoji: String = code
                .bytes()
                .map(|b| char::from_u32(RI_START + u32::from(b - b'a')).unwrap())
                .collect();
            assert_eq!(
                split_flag(&format!("{emoji} x")),
                want(Some(code), "x"),
                "{code}"
            );
        }
    }

    #[test]
    fn plain_name_spells_flags() {
        assert_eq!(
            plain_name("🇷🇺→🇪🇪 для wifi · via RU"),
            "RU→EE для wifi · via RU"
        );
        assert_eq!(plain_name("🇪🇪\u{FE0F} для wifi"), "EE для wifi");
        assert_eq!(plain_name(" Server "), "Server");
        assert_eq!(plain_name("\u{1F1F7} x"), " x");
    }
}
