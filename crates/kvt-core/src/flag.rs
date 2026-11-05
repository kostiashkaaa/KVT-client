//! Флаг страны в названии сервера. Провайдеры пишут флаг эмодзи (🇳🇱), но Windows
//! не рисует эмодзи-флаги — вместо них видны буквы. Поэтому флаг вынимается из
//! названия как код страны, а интерфейс рисует его картинкой.
//!
//! Цепочки серверов провайдеры называют «🇷🇺→🇪🇪 для wifi · via RU»: вход через одну
//! страну, выход — в другой. Флагом сервера считается страна выхода (последний флаг):
//! через неё виден интернет. Страна входа — отдельной пометкой.

const RI_START: u32 = 0x1F1E6;
const RI_END: u32 = 0x1F1FF;

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

/// Флаги, разобранные из названия сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFlags {
    /// Страна, через которую виден интернет (`"ee"`).
    pub flag: Option<String>,
    /// Страна входа у цепочки (`"ru"`), если она отличается от страны выхода.
    pub via: Option<String>,
    /// Название без флагов и без «via RU».
    pub name: String,
}

fn regional(c: char) -> Option<char> {
    let code = u32::from(c);
    (RI_START..=RI_END)
        .contains(&code)
        .then(|| char::from(b'a' + (code - RI_START) as u8))
}

/// Код страны из слова («RU», «uk»), если для него есть флаг.
fn country_code(word: &str) -> Option<String> {
    if word.len() != 2 || !word.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let code = match word.to_ascii_lowercase().as_str() {
        "uk" => "gb".to_owned(),
        other => other.to_owned(),
    };
    KNOWN.split_whitespace().any(|k| k == code).then_some(code)
}

/// Разделители, которые остаются по краям названия, когда из него вынули флаги.
fn is_separator(c: char) -> bool {
    c.is_whitespace() || matches!(c, '|' | '-' | '·' | ',' | '→' | '>' | '\u{FE0F}')
}

pub fn split_flags(name: &str) -> ServerFlags {
    let chars: Vec<char> = name.chars().collect();
    let mut flags: Vec<String> = Vec::new();
    // Флаги вынимаются целиком; на месте каждого — пробел, чтобы слова не слиплись.
    let mut text = String::with_capacity(name.len());
    let mut i = 0;
    while i < chars.len() {
        match regional(chars[i]).zip(chars.get(i + 1).copied().and_then(regional)) {
            Some((a, b)) => {
                flags.push(format!("{a}{b}"));
                text.push(' ');
                i += 2;
            }
            // Одинокий индикатор не флаг — выбрасываем, он всё равно не читается.
            None if regional(chars[i]).is_some() => i += 1,
            None => {
                text.push(chars[i]);
                i += 1;
            }
        }
    }

    let mut words: Vec<&str> = text.split_whitespace().collect();

    // «via RU» / «через RU» — страна входа словами.
    let mut via_word = None;
    if let Some(pos) = words.windows(2).position(|w| {
        matches!(w[0].to_lowercase().as_str(), "via" | "через") && country_code(w[1]).is_some()
    }) {
        via_word = country_code(words[pos + 1]);
        words.drain(pos..pos + 2);
    }

    // Нет флага-эмодзи, но название начинается с кода страны: «DK для wifi».
    if flags.is_empty() {
        if let Some(code) = words
            .first()
            .filter(|w| w.bytes().all(|b| b.is_ascii_uppercase()))
            .and_then(|w| country_code(w))
        {
            flags.push(code);
            words.remove(0);
        }
    }

    let flag = flags.last().cloned();
    let via = match flags.len() {
        0 | 1 => via_word,
        _ => flags.first().cloned(),
    }
    .filter(|v| Some(v) != flag.as_ref());

    let joined = words.join(" ");
    // Разделитель, оставшийся от вынутого «· via RU», тоже уходит.
    let trimmed = joined.trim_matches(is_separator).to_owned();
    let name = if trimmed.is_empty() {
        name.trim().to_owned()
    } else {
        trimmed
    };
    ServerFlags { flag, via, name }
}

/// Название без флагов и код страны выхода (`"nl"`).
pub fn split_flag(name: &str) -> (Option<String>, String) {
    let f = split_flags(name);
    (f.flag, f.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(name: &str) -> (Option<String>, Option<String>, String) {
        let f = split_flags(name);
        (f.flag, f.via, f.name)
    }

    fn want(
        flag: Option<&str>,
        via: Option<&str>,
        name: &str,
    ) -> (Option<String>, Option<String>, String) {
        (flag.map(Into::into), via.map(Into::into), name.into())
    }

    #[test]
    fn leading_flag() {
        assert_eq!(
            split_flag("🇳🇱 Нидерланды"),
            (Some("nl".into()), "Нидерланды".into())
        );
        assert_eq!(
            split_flag("🇩🇰 | DK для wifi"),
            (Some("dk".into()), "DK для wifi".into())
        );
    }

    #[test]
    fn flag_in_the_middle() {
        assert_eq!(
            split_flag("Fast 🇩🇪 Frankfurt ⚡"),
            (Some("de".into()), "Fast Frankfurt ⚡".into())
        );
    }

    #[test]
    fn chain_takes_exit_country() {
        for name in [
            "🇷🇺→🇪🇪 для wifi · via RU",
            "🇷🇺 → 🇪🇪 для wifi",
            "🇷🇺>🇪🇪 для wifi",
            "🇷🇺-🇪🇪 для wifi",
            "🇷🇺 🇪🇪 для wifi",
        ] {
            assert_eq!(
                flags(name),
                want(Some("ee"), Some("ru"), "для wifi"),
                "{name}"
            );
        }
    }

    #[test]
    fn via_in_words() {
        assert_eq!(
            flags("🇩🇰 для wifi · via RU"),
            want(Some("dk"), Some("ru"), "для wifi")
        );
        assert_eq!(flags("Таллин через ru"), want(None, Some("ru"), "Таллин"));
        // «via» без кода страны — обычные слова.
        assert_eq!(flags("🇳🇱 via cdn"), want(Some("nl"), None, "via cdn"));
    }

    #[test]
    fn same_country_twice_is_not_a_chain() {
        assert_eq!(
            flags("🇩🇪→🇩🇪 Франкфурт"),
            want(Some("de"), None, "Франкфурт")
        );
    }

    #[test]
    fn country_code_as_first_word() {
        assert_eq!(flags("DK для wifi"), want(Some("dk"), None, "для wifi"));
        assert_eq!(flags("UK London"), want(Some("gb"), None, "London"));
        // Только заглавные, только первое слово, только настоящие коды.
        assert_eq!(flags("Dk для wifi"), want(None, None, "Dk для wifi"));
        assert_eq!(flags("Сервер DE"), want(None, None, "Сервер DE"));
        assert_eq!(flags("XX тест"), want(None, None, "XX тест"));
        assert_eq!(flags("LTE сервера"), want(None, None, "LTE сервера"));
    }

    #[test]
    fn no_flag() {
        assert_eq!(split_flag("  Server 1 "), (None, "Server 1".into()));
        assert_eq!(split_flag("🚀 Turbo"), (None, "🚀 Turbo".into()));
        assert_eq!(
            split_flag("📶 LTE сервера 👇"),
            (None, "📶 LTE сервера 👇".into())
        );
    }

    #[test]
    fn only_flag_keeps_something_readable() {
        let (flag, name) = split_flag("🇯🇵");
        assert_eq!(flag.as_deref(), Some("jp"));
        assert_eq!(name, "🇯🇵");
    }

    #[test]
    fn code_is_always_two_ascii_letters() {
        for c in RI_START..=RI_END {
            let ch = char::from_u32(c).unwrap();
            let (flag, _) = split_flag(&format!("{ch}{ch} x"));
            let flag = flag.unwrap();
            assert_eq!(flag.len(), 2);
            assert!(flag.bytes().all(|b| b.is_ascii_lowercase()));
        }
    }
}
