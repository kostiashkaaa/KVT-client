//! Флаг страны в названии сервера. Провайдеры пишут флаг эмодзи (🇳🇱), но Windows
//! не рисует эмодзи-флаги — вместо них видны буквы. Поэтому флаг вынимается из
//! названия как код страны, а интерфейс рисует его картинкой.

const RI_START: u32 = 0x1F1E6;
const RI_END: u32 = 0x1F1FF;

fn regional(c: char) -> Option<char> {
    let code = u32::from(c);
    (RI_START..=RI_END)
        .contains(&code)
        .then(|| char::from(b'a' + (code - RI_START) as u8))
}

/// Название без флага и код страны первого флага (`"nl"`). Остальные флаги
/// (например, цепочка «🇷🇺→🇩🇰») превращаются в буквы, чтобы читались одинаково везде.
pub fn split_flag(name: &str) -> (Option<String>, String) {
    let chars: Vec<char> = name.chars().collect();
    let mut flag = None;
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < chars.len() {
        let pair = regional(chars[i]).zip(chars.get(i + 1).copied().and_then(regional));
        match pair {
            Some((a, b)) if flag.is_none() => {
                flag = Some(format!("{a}{b}"));
                i += 2;
            }
            Some((a, b)) => {
                out.push(a.to_ascii_uppercase());
                out.push(b.to_ascii_uppercase());
                i += 2;
            }
            // Одинокий индикатор не флаг — выбрасываем, он всё равно не читается.
            None if regional(chars[i]).is_some() => i += 1,
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed
        .trim_matches(|c: char| {
            c.is_whitespace() || matches!(c, '|' | '-' | '·' | ',' | '→' | '>' | '\u{FE0F}')
        })
        .to_owned();
    let name = if trimmed.is_empty() {
        name.trim().to_owned()
    } else {
        trimmed
    };
    (flag, name)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn flag_in_the_middle_and_chain() {
        assert_eq!(
            split_flag("Fast 🇩🇪 Frankfurt ⚡"),
            (Some("de".into()), "Fast Frankfurt ⚡".into())
        );
        assert_eq!(
            split_flag("🇷🇺→🇩🇰 via RU"),
            (Some("ru".into()), "DK via RU".into())
        );
    }

    #[test]
    fn no_flag() {
        assert_eq!(split_flag("  Server 1 "), (None, "Server 1".into()));
        assert_eq!(split_flag("🚀 Turbo"), (None, "🚀 Turbo".into()));
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
