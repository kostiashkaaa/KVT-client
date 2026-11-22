use super::*;
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn db(csv: &str) -> Vec<u8> {
    pack(csv).expect("CSV упаковался").0
}

fn code(db: &CountryDb<'_>, ip: &str) -> Option<String> {
    let ip: IpAddr = ip.parse().expect("адрес");
    db.country(ip)
        .map(|c| String::from_utf8_lossy(&c).into_owned())
}

const SMALL: &str = "\
0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
8.8.8.0,8.8.8.255,US
77.88.0.0,77.88.255.255,RU
255.255.255.0,255.255.255.255,ZZ
::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
2a02:6b8::,2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff,RU
";

#[test]
fn finds_the_range_an_address_falls_into() {
    let bytes = db(SMALL);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    assert_eq!(code(&db, "1.0.0.0").as_deref(), Some("AU"));
    assert_eq!(code(&db, "1.0.0.255").as_deref(), Some("AU"));
    assert_eq!(code(&db, "1.0.1.0").as_deref(), Some("CN"));
    assert_eq!(code(&db, "1.0.3.255").as_deref(), Some("CN"));
    assert_eq!(code(&db, "8.8.8.8").as_deref(), Some("US"));
    assert_eq!(code(&db, "77.88.8.8").as_deref(), Some("RU"));
    assert_eq!(code(&db, "2001:4860:4860::8888").as_deref(), Some("US"));
    assert_eq!(code(&db, "2a02:6b8:0:1::1").as_deref(), Some("RU"));
}

#[test]
fn gaps_and_edges_are_unknown_not_a_neighbour() {
    let bytes = db(SMALL);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    // Дыра между 1.0.3.255 и 8.8.8.0 закрыта «неизвестно», а не страной соседа.
    assert_eq!(code(&db, "1.0.4.0").as_deref(), Some("ZZ"));
    assert_eq!(code(&db, "8.8.7.255").as_deref(), Some("ZZ"));
    assert_eq!(code(&db, "8.8.9.0").as_deref(), Some("ZZ"));
    // Самые первый и последний адреса пространства.
    assert_eq!(code(&db, "0.0.0.0").as_deref(), Some("ZZ"));
    assert_eq!(code(&db, "255.255.255.255").as_deref(), Some("ZZ"));
    assert_eq!(code(&db, "::").as_deref(), Some("ZZ"));
    assert_eq!(
        code(&db, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").as_deref(),
        Some("ZZ")
    );
}

#[test]
fn ipv4_mapped_ipv6_is_looked_up_as_ipv4() {
    let bytes = db(SMALL);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    assert_eq!(code(&db, "::ffff:8.8.8.8").as_deref(), Some("US"));
}

#[test]
fn neighbours_of_the_same_country_are_merged() {
    let csv = "0.0.0.0,9.255.255.255,DE\n10.0.0.0,10.255.255.255,DE\n11.0.0.0,255.255.255.255,FR\n";
    let (bytes, stats) = pack(csv).expect("упаковалась");
    assert_eq!(stats.v4, 2);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    assert_eq!(code(&db, "10.1.1.1").as_deref(), Some("DE"));
    assert_eq!(code(&db, "11.0.0.0").as_deref(), Some("FR"));
}

#[test]
fn ipv6_keeps_network_48_precision() {
    // Два диапазона в одной сети /48: побеждает последний, но соседние сети не задеты.
    let csv = "\
::,2001:db7:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
2001:db8::,2001:db8:0:7fff:ffff:ffff:ffff:ffff,NL
2001:db8:0:8000::,2001:db8:0:ffff:ffff:ffff:ffff:ffff,DE
2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,FR
2001:db8:2::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
";
    let bytes = db(csv);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    assert_eq!(code(&db, "2001:db8::1").as_deref(), Some("DE"));
    assert_eq!(code(&db, "2001:db8:1::1").as_deref(), Some("FR"));
    assert_eq!(code(&db, "2001:db7::1").as_deref(), Some("ZZ"));
}

#[test]
fn pack_rejects_bad_csv() {
    assert_eq!(pack("").unwrap_err(), PackError::Empty);
    assert_eq!(pack("1.0.0.0,1.0.0.255\n").unwrap_err(), PackError::Line(1));
    assert_eq!(
        pack("1.0.0.0,1.0.0.255,AU,x\n").unwrap_err(),
        PackError::Line(1)
    );
    assert_eq!(
        pack("не адрес,1.0.0.255,AU\n").unwrap_err(),
        PackError::Value(1)
    );
    assert_eq!(
        pack("1.0.0.0,1.0.0.255,AUS\n").unwrap_err(),
        PackError::Value(1)
    );
    assert_eq!(
        pack("1.0.0.0,1.0.0.255,A1\n").unwrap_err(),
        PackError::Value(1)
    );
    // Разные семейства адресов в одной строке.
    assert_eq!(pack("1.0.0.0,::1,AU\n").unwrap_err(), PackError::Value(1));
    // Конец раньше начала и пересечения.
    assert_eq!(
        pack("1.0.0.9,1.0.0.1,AU\n").unwrap_err(),
        PackError::Range(1)
    );
    assert_eq!(
        pack("1.0.0.0,1.0.0.255,AU\n1.0.0.128,1.0.1.0,CN\n").unwrap_err(),
        PackError::Range(2)
    );
    // Диапазон после конца пространства — тоже пересечение.
    assert_eq!(
        pack("0.0.0.0,255.255.255.255,AU\n1.0.0.0,1.0.0.1,CN\n").unwrap_err(),
        PackError::Range(2)
    );
}

#[test]
fn parse_rejects_damaged_files() {
    let good = db(SMALL);
    assert_eq!(CountryDb::parse(&[]).unwrap_err(), FormatError::Magic);
    assert_eq!(
        CountryDb::parse(b"not a database at all").unwrap_err(),
        FormatError::Magic
    );
    assert!(CountryDb::parse(&good).is_ok());
    // Обрезан на каждой границе и где-то посередине.
    for cut in [8, 9, 12, 20, good.len() / 2, good.len() - 1] {
        assert!(CountryDb::parse(&good[..cut]).is_err(), "cut {cut}");
    }
    // Лишнее в конце.
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        CountryDb::parse(&trailing).unwrap_err(),
        FormatError::Trailing
    );
    // Огромное число записей не выделяет память и не переполняет умножение.
    let mut huge = MAGIC.to_vec();
    huge.extend_from_slice(&[1, 0, b'Z', b'Z']);
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(CountryDb::parse(&huge).is_err());
    // Индекс страны за пределами списка и нарушенный порядок.
    let mut bad_index = good.clone();
    let last = bad_index.len() - 1;
    bad_index[last] = 200;
    assert_eq!(
        CountryDb::parse(&bad_index).unwrap_err(),
        FormatError::Corrupt
    );
}

#[test]
fn private_and_unspecified_addresses_do_not_panic() {
    let bytes = db(SMALL);
    let db = CountryDb::parse(&bytes).expect("разобралась");
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    ] {
        assert_eq!(db.country(ip), Some(*b"ZZ"), "{ip}");
    }
}

proptest! {
    // Любые байты — отказ или разобранная база, но не паника: в релизе это `abort`.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(db) = CountryDb::parse(&bytes) {
            let _ = db.country(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        }
    }

    // Случайные ограничения базы с настоящей заголовочной частью: сломанные записи
    // отсеивает проверка, а поиск по принятой базе не выходит за её пределы.
    #[test]
    fn mutated_good_file_never_panics(
        position in 0usize..400,
        value in any::<u8>(),
        ip in any::<u32>(),
    ) {
        let mut bytes = db(SMALL);
        let at = position % bytes.len();
        bytes[at] = value;
        if let Ok(db) = CountryDb::parse(&bytes) {
            let _ = db.country(IpAddr::V4(Ipv4Addr::from(ip)));
            let _ = db.country(IpAddr::V6(Ipv6Addr::from(u128::from(ip) << 70)));
        }
    }

    // Упакованные случайные диапазоны ищутся так же, как перебором.
    #[test]
    fn packed_ranges_match_a_linear_scan(
        cuts in proptest::collection::btree_set(1u32..100_000, 1..30),
        probes in proptest::collection::vec(0u32..110_000, 1..40),
    ) {
        let codes = ["AA", "BB", "CC", "ZZ"];
        let starts: Vec<u32> = std::iter::once(0).chain(cuts).collect();
        let mut csv = String::new();
        let mut expected: Vec<(u32, &str)> = Vec::new();
        for (i, start) in starts.iter().enumerate() {
            let end = starts.get(i + 1).map_or(u32::MAX, |n| n - 1);
            let cc = codes[i % codes.len()];
            csv.push_str(&format!("{},{},{cc}\n", Ipv4Addr::from(*start), Ipv4Addr::from(end)));
            expected.push((*start, cc));
        }
        let bytes = db(&csv);
        let database = CountryDb::parse(&bytes).expect("разобралась");
        for probe in probes {
            let want = expected.iter().rev().find(|(s, _)| *s <= probe).map(|(_, c)| *c);
            let got = database.country(IpAddr::V4(Ipv4Addr::from(probe)));
            prop_assert_eq!(got.map(|c| String::from_utf8_lossy(&c).into_owned()), want.map(str::to_string));
        }
    }
}

/// Вшитая в окно база: тот же файл, что берёт `kvt-app`.
const BUNDLED: &[u8] = include_bytes!("../../../../presets/dbip-country.bin");

#[test]
fn bundled_database_is_valid_and_knows_stable_addresses() {
    let db = CountryDb::parse(BUNDLED).expect("вшитая база разбирается и проходит проверку");
    let (v4, v6) = db.len();
    assert!(v4 > 300_000 && v6 > 300_000, "{v4} / {v6}");
    // Адреса, страна которых не меняется от месяца к месяцу.
    assert_eq!(code(&db, "8.8.8.8").as_deref(), Some("US"));
    assert_eq!(code(&db, "77.88.8.8").as_deref(), Some("RU"));
    // Адреса Яндекса и RIPE NCC (RIPE выдаёт их из Европы и Ближнего Востока).
    assert_eq!(code(&db, "2a02:6b8::1").as_deref(), Some("RU"));
    assert_eq!(
        code(&db, "2001:67c:2e8:22::c100:68b").as_deref(),
        Some("NL")
    );
    // Частные и служебные адреса страны не имеют.
    for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "::1"] {
        assert_eq!(code(&db, ip).as_deref(), Some("ZZ"), "{ip}");
    }
    // И флага у «неизвестно» нет, а у настоящей страны — есть.
    assert_eq!(crate::flag::from_country(*b"ZZ"), None);
    assert_eq!(crate::flag::from_country(*b"NL").as_deref(), Some("nl"));
}
