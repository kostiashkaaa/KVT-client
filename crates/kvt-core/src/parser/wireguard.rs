//! WireGuard и AmneziaWG из `.conf` (формат `wg-quick` и `awg-quick`).
//!
//! В «Добавлено вручную» каждый сервер — одна строка, а `.conf` многострочный, поэтому
//! при вставке он превращается в ссылку `kvt-wg://` — своя схема KVT: base64url (без
//! заполнения) от текста `.conf`. Других клиентов она не касается; текст в ней — ровно
//! то, что вставил пользователь (без CRLF и BOM), так что ничего не теряется: ни пиры,
//! ни `I1`–`I5`, ни имя из комментария.
//!
//! `PostUp`/`PreUp`/`PostDown`/`PreDown`, `Table`, `SaveConfig` и прочее из `wg-quick`
//! читаются и **отбрасываются**: KVT никогда не запускает команды из `.conf`.

use super::{decode_base64_lenient, ParseError, MAX_NAME_CHARS};
use crate::i18n::tr;
use crate::model::{Protocol, Security, Server, Transport};
use crate::secret::Secret;
use crate::wireguard::{
    self, awg_key_by_conf, normalize_awg_value, normalize_cidr, normalize_range, Awg, AwgKind,
    WgPeer, WireGuard, MAX_ALLOWED_IPS, MAX_PEERS,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub(super) const SCHEME: &str = "kvt-wg";
/// Предел текста `.conf`: `I1`–`I5` бывают в несколько килобайт, больше — мусор.
pub(super) const MAX_CONF_LEN: usize = 64 * 1024;
/// Предел ссылки `kvt-wg://` (base64 раздувает текст на треть).
pub(super) const MAX_LINK_LEN: usize = SCHEME.len() + 3 + MAX_CONF_LEN.div_ceil(3) * 4;
const MAX_COMMENT_NAME_CHARS: usize = 64;
const MAX_IGNORED: usize = 64;

fn bad(field: &'static str) -> ParseError {
    ParseError::InvalidField {
        field,
        reason: tr("недопустимое значение", "invalid value"),
    }
}

/// Похоже ли на `.conf`: есть строка `[Interface]`.
pub fn looks_like_conf(text: &str) -> bool {
    conf_lines(text).any(is_interface_header)
}

/// Строки `.conf`: кроме `\n` и `\r\n`, бывает одиночный `\r` (старые редакторы,
/// буфер обмена) — `str::lines` его не делит. Лишние пустые строки разбор пропускает.
fn conf_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split(['\r', '\n'])
}

/// `[Interface]`, в том числе с комментарием в строке (`[Interface] # дом`), —
/// как его понимает разбор (`parse_conf` снимает `#…`).
fn is_interface_header(line: &str) -> bool {
    line.trim_start_matches('\u{feff}')
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("[interface]")
}

fn is_comment_or_blank(line: &str) -> bool {
    let t = line.trim_start_matches('\u{feff}').trim();
    t.is_empty() || t.starts_with('#') || t.starts_with(';')
}

/// Делит текст с несколькими `.conf` по строкам `[Interface]`. Комментарии прямо
/// перед `[Interface]` (имя сервера) остаются со своим `.conf`.
pub(super) fn split_confs(text: &str) -> Vec<String> {
    let mut blocks: Vec<Vec<&str>> = vec![Vec::new()];
    let mut pending: Vec<&str> = Vec::new();
    let mut current_has_interface = false;
    for line in conf_lines(text) {
        if is_comment_or_blank(line) {
            pending.push(line);
            continue;
        }
        if is_interface_header(line) && current_has_interface {
            blocks.push(Vec::new());
            current_has_interface = false;
        }
        if is_interface_header(line) {
            current_has_interface = true;
        }
        if let Some(block) = blocks.last_mut() {
            block.append(&mut pending);
            block.push(line);
        }
    }
    if let Some(block) = blocks.last_mut() {
        block.append(&mut pending);
    }
    blocks
        .into_iter()
        .filter(|b| b.iter().any(|l| !is_comment_or_blank(l)))
        .map(|b| b.join("\n"))
        .collect()
}

/// Однострочная ссылка с текстом `.conf` внутри.
pub(super) fn to_link(conf: &str) -> String {
    let text = conf
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    format!("{SCHEME}://{}", URL_SAFE_NO_PAD.encode(text.trim()))
}

/// `kvt-wg://<base64>` и `kvt-wg://<base64>#название`: фрагмент (его ставит `with_name`
/// при переименовании) важнее комментария из самого `.conf`.
pub(super) fn parse_link(input: &str) -> Result<Server, ParseError> {
    let rest = input
        .get(SCHEME.len() + 3..)
        .ok_or(ParseError::InvalidUrl)?;
    let (body, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let bytes = decode_base64_lenient(body).ok_or(ParseError::InvalidUrl)?;
    let text = String::from_utf8(bytes).map_err(|_| ParseError::InvalidUrl)?;
    let mut server = parse_conf(&text)?;
    let renamed: String = percent_decode_str(fragment)
        .decode_utf8_lossy()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    let renamed = renamed.trim();
    if !renamed.is_empty() {
        server.name = renamed.to_owned();
    }
    Ok(server)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct PeerBuf {
    public_key: Option<String>,
    preshared_key: Option<String>,
    endpoint: Option<(String, u16)>,
    allowed_ips: Vec<String>,
    keepalive: Option<String>,
}

#[derive(Default)]
struct InterfaceBuf {
    private_key: Option<String>,
    addresses: Vec<String>,
    dns: Vec<String>,
    mtu: Option<u16>,
    params: BTreeMap<String, String>,
    ignored: Vec<String>,
}

pub(super) fn parse_conf(text: &str) -> Result<Server, ParseError> {
    if text.len() > MAX_CONF_LEN {
        return Err(ParseError::TooLong);
    }
    let mut section = Section::None;
    let mut seen_interface = false;
    let mut iface = InterfaceBuf::default();
    let mut peers: Vec<PeerBuf> = Vec::new();
    let mut name: Option<String> = None;

    for raw in conf_lines(text) {
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') {
            if name.is_none() {
                name = comment_name(line);
            }
            continue;
        }
        // `#` внутри значения — комментарий (как в wg-quick); в base64 и в `I1`–`I5` его нет.
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            match header.trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    if seen_interface {
                        return Err(bad("[Interface]"));
                    }
                    seen_interface = true;
                    section = Section::Interface;
                }
                "peer" => {
                    if peers.len() >= MAX_PEERS {
                        return Err(bad(tr("[Peer] (не больше 16)", "[Peer] (16 at most)")));
                    }
                    peers.push(PeerBuf::default());
                    section = Section::Peer;
                }
                _ => return Err(bad(tr("раздел", "section"))),
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(bad(tr("строка", "line")));
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match section {
            Section::None => return Err(bad(tr("раздел", "section"))),
            Section::Interface => interface_key(&mut iface, &key, value)?,
            Section::Peer => {
                if let Some(peer) = peers.last_mut() {
                    peer_key(peer, &key, value)?;
                }
            }
        }
    }
    build(iface, peers, name, seen_interface)
}

fn interface_key(iface: &mut InterfaceBuf, key: &str, value: &str) -> Result<(), ParseError> {
    match key {
        "privatekey" => iface.private_key = Some(value.to_owned()),
        "address" => {
            for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let cidr = normalize_cidr(part).ok_or_else(|| bad("Address"))?;
                if !iface.addresses.contains(&cidr) {
                    iface.addresses.push(cidr);
                }
            }
        }
        "dns" => {
            // Домены поиска в `DNS =` отбрасываются: берём только адреса.
            for part in value.split(',').map(str::trim) {
                if let Ok(ip) = part.parse::<IpAddr>() {
                    let ip = ip.to_string();
                    if !iface.dns.contains(&ip) {
                        iface.dns.push(ip);
                    }
                }
            }
        }
        "mtu" => iface.mtu = Some(value.parse().map_err(|_| bad("MTU"))?),
        // Команды и настройки `wg-quick`: читаем и не выполняем.
        "listenport" | "fwmark" | "table" | "preup" | "postup" | "predown" | "postdown"
        | "saveconfig" => {}
        _ => {
            if let Some(k) = awg_key_by_conf(key) {
                let v = normalize_awg_value(k.kind, value).ok_or_else(|| bad(k.conf))?;
                if !v.is_empty() && !is_unset(k.kind, k.json, &v) {
                    iface.params.insert(k.json.to_owned(), v);
                }
            } else if !key.is_empty()
                && key.len() <= 32
                && key.bytes().all(|b| b.is_ascii_alphanumeric())
                && iface.ignored.len() < MAX_IGNORED
                && !iface.ignored.iter().any(|i| i == key)
            {
                // `J1`–`J3`, `Itime` (AmneziaWG 1.5) и неизвестное.
                iface.ignored.push(key.to_owned());
            }
        }
    }
    Ok(())
}

/// `0` у счётчиков и `H1`=1…`H4`=4 — значения «не задано» в WireGuard; без них
/// `.conf` обычного WireGuard с «нулевой» AmneziaWG остаётся обычным.
fn is_unset(kind: AwgKind, json: &str, value: &str) -> bool {
    match kind {
        AwgKind::Count(_) => value == "0",
        AwgKind::Range => {
            value == "0"
                || matches!(
                    (json, value),
                    ("h1", "1") | ("h2", "2") | ("h3", "3") | ("h4", "4")
                )
        }
        _ => false,
    }
}

fn peer_key(peer: &mut PeerBuf, key: &str, value: &str) -> Result<(), ParseError> {
    match key {
        "publickey" => peer.public_key = Some(value.to_owned()),
        "presharedkey" => peer.preshared_key = Some(value.to_owned()),
        "endpoint" => peer.endpoint = Some(parse_endpoint(value).ok_or_else(|| bad("Endpoint"))?),
        "allowedips" => {
            for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if peer.allowed_ips.len() >= MAX_ALLOWED_IPS {
                    return Err(bad("AllowedIPs"));
                }
                let cidr = normalize_cidr(part).ok_or_else(|| bad("AllowedIPs"))?;
                if !peer.allowed_ips.contains(&cidr) {
                    peer.allowed_ips.push(cidr);
                }
            }
        }
        "persistentkeepalive" => {
            let v = normalize_range(value).ok_or_else(|| bad("PersistentKeepalive"))?;
            // `0` — выключено.
            peer.keepalive = (v != "0").then_some(v);
        }
        _ => {}
    }
    Ok(())
}

/// `host:port`, `[v6]:port`; хост без скобок.
fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        let (host, port) = value.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    let port: u16 = port.trim().parse().ok().filter(|p| *p != 0)?;
    let host = host.trim();
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

/// Имя из первого комментария: `# Мой сервер`, `; name`.
fn comment_name(line: &str) -> Option<String> {
    let text: String = line
        .trim_start_matches(['#', ';'])
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_COMMENT_NAME_CHARS)
        .collect();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn build(
    iface: InterfaceBuf,
    peers: Vec<PeerBuf>,
    name: Option<String>,
    seen_interface: bool,
) -> Result<Server, ParseError> {
    if !seen_interface {
        return Err(ParseError::MissingField("[Interface]"));
    }
    let private_key = iface
        .private_key
        .ok_or(ParseError::MissingField("PrivateKey"))?;
    if iface.addresses.is_empty() {
        return Err(ParseError::MissingField("Address"));
    }
    if peers.is_empty() {
        return Err(ParseError::MissingField("[Peer]"));
    }
    let mut built = Vec::with_capacity(peers.len());
    for p in peers {
        let (host, port) = p.endpoint.ok_or(ParseError::MissingField("Endpoint"))?;
        if p.allowed_ips.is_empty() {
            return Err(ParseError::MissingField("AllowedIPs"));
        }
        built.push(WgPeer {
            public_key: p.public_key.ok_or(ParseError::MissingField("PublicKey"))?,
            preshared_key: p.preshared_key.map(Secret::new),
            host,
            port,
            allowed_ips: p.allowed_ips,
            keepalive: p.keepalive,
        });
    }
    let awg = (!iface.params.is_empty()).then_some(Awg {
        params: iface.params,
        ignored: iface.ignored,
    });
    let wg = WireGuard {
        private_key: Secret::new(private_key),
        addresses: iface.addresses,
        mtu: iface.mtu,
        dns: iface.dns,
        peers: built,
        awg,
    };
    wireguard::validate(&wg).map_err(bad)?;
    let (address, port) = wg
        .peers
        .first()
        .map(|p| (p.host.clone(), p.port))
        .ok_or(ParseError::MissingField("[Peer]"))?;
    Ok(Server {
        name: name.unwrap_or_else(|| address.clone()),
        address,
        port,
        protocol: Protocol::WireGuard(Box::new(wg)),
        transport: Transport::Udp,
        security: Security::None,
        fragment: None,
        mux: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{check_server, parse_subscription_body, parse_uri, Entry};

    const KEY: &str = "YEocP0XnRPOZ8pZDsCbSDY5vlNwFJCKjR8+Tl5n0DGM=";
    const KEY2: &str = "sRHdS8ss5pR0yWRe7LFSc2iMv5fHgVuOHEv7Hvaw9Qo=";
    const PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

    fn wg_conf() -> String {
        format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.0.2/32, fd00::2/128\nDNS = 10.8.0.1, 1.1.1.1\nMTU = 1380\n\n[Peer]\nPublicKey = {KEY2}\nPresharedKey = {PSK}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        )
    }

    fn wg_of(s: &Server) -> &WireGuard {
        match &s.protocol {
            Protocol::WireGuard(wg) => wg,
            other => panic!("ожидался WireGuard, а не {other:?}"),
        }
    }

    #[test]
    fn plain_wireguard() {
        let s = parse_conf(&wg_conf()).unwrap();
        let wg = wg_of(&s);
        assert_eq!(s.address, "vpn.example.com");
        assert_eq!(s.port, 51820);
        assert_eq!(s.name, "vpn.example.com");
        assert_eq!(wg.addresses, ["10.8.0.2/32", "fd00::2/128"]);
        assert_eq!(wg.dns, ["10.8.0.1", "1.1.1.1"]);
        assert_eq!(wg.mtu, Some(1380));
        assert_eq!(wg.peers[0].keepalive.as_deref(), Some("25"));
        assert_eq!(wg.peers[0].preshared_key.as_ref().unwrap().expose(), PSK);
        assert!(wg.awg.is_none());
        assert_eq!(s.protocol.kind(), "wireguard");
        assert!(s.protocol.is_udp_only());
        assert_eq!(check_server(&s), Ok(()));
    }

    /// Одиночный `\r` вместо перевода строки и комментарий в строке `[Interface]`.
    #[test]
    fn lone_cr_and_header_comment_are_understood() {
        let conf = wg_conf().replace("[Interface]", "[Interface] # дом");
        assert!(looks_like_conf(&conf));
        assert!(parse_conf(&conf).is_ok());
        let conf = wg_conf().replace('\n', "\r");
        assert!(looks_like_conf(&conf));
        assert_eq!(wg_of(&parse_conf(&conf).unwrap()).peers.len(), 1);
    }

    #[test]
    fn amneziawg_one_zero_with_name_and_crlf() {
        let conf = format!(
            "\u{feff}# Мой сервер AWG\r\n[Interface]\r\nPrivateKey = {KEY}\r\nAddress = 10.8.1.7/32\r\nJc = 4\r\nJmin = 10\r\nJmax = 50\r\nS1 = 55\r\nS2 = 42\r\nH1 = 1234567890\r\nH2 = 987654321\r\nH3 = 11111\r\nH4 = 22222\r\n\r\n[Peer]\r\nPublicKey = {KEY2}\r\nEndpoint = 203.0.113.30:30565\r\nAllowedIPs = 0.0.0.0/0\r\n"
        );
        let s = parse_conf(&conf).unwrap();
        let awg = wg_of(&s).awg.as_ref().unwrap();
        assert_eq!(s.name, "Мой сервер AWG");
        assert_eq!(awg.params["jc"], "4");
        assert_eq!(awg.params["h1"], "1234567890");
        assert_eq!(awg.params.len(), 9);
        assert_eq!(s.protocol.kind(), "amneziawg");
        assert_eq!(check_server(&s), Ok(()));
        assert_eq!(
            crate::core_select::select_core(&s).core,
            crate::core_select::CoreKind::SingBoxAwg
        );
    }

    #[test]
    fn amneziawg_three_one_export() {
        let conf = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.1.7/32\nMTU = 1376\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 55\nS2 = 42\nS3 = 40\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = <b 0x000100002112a442><r 12>\nHeaderProtectionKey = {PSK}\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRandomTrailers = on\nDisableCookies = true\nJ1 = <b 0x00>\nItime = 5\n[Peer]\nPublicKey = {KEY2}\nPresharedKey = {PSK}\nEndpoint = 203.0.113.31:30565\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25-35\n"
        );
        let s = parse_conf(&conf).unwrap();
        let wg = wg_of(&s);
        let awg = wg.awg.as_ref().unwrap();
        // H1–H4 по умолчанию (1–4) не хранятся.
        assert!(!awg.params.contains_key("h1"));
        assert_eq!(awg.params["i1"], "<b 0x000100002112a442><r 12>");
        assert_eq!(awg.params["header_protection_key"], PSK);
        assert_eq!(awg.params["content_padding_addition"], "10-100");
        assert_eq!(awg.params["random_trailers"], "true");
        assert_eq!(awg.params["disable_cookies"], "true");
        assert_eq!(awg.ignored, ["j1", "itime"]);
        assert_eq!(wg.peers[0].keepalive.as_deref(), Some("25-35"));
        assert_eq!(s.warnings().len(), 1);
        assert_eq!(check_server(&s), Ok(()));
    }

    #[test]
    fn zero_amnezia_is_plain_wireguard() {
        let conf = wg_conf().replace(
            "MTU = 1380",
            "MTU = 1380\nJc = 0\nJmin = 0\nJmax = 0\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4",
        );
        let s = parse_conf(&conf).unwrap();
        assert!(wg_of(&s).awg.is_none());
        assert_eq!(
            crate::core_select::select_core(&s).core,
            crate::core_select::CoreKind::SingBox
        );
    }

    #[test]
    fn several_peers_and_ipv6_endpoint() {
        let conf = format!(
            "[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {KEY2}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 10.0.0.0/24\n[Peer]\nPublicKey = {PSK}\nEndpoint = b.example.com:443\nAllowedIPs = 0.0.0.0/0\n"
        );
        let s = parse_conf(&conf).unwrap();
        let wg = wg_of(&s);
        assert_eq!(wg.addresses, ["10.0.0.2/32"]);
        assert_eq!(wg.peers.len(), 2);
        assert_eq!(s.address, "2001:db8::1");
        assert_eq!(s.endpoints(), ["2001:db8::1", "b.example.com"]);
    }

    #[test]
    fn comments_and_wg_quick_commands_are_not_executed() {
        let conf = format!(
            "[Interface]\nPrivateKey = {KEY} # секрет\nAddress = 10.0.0.2/32\nPostUp = powershell -c calc\nPreUp = evil\nTable = off\nListenPort = 1\n; комментарий\n[Peer]\nPublicKey = {KEY2}\nEndpoint = h.example.com:1\nAllowedIPs = 0.0.0.0/0\n"
        );
        let s = parse_conf(&conf).unwrap();
        assert_eq!(wg_of(&s).private_key.expose(), KEY);
        // `PostUp` не попал ни в модель, ни в «непримененные» параметры.
        assert!(wg_of(&s).awg.is_none());
        assert!(!format!("{s:?}").contains("calc"));
    }

    #[test]
    fn bad_configs_are_rejected_without_secrets_in_errors() {
        let good = wg_conf();
        let cases = [
            good.replace(KEY, "short"),
            good.replace(
                "Endpoint = vpn.example.com:51820",
                "Endpoint = vpn.example.com",
            ),
            good.replace("Endpoint = vpn.example.com:51820", "Endpoint = host:0"),
            good.replace("Endpoint = vpn.example.com:51820", "Endpoint = ::1:5"),
            good.replace("Address = 10.8.0.2/32, fd00::2/128", "Address = nope"),
            good.replace("MTU = 1380", "MTU = 12"),
            good.replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 1.2.3.4/99"),
            good.replace("PersistentKeepalive = 25", "PersistentKeepalive = 25-35"),
            good.replace("[Peer]", "[Interface]"),
            good.replace("[Peer]", "[Mystery]"),
            good.replace("PersistentKeepalive = 25", "PersistentKeepalive"),
            good.replace("[Interface]\n", ""),
            good.replace("MTU = 1380", "Jc = 129"),
            good.replace("MTU = 1380", "Jc = 4\nJmin = 80\nJmax = 40"),
            good.replace("MTU = 1380", "Jc = 4\nH1 = 5-1"),
            good.replace("MTU = 1380", "I1 = <r 12"),
            good.replace("MTU = 1380", "Jc = 99999999999999999999"),
        ];
        for (i, conf) in cases.iter().enumerate() {
            let err = parse_conf(conf).expect_err(&format!("случай {i} должен отвергаться"));
            let text = err.to_string();
            assert!(!text.contains(KEY) && !text.contains(KEY2), "{i}: {text}");
        }
        assert_eq!(
            parse_conf(&"x".repeat(MAX_CONF_LEN + 1)),
            Err(ParseError::TooLong)
        );
    }

    #[test]
    fn missing_parts_are_named() {
        let no_peer = format!("[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2/32\n");
        assert_eq!(
            parse_conf(&no_peer),
            Err(ParseError::MissingField("[Peer]"))
        );
        let no_key = format!(
            "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {KEY2}\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n"
        );
        assert_eq!(
            parse_conf(&no_key),
            Err(ParseError::MissingField("PrivateKey"))
        );
    }

    #[test]
    fn link_round_trip_and_pasting() {
        let link = to_link(&format!("\u{feff}{}", wg_conf().replace('\n', "\r\n")));
        assert!(link.starts_with("kvt-wg://"));
        assert!(!link.contains('\n'));
        let Entry::Server(from_link) = parse_uri(&link).unwrap() else {
            panic!("ожидался сервер")
        };
        assert_eq!(*from_link, parse_conf(&wg_conf()).unwrap());

        // Подписка из ссылок и сырого `.conf` разом.
        let body = format!("{link}\n");
        assert_eq!(parse_subscription_body(&body).servers.len(), 1);
        let raw = parse_subscription_body(&wg_conf());
        assert_eq!(raw.servers.len(), 1);
        assert!(raw.errors.is_empty());
    }

    #[test]
    fn rename_goes_through_the_fragment() {
        let link = to_link(&format!(
            "# Из комментария
{}",
            wg_conf()
        ));
        let Entry::Server(s) = parse_uri(&link).unwrap() else {
            panic!("ожидался сервер")
        };
        assert_eq!(s.name, "Из комментария");

        // Так переименовывает «Изменить ключ».
        let renamed = crate::parser::with_name(&link, "Мой AWG / №2").unwrap();
        assert!(renamed.contains('#') && !renamed.contains(' '));
        let Entry::Server(r) = parse_uri(&renamed).unwrap() else {
            panic!("ожидался сервер")
        };
        assert_eq!(r.name, "Мой AWG / №2");
        assert_eq!(r.protocol, s.protocol);

        // Повторное переименование заменяет фрагмент, а не копит их.
        let again = crate::parser::with_name(&renamed, "Третье").unwrap();
        assert_eq!(again.matches('#').count(), 1);
        // Пустой фрагмент оставляет имя из `.conf`.
        let Entry::Server(e) = parse_uri(&format!("{link}#")).unwrap() else {
            panic!("ожидался сервер")
        };
        assert_eq!(e.name, "Из комментария");
    }

    #[test]
    fn several_confs_in_one_paste() {
        let a = wg_conf();
        let b = wg_conf().replace("vpn.example.com", "second.example.com");
        let text = format!("# Первый\n{a}\n# Второй\n{b}");
        let parts = split_confs(&text);
        assert_eq!(parts.len(), 2);
        let first = parse_conf(&parts[0]).unwrap();
        let second = parse_conf(&parts[1]).unwrap();
        assert_eq!(first.name, "Первый");
        assert_eq!(second.name, "Второй");
        assert_eq!(second.address, "second.example.com");
        assert_eq!(parse_subscription_body(&text).servers.len(), 2);
    }

    #[test]
    fn oversized_link_is_rejected() {
        let link = format!("kvt-wg://{}", "A".repeat(MAX_LINK_LEN));
        assert_eq!(parse_uri(&link), Err(ParseError::TooLong));
        assert_eq!(parse_uri("kvt-wg://!!!"), Err(ParseError::InvalidUrl));
        assert_eq!(parse_uri("kvt-wg://"), Err(ParseError::InvalidUrl));
    }

    proptest::proptest! {
        #[test]
        fn never_panics_on_arbitrary_text(s in "\\PC{0,600}") {
            let _ = parse_conf(&s);
            let _ = split_confs(&s);
            let _ = parse_uri(&format!("kvt-wg://{s}"));
        }

        #[test]
        fn never_panics_on_conf_like_text(
            s in "(\\[(Interface|Peer)\\]|[A-Za-z0-9]{1,12} ?= ?[A-Za-z0-9+/=<>,. :-]{0,40}|#[ -~]{0,20})(\n(\\[(Interface|Peer)\\]|[A-Za-z0-9]{1,12} ?= ?[A-Za-z0-9+/=<>,. :-]{0,40}|#[ -~]{0,20})){0,12}"
        ) {
            let _ = parse_conf(&s);
        }
    }
}
