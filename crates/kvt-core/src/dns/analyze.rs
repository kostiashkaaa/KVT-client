//! Выводы по наблюдениям: перехват порта 53, подмена ответов, FakeIP, какой резолвер
//! выбрать для прямых сайтов. Чистая функция [`analyze`] — без сети, покрыта тестами.

use super::resolvers::{is_bogon, is_fake_ip, same_24};
use super::{
    in_nets, resolver, title_text, wire, Answer, DnsReport, Observations, PathStatus, QueryResult,
    Resolver, ResolverReport, Source, SpoofFinding, SpoofKind, Tone, Via, RESOLVERS, SPOOF_DOMAINS,
};
use crate::i18n::tr;
use crate::trf;
use std::net::Ipv4Addr;

fn path_status(
    resolver: &Resolver,
    via: Via,
    result: Option<&QueryResult>,
    system: Option<Ipv4Addr>,
    encrypted_egress: Option<Ipv4Addr>,
) -> PathStatus {
    match result {
        None => PathStatus::NotChecked,
        Some(QueryResult::Timeout) => PathStatus::Blocked,
        Some(QueryResult::Failed(reason)) => PathStatus::Failed {
            reason: reason.clone(),
        },
        Some(QueryResult::Answer { answer, ms }) => {
            let ms = *ms;
            let Some(egress) = answer.a.first().copied() else {
                return PathStatus::Works { ms };
            };
            // DoH и DoT защищены сертификатом: подменить их ответ провайдер не может.
            if via == Via::Udp && intercepted(resolver, egress, system, encrypted_egress) {
                PathStatus::Intercepted { ms, by: egress }
            } else {
                PathStatus::Works { ms }
            }
        }
    }
}

/// Выводы делаются осторожно: таблицы сетей могут устареть, поэтому перехват
/// засчитывается, только если его подтверждает второй признак.
fn intercepted(
    resolver: &Resolver,
    egress: Ipv4Addr,
    system: Option<Ipv4Addr>,
    encrypted_egress: Option<Ipv4Addr>,
) -> bool {
    let like_system = system.is_some_and(|s| same_24(s, egress));
    if !resolver.egress.is_empty() {
        if in_nets(egress, resolver.egress) {
            return false;
        }
        return like_system || encrypted_egress.is_some_and(|e| in_nets(e, resolver.egress));
    }
    like_system && encrypted_egress.is_some_and(|e| !same_24(e, egress))
}

fn source_title(source: Source) -> String {
    match source {
        Source::System => crate::i18n::tr("DNS сети", "Network DNS").into(),
        Source::Resolver(id, via) => {
            let title = resolver(id).map_or(id, |r| title_text(r.title));
            let via = match via {
                Via::Udp => "UDP",
                Via::Dot => "DoT",
                Via::Doh => "DoH",
            };
            format!("{title} ({via})")
        }
    }
}

fn spoof_findings(obs: &Observations) -> Vec<SpoofFinding> {
    let encrypted = |s: Source| matches!(s, Source::Resolver(_, Via::Doh | Via::Dot));
    // Эталон — зашифрованный ответ, в нём есть адреса.
    let reference = |domain: &str| -> Option<Vec<Ipv4Addr>> {
        obs.spoof
            .iter()
            .filter(|(d, s, _)| *d == domain && encrypted(*s))
            .filter_map(|(_, _, r)| r.answer())
            .find(|a| !a.a.is_empty())
            .map(|a| a.a.clone())
    };
    let references: Vec<Option<Vec<Ipv4Addr>>> = SPOOF_DOMAINS.into_iter().map(reference).collect();
    let reference_disjoint = match (&references[0], &references[1]) {
        (Some(a), Some(b)) => !a.iter().any(|ip| b.contains(ip)),
        // Без эталона полагаемся на то, что у Meta и Cloudflare нет общих адресов.
        _ => true,
    };

    let mut sources: Vec<Source> = Vec::new();
    for (_, s, _) in &obs.spoof {
        if !encrypted(*s) && !sources.contains(s) {
            sources.push(*s);
        }
    }

    let mut out = Vec::new();
    for source in sources {
        let answers: Vec<Option<&Answer>> = SPOOF_DOMAINS
            .into_iter()
            .map(|d| {
                obs.spoof
                    .iter()
                    .find(|(dd, s, _)| *dd == d && *s == source)
                    .and_then(|(_, _, r)| r.answer())
            })
            .collect();
        let shared: Vec<Ipv4Addr> = match (answers[0], answers[1]) {
            (Some(a), Some(b)) if reference_disjoint => {
                a.a.iter().filter(|ip| b.a.contains(ip)).copied().collect()
            }
            _ => Vec::new(),
        };
        for (i, domain) in SPOOF_DOMAINS.into_iter().enumerate() {
            let Some(answer) = answers[i] else { continue };
            let kind = if !answer.a.is_empty() && answer.a.iter().all(|ip| is_fake_ip(*ip)) {
                Some(SpoofKind::FakeIp)
            } else if answer.a.iter().any(|ip| is_bogon(*ip)) || !shared.is_empty() {
                Some(SpoofKind::Stub)
            } else if matches!(answer.rcode, wire::RCODE_NXDOMAIN | wire::RCODE_REFUSED)
                && references[i].is_some()
            {
                Some(SpoofKind::Denied)
            } else {
                None
            };
            if let Some(kind) = kind {
                out.push(SpoofFinding {
                    domain,
                    source: source_title(source),
                    kind,
                    got: answer.a.clone(),
                });
            }
        }
    }
    out
}

pub fn analyze(obs: &Observations) -> DnsReport {
    let system_egress = obs.system_whoami.as_ref().and_then(QueryResult::egress);
    let find = |id: &str, via: Via| {
        obs.whoami
            .iter()
            .find(|(i, v, _)| *i == id && *v == via)
            .map(|(_, _, r)| r)
    };

    let resolvers: Vec<ResolverReport> = RESOLVERS
        .iter()
        .map(|r| {
            let encrypted_egress = [Via::Doh, Via::Dot]
                .into_iter()
                .find_map(|via| find(r.id, via).and_then(QueryResult::egress));
            let status =
                |via| path_status(r, via, find(r.id, via), system_egress, encrypted_egress);
            ResolverReport {
                id: r.id,
                title: r.title,
                udp: status(Via::Udp),
                dot: status(Via::Dot),
                doh: status(Via::Doh),
            }
        })
        .collect();

    let interception = resolvers
        .iter()
        .any(|r| matches!(r.udp, PathStatus::Intercepted { .. }));
    let interceptor = resolvers.iter().find_map(|r| match r.udp {
        PathStatus::Intercepted { by, .. } => Some(by),
        _ => None,
    });
    let encrypted_available = resolvers.iter().any(|r| {
        matches!(r.dot, PathStatus::Works { .. }) || matches!(r.doh, PathStatus::Works { .. })
    });
    // Для прямых сайтов годится любой резолвер, который отвечает сам; Яндекс — первый.
    let recommended_local = resolvers
        .iter()
        .find(|r| matches!(r.udp, PathStatus::Works { .. }))
        .map_or(RESOLVERS[0].id, |r| r.id);
    let (fake, spoofing): (Vec<_>, Vec<_>) = spoof_findings(obs)
        .into_iter()
        .partition(|f| f.kind == SpoofKind::FakeIp);
    let fake_ip = !fake.is_empty();

    let (tone, title, mut detail) = match (interception, spoofing.is_empty()) {
        (true, false) => (
            Tone::Warning,
            tr(
                "Провайдер перехватывает DNS и подменяет ответы",
                "Your ISP intercepts DNS and spoofs answers",
            )
            .to_owned(),
            trf!(
                "На запросы к публичным DNS по UDP отвечает сервер провайдера ({}), а для \
                 заблокированных сайтов он возвращает адрес заглушки.",
                "Queries to public DNS over UDP are answered by your ISP's server ({}), and for \
                 blocked sites it returns a block-page address.",
                interceptor.map(|ip| ip.to_string()).unwrap_or_default()
            ),
        ),
        (true, true) => (
            Tone::Warning,
            tr(
                "Провайдер перехватывает DNS-запросы",
                "Your ISP intercepts DNS queries",
            )
            .to_owned(),
            trf!(
                "На запросы к публичным DNS по UDP отвечает сервер провайдера ({}). Подмены \
                 ответов для проверочных сайтов не нашлось.",
                "Queries to public DNS over UDP are answered by your ISP's server ({}). No \
                 spoofed answers were found for the test sites.",
                interceptor.map(|ip| ip.to_string()).unwrap_or_default()
            ),
        ),
        (false, false) => (
            Tone::Warning,
            tr(
                "DNS подменяет ответы для заблокированных сайтов",
                "DNS spoofs answers for blocked sites",
            )
            .to_owned(),
            trf!(
                "{} возвращает адрес заглушки вместо настоящего адреса сайта.",
                "{} returns a block-page address instead of the site's real address.",
                spoofing[0].source
            ),
        ),
        (false, true) if fake_ip => (
            Tone::Ok,
            tr(
                "На роутере работает обход блокировок",
                "Your router bypasses blocks",
            )
            .to_owned(),
            tr(
                "DNS сети отдаёт заблокированным сайтам адреса FakeIP (198.18.x.x) — так работают \
                 podkop и sing-box: роутер сам ведёт эти сайты через свой VPN. Подмены провайдером \
                 и перехвата запросов не обнаружено. С KVT это не конфликтует: при подключении DNS \
                 идёт через DoH в туннеле KVT.",
                "The network DNS gives blocked sites FakeIP addresses (198.18.x.x) — that's how \
                 podkop and sing-box work: the router routes these sites through its own VPN. No ISP \
                 spoofing or query interception was found. This doesn't conflict with KVT: when \
                 connected, DNS goes over DoH inside the KVT tunnel.",
            )
            .to_owned(),
        ),
        (false, true) => (
            Tone::Ok,
            tr("DNS работает честно", "DNS is honest").to_owned(),
            tr(
                "Перехвата запросов и подмены ответов не обнаружено.",
                "No query interception or spoofed answers found.",
            )
            .to_owned(),
        ),
    };
    if tone == Tone::Warning {
        detail.push_str(tr(
            " При подключении через KVT это не мешает: DNS шифруется (DoH) и идёт внутри туннеля.",
            " This doesn't matter when connected through KVT: DNS is encrypted (DoH) and goes inside the tunnel.",
        ));
    }
    if !encrypted_available {
        detail.push_str(tr(
            " Зашифрованный DNS (DoH и DoT) напрямую недоступен — похоже, провайдер его блокирует.",
            " Encrypted DNS (DoH and DoT) isn't reachable directly — your ISP seems to block it.",
        ));
    }

    DnsReport {
        resolvers,
        system_server: obs.system_server,
        system_egress,
        interception,
        spoofing,
        fake_ip,
        encrypted_available,
        recommended_local,
        tone,
        title,
        detail,
    }
}
