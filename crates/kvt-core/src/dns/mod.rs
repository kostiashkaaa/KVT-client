//! Проверка DNS: какие резолверы доступны из текущей сети, перехватывает ли
//! провайдер запросы к ним и подменяет ли ответы для заблокированных сайтов.
//!
//! Здесь только данные и выводы. Запросы отправляет приложение и передаёт сюда
//! наблюдения ([`Observations`]), поэтому анализ покрыт тестами без сети.
//!
//! Как это определяется:
//!
//! - **перехват**: `whoami.akamai.net` возвращает адрес резолвера, который на самом
//!   деле спросил Akamai. Если по UDP «Google» отвечает адресом провайдера, а по
//!   DoH (его не подделать без сертификата) — адресом Google, провайдер
//!   перехватывает порт 53;
//! - **подмена**: два заблокированных сайта с разной инфраструктурой. Честный
//!   резолвер вернёт им разные адреса, а заглушка провайдера — один и тот же адрес
//!   страницы блокировки (или адрес из частной сети).
//!
//! Состав: `resolvers` — каталог и признаки адресов, `report` — словарь наблюдений и
//! выводов, `analyze` — сами выводы; `names` — имена серверов через DoH, `wire` —
//! разбор ответов.

pub mod names;
pub mod wire;

mod analyze;
mod report;
mod resolvers;
#[cfg(test)]
mod tests;

pub use analyze::analyze;
pub use report::{
    DnsReport, Observations, PathStatus, QueryResult, ResolverReport, Source, SpoofFinding,
    SpoofKind, Tone, Via,
};
pub use resolvers::{
    in_nets, resolver, title_text, Endpoint, Resolver, CLOUDFLARE_NETS, RESOLVERS, SPOOF_DOMAINS,
    WHOAMI,
};
pub use wire::Answer;
