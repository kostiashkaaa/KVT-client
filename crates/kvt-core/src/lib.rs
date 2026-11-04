//! Ядро логики KVT. Работает в процессе приложения с правами пользователя:
//! всё, что пришло из сети (подписки, ссылки), разбирается здесь, а служба
//! получает уже типизированную и проверенную модель.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod audit;
pub mod captive;
pub mod compile;
pub mod core_errors;
pub mod core_select;
pub mod diaglog;
pub mod dns;
pub mod flag;
pub mod governor;
pub mod ipc;
pub mod lists;
pub mod migrate;
pub mod model;
pub mod netlog;
pub mod parser;
pub mod probe;
pub mod redact;
pub mod routing;
pub mod rulesync;
pub mod secret;
pub mod subscription;
pub mod tester;
pub mod zapret;

pub use model::Server;
pub use secret::Secret;
