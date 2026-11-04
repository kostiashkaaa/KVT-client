//! Обновление списков маршрутизации службой.

use crate::net::NetClient;
use kvt_core::core_select::CoreKind;
use kvt_core::lists::ITDOG_LISTS;
use kvt_core::routing::presets::{self, ListMode};
use kvt_core::routing::{Action, RoutingPlan};
use kvt_core::rulesync::{self, RuleFile, SyncReport};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// План, покрывающий все наборы режима: пресет, zapret и все сервисы itdoginfo,
/// чтобы переключатели сервисов работали без повторной загрузки.
fn coverage_plan(mode: ListMode) -> RoutingPlan {
    let mut plan = presets::russia_smart(Action::Proxy, mode);
    plan.extend(presets::zapret_youtube_discord());
    plan.extend(
        ITDOG_LISTS
            .iter()
            .filter_map(|l| presets::list_choice(l.id, Action::Proxy)),
    );
    plan
}

pub fn files_for(mode: ListMode, cores: &[CoreKind]) -> Vec<RuleFile> {
    let plan = coverage_plan(mode);
    let mut files: Vec<RuleFile> = cores
        .iter()
        .flat_map(|c| rulesync::required_files(&plan, *c))
        .collect();
    files.sort();
    files.dedup();
    files
}

pub async fn update(
    dir: &Path,
    mode: ListMode,
    cores: &[CoreKind],
    force: bool,
) -> anyhow::Result<SyncReport> {
    let http = NetClient::new(kvt_core::netlog::Purpose::Rules)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(rulesync::sync(&http, dir, &files_for(mode, cores), now, force).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_mode_skips_huge_runetfreedom_geosite() {
        let files = files_for(ListMode::Compact, &[CoreKind::Xray, CoreKind::SingBox]);
        assert!(files.iter().all(|f| f.local != "geosite.dat"));
        assert!(files.iter().any(|f| f.local == "itdog-youtube.srs"));
        assert!(files.iter().any(|f| f.local == "itdog-geosite.dat"));
    }
}
