use crate::subscription::SubscriptionNode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientSettings {
    pub autostart: bool,
    pub close_to_tray: bool,
    pub disconnect_on_exit: bool,
    pub language: String,
    pub appearance: String,
    pub connection_mode: String,
    pub auto_system_proxy: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            close_to_tray: true,
            disconnect_on_exit: true,
            language: "简体中文".into(),
            appearance: "system".into(),
            connection_mode: "client".into(),
            auto_system_proxy: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Preferences {
    pub schema_version: u32,
    pub subscription_url: String,
    pub ppp_path: String,
    pub raw_config: String,
    pub favorites: BTreeSet<String>,
    pub manual_nodes: Vec<SubscriptionNode>,
    pub launch_options: BTreeMap<String, Value>,
    pub settings: ClientSettings,
    pub subscriptions: Vec<SubscriptionSource>,
    pub network_overrides: Value,
    /// Use the GUI-managed policy v2 workspace for every connection.
    pub policy_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    #[serde(default)]
    pub last_synced_at: u64,
    #[serde(default)]
    pub cached: bool,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Error)]
pub enum PreferencesError {
    #[error("设置文件读写失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("设置文件 JSON 无效: {0}")]
    Json(#[from] serde_json::Error),
    #[error("未知设置项: {0}")]
    UnknownSetting(String),
    #[error("设置项 {0} 的值类型无效")]
    InvalidSetting(String),
    #[error("{0}")]
    Storage(String),
}

pub fn load_preferences(path: &Path) -> Result<Preferences, PreferencesError> {
    if !path.exists() {
        return Ok(Preferences::default());
    }
    let mut preferences: Preferences = serde_json::from_slice(&fs::read(path)?)?;
    let mut migrated = false;
    if preferences.schema_version < 2
        && preferences.subscriptions.is_empty()
        && !preferences.subscription_url.is_empty()
    {
        preferences.subscriptions.push(SubscriptionSource {
            id: "legacy".into(),
            name: "Subscription".into(),
            url: preferences.subscription_url.clone(),
            enabled: true,
            last_synced_at: 0,
            cached: true,
            error: String::new(),
        });
        preferences.favorites = preferences
            .favorites
            .into_iter()
            .map(|id| {
                if id.starts_with("manual:") {
                    id
                } else {
                    format!("sub:legacy:{id}")
                }
            })
            .collect();
        let directory = path.parent().unwrap_or(Path::new("."));
        let cache = directory.join("subscription-cache.json");
        if cache.exists() {
            fs::copy(cache, directory.join("subscription-legacy.json"))?;
        }
        migrated = true;
    }
    if !preferences.settings.disconnect_on_exit {
        preferences.settings.disconnect_on_exit = true;
        migrated = true;
    }
    if preferences.schema_version < 2 {
        preferences.schema_version = 2;
        migrated = true;
    }
    if migrated {
        if !path.with_extension("migration-backup.json").exists() {
            fs::copy(path, path.with_extension("migration-backup.json"))?;
        }
        save_preferences(path, &preferences)?;
    }
    Ok(preferences)
}

pub fn save_preferences(path: &Path, preferences: &Preferences) -> Result<(), PreferencesError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::storage::write(path, &serde_json::to_vec_pretty(preferences)?)
        .map_err(PreferencesError::Storage)
}

pub fn update_setting(
    preferences: &mut Preferences,
    key: &str,
    value: Value,
) -> Result<(), PreferencesError> {
    match key {
        "pppPath" => preferences.ppp_path = string_value(key, value)?,
        "autostart" => preferences.settings.autostart = bool_value(key, value)?,
        "autoSystemProxy" => preferences.settings.auto_system_proxy = bool_value(key, value)?,
        "closeToTray" => preferences.settings.close_to_tray = bool_value(key, value)?,
        "disconnectOnExit" => {
            if !bool_value(key, value)? {
                return Err(PreferencesError::InvalidSetting(key.into()));
            }
            preferences.settings.disconnect_on_exit = true;
        }
        "language" => preferences.settings.language = string_value(key, value)?,
        "appearance" => {
            let theme = string_value(key, value)?;
            if !["light", "dark", "system", "深色", "浅色"].contains(&theme.as_str()) {
                return Err(PreferencesError::InvalidSetting(key.into()));
            }
            preferences.settings.appearance = theme;
        }
        "connectionMode" => {
            let mode = string_value(key, value)?;
            if mode != "client" && mode != "proxy" {
                return Err(PreferencesError::InvalidSetting(key.into()));
            }
            preferences.settings.connection_mode = mode;
        }
        _ => return Err(PreferencesError::UnknownSetting(key.into())),
    }
    Ok(())
}

fn string_value(key: &str, value: Value) -> Result<String, PreferencesError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| PreferencesError::InvalidSetting(key.into()))
}

fn bool_value(key: &str, value: Value) -> Result<bool, PreferencesError> {
    value
        .as_bool()
        .ok_or_else(|| PreferencesError::InvalidSetting(key.into()))
}
