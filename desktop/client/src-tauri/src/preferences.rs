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
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            autostart: false,
            close_to_tray: true,
            disconnect_on_exit: true,
            language: "简体中文".into(),
            appearance: "深色".into(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Preferences {
    pub subscription_url: String,
    pub ppp_path: String,
    pub raw_config: String,
    pub favorites: BTreeSet<String>,
    pub manual_nodes: Vec<SubscriptionNode>,
    pub launch_options: BTreeMap<String, Value>,
    pub settings: ClientSettings,
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
}

pub fn load_preferences(path: &Path) -> Result<Preferences, PreferencesError> {
    if !path.exists() {
        return Ok(Preferences::default());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn save_preferences(path: &Path, preferences: &Preferences) -> Result<(), PreferencesError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(preferences)?)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn update_setting(
    preferences: &mut Preferences,
    key: &str,
    value: Value,
) -> Result<(), PreferencesError> {
    match key {
        "pppPath" => preferences.ppp_path = string_value(key, value)?,
        "autostart" => preferences.settings.autostart = bool_value(key, value)?,
        "closeToTray" => preferences.settings.close_to_tray = bool_value(key, value)?,
        "disconnectOnExit" => preferences.settings.disconnect_on_exit = bool_value(key, value)?,
        "language" => preferences.settings.language = string_value(key, value)?,
        "appearance" => preferences.settings.appearance = string_value(key, value)?,
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
