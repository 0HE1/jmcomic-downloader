use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{DownloadFormat, ProxyMode};
use serde::{Deserialize, Serialize};
use specta::Type;
use tauri::{AppHandle, Manager};

use chrono::Local;  // 新增：用于日期格式化

const API_DOMAIN_1: &str = "www.cdnzack.cc";
const API_DOMAIN_2: &str = "www.cdnhth.cc";
const API_DOMAIN_3: &str = "www.cdnhth.net";
const API_DOMAIN_4: &str = "www.cdnbea.net";
const API_DOMAIN_5: &str = "www.cdn-mspjmapiproxy.xyz";

// 获取最新 API 域名的服务器列表
const API_DOMAIN_SERVER_LIST: &[&str] = &[
    "https://jm365.work/jmcomic/jmapi/appload",
    "https://jmcomic-fb.vip/jmcomic/jmapi/appload",
];

// 解密 API 域名服务器信息的密钥
const API_DOMAIN_SERVER_SECRET: &str = "diosfjckwpqpdfjkvnqQjsik";

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub username: String,
    pub password: String,
    pub download_dir: PathBuf,
    pub export_dir: PathBuf,
    pub download_format: DownloadFormat,
    pub dir_fmt: String,
    pub proxy_mode: ProxyMode,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub enable_file_logger: bool,
    pub chapter_concurrency: usize,
    pub chapter_download_interval_sec: u64,
    pub img_concurrency: usize,
    pub img_download_interval_sec: u64,
    pub download_all_favorites_interval_sec: u64,
    pub update_downloaded_comics_interval_sec: u64,
    pub api_domain_mode: ApiDomainMode,
    pub custom_api_domain: String,
    #[serde(skip)]
    pub dynamic_api_domains: Vec<String>,
    pub last_api_domain_update_time: u64,
}

impl Config {
    pub fn new(app: &AppHandle) -> anyhow::Result<Self> {
        let app_data_dir = app.path().app_data_dir()?;
        let config_path = app_data_dir.join("config.json");

        let config = if config_path.exists() {
            let config_string = std::fs::read_to_string(&config_path)?;
            match serde_json::from_str(&config_string) {
                Ok(config) => config,
                Err(_) => Config::merge_config(&config_string, &app_data_dir),
            }
        } else {
            Config::default(&app_data_dir)
        };

        config.save(app)?;
        Ok(config)
    }

    pub fn save(&self, app: &AppHandle) -> anyhow::Result<()> {
        let resource_dir = app.path().app_data_dir()?;
        let config_path = resource_dir.join("config.json");
        let config_string = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, config_string)?;
        Ok(())
    }

    pub fn get_api_domain(&self) -> String {
        match self.api_domain_mode {
            ApiDomainMode::Domain1 => API_DOMAIN_1.to_string(),
            ApiDomainMode::Domain2 => API_DOMAIN_2.to_string(),
            ApiDomainMode::Domain3 => API_DOMAIN_3.to_string(),
            ApiDomainMode::Domain4 => API_DOMAIN_4.to_string(),
            ApiDomainMode::Domain5 => API_DOMAIN_5.to_string(),
            ApiDomainMode::Custom => self.custom_api_domain.clone(),
        }
    }

    pub fn get_dynamic_api_domains(&self) -> Vec<String> {
        if self.dynamic_api_domains.is_empty() {
            vec![
                API_DOMAIN_1.to_string(),
                API_DOMAIN_2.to_string(),
                API_DOMAIN_3.to_string(),
                API_DOMAIN_4.to_string(),
                API_DOMAIN_5.to_string(),
            ]
        } else {
            self.dynamic_api_domains.clone()
        }
    }

    pub fn should_update_dynamic_api_domains(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now - self.last_api_domain_update_time > 86400
    }

    pub fn update_dynamic_api_domains(&mut self, domains: Vec<String>) {
        self.dynamic_api_domains = domains;
        self.last_api_domain_update_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    pub fn get_api_domain_server_list() -> &'static [&'static str] {
        API_DOMAIN_SERVER_LIST
    }

    pub fn get_api_domain_server_secret() -> &'static str {
        API_DOMAIN_SERVER_SECRET
    }

    fn merge_config(config_string: &str, app_data_dir: &Path) -> Config {
        let Ok(mut json_value) = serde_json::from_str::<serde_json::Value>(config_string) else {
            return Config::default(app_data_dir);
        };

        let serde_json::Value::Object(ref mut map) = json_value else {
            return Config::default(app_data_dir);
        };

        let Ok(default_value) = serde_json::to_value(Config::default(app_data_dir)) else {
            return Config::default(app_data_dir);
        };

        let serde_json::Value::Object(default_map) = default_value else {
            return Config::default(app_data_dir);
        };

        for (key, value) in default_map {
            map.entry(key).or_insert(value);
        }

        serde_json::from_value(json_value).unwrap_or_else(|_| Config::default(app_data_dir))
    }

    fn default(app_data_dir: &Path) -> Config {
        Config {
            username: String::new(),
            password: String::new(),
            download_dir: app_data_dir.join("漫画下载"),
            export_dir: app_data_dir.join("漫画导出"),
            download_format: DownloadFormat::default(),
            dir_fmt: "{comic_title}/{chapter_title}".to_string(),
            proxy_mode: ProxyMode::default(),
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 7890,
            enable_file_logger: true,
            chapter_concurrency: 3,
            chapter_download_interval_sec: 0,
            img_concurrency: 20,
            img_download_interval_sec: 0,
            download_all_favorites_interval_sec: 0,
            update_downloaded_comics_interval_sec: 0,
            api_domain_mode: ApiDomainMode::Domain2,
            custom_api_domain: API_DOMAIN_2.to_string(),
            dynamic_api_domains: Vec::new(),
            last_api_domain_update_time: 0,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Type)]
pub enum ApiDomainMode {
    Domain1,
    #[default]
    Domain2,
    Domain3,
    Domain4,
    Domain5,
    Custom,
}
