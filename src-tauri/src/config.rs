use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{DownloadFormat, ProxyMode};
use serde::{Deserialize, Serialize};
use specta::Type;
use tauri::{AppHandle, Manager};

const API_DOMAIN_1: &str = "www.cdnzack.cc";
const API_DOMAIN_2: &str = "www.cdnhth.cc";
const API_DOMAIN_3: &str = "www.cdnhth.net";
const API_DOMAIN_4: &str = "www.cdnbea.net";
const API_DOMAIN_5: &str = "www.cdn-mspjmapiproxy.xyz";

// 获取最新 API 域名的服务器列表（对齐 JMComic-Crawler-Python 的配置）
const API_DOMAIN_SERVER_LIST: &[&str] = &[
    "https://rup4a04-c01.tos-ap-southeast-1.bytepluses.com/newsvr-2025.txt",
    "https://rup4a04-c02.tos-cn-hongkong.bytepluses.com/newsvr-2025.txt",
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
    #[serde(default)]
    pub dynamic_api_domains: Vec<String>,
    pub last_api_domain_update_time: u64,
    /// 上次成功的 API 域名，下次启动时优先尝试，减少逐个切换的耗时
    #[serde(default)]
    pub last_working_api_domain: Option<String>,
}

impl Config {
    fn all_static_api_domains() -> [&'static str; 5] {
        [API_DOMAIN_1, API_DOMAIN_2, API_DOMAIN_3, API_DOMAIN_4, API_DOMAIN_5]
    }

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

    /// 获取候选 API 域名列表（按优先级排序，自动去重）。
    /// - 上次成功的域名（持久化）优先，以加速后续请求
    /// - 动态域名（手动刷新得到）其次
    /// - 当前静态线路（线路1-5或自定义）再次
    /// - 其余内置静态域名最后
    pub fn get_api_domain_candidates(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();

        let mut push_unique = |v: String| {
            if v.trim().is_empty() {
                return;
            }
            if !out.iter().any(|x| x == &v) {
                out.push(v);
            }
        };

        // 1) 动态域名（保持顺序，去重）
        for d in &self.dynamic_api_domains {
            push_unique(d.clone());
        }

        // 2) 当前静态线路（或自定义）
        push_unique(self.get_api_domain());

        // 3) 其余内置静态域名
        for d in Self::all_static_api_domains() {
            push_unique(d.to_string());
        }

        // 4) 若上次成功的域名在候选中，移到最前
        if let Some(ref last) = self.last_working_api_domain {
            if let Some(pos) = out.iter().position(|d| d == last) {
                if pos > 0 {
                    let d = out.remove(pos);
                    out.insert(0, d);
                }
            }
        }

        out
    }

    /// 返回当前应当使用的 API 域名：
    /// - 如果存在动态域名（通过 appload 获取），优先使用第一个动态域名；
    /// - 否则回退到静态配置的 api_domain（线路1-5或自定义）。
    pub fn get_effective_api_domain(&self) -> String {
        if let Some(first) = self.dynamic_api_domains.first() {
            first.clone()
        } else {
            self.get_api_domain()
        }
    }

    /// 合并动态域名列表：把新获取的域名插到最前，去重，并限制数量。
    pub fn merge_dynamic_api_domains(&mut self, domains: Vec<String>) {
        const MAX_DYNAMIC_DOMAINS: usize = 10;

        let mut merged: Vec<String> = Vec::new();

        let mut push_unique = |v: String| {
            let v = v.trim().to_string();
            if v.is_empty() {
                return;
            }
            if !merged.iter().any(|x| x == &v) {
                merged.push(v);
            }
        };

        // 新域名优先（插队到最前）
        for d in domains {
            push_unique(d);
        }

        // 再拼接旧的动态域名（保持旧顺序）
        for d in self.dynamic_api_domains.clone() {
            push_unique(d);
        }

        merged.truncate(MAX_DYNAMIC_DOMAINS);
        self.dynamic_api_domains = merged;
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
            last_working_api_domain: None,
        }
    }

    /// 记录成功的 API 域名（仅在变更时持久化，减少磁盘写入）
    pub fn set_last_working_api_domain_if_changed(
        config: &mut parking_lot::RwLockWriteGuard<'_, Self>,
        domain: &str,
        app: &AppHandle,
    ) {
        if config.last_working_api_domain.as_deref() != Some(domain) {
            config.last_working_api_domain = Some(domain.to_string());
            if let Err(e) = config.save(app) {
                tracing::warn!("保存 last_working_api_domain 失败: {}", e);
            }
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
