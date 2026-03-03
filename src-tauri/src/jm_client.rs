use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes:: cipher:: generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use anyhow::{anyhow, Context};
use base64::engine::general_purpose;
use base64::Engine;
use bytes::Bytes;
use image:: ImageFormat;
use parking_lot::RwLock;
use reqwest:: cookie:: Jar;
use reqwest::header::CONTENT_TYPE;
use reqwest::StatusCode;
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::{Jitter, RetryTransientMiddleware};
use serde_json::json;
use tauri::AppHandle;

use crate::download_manager::IMAGE_DOMAIN;
use crate::extensions::{AnyhowErrorToStringChain, AppHandleExt};
use crate::responses::{
    GetChapterRespData, GetComicRespData, GetFavoriteRespData, GetUserProfileRespData,
    GetWeeklyInfoRespData, GetWeeklyRespData, JmResp, RedirectRespData, SearchResp, SearchRespData,
    ToggleFavoriteRespData,
};
use crate::types::{FavoriteSort, ProxyMode, SearchSort};
use crate::utils;
use futures::future::{select_ok, FutureExt};

const APP_TOKEN_SECRET: &str = "18comicAPP";
const APP_TOKEN_SECRET_2: &str = "18comicAPPContent";
const APP_DATA_SECRET: &str = "185Hcomic3PAPP7R";
const APP_VERSION: &str = "2.0.13";

#[derive(Debug, Clone, PartialEq)]
enum ApiPath {
    Login,
    GetUserProfile,
    Search,
    GetComic,
    GetChapter,
    GetScrambleId,
    GetFavoriteFolder,
    GetWeeklyInfo,
    GetWeekly,
}

impl ApiPath {
    fn as_str(&self) -> &'static str {
        match self {
            ApiPath::Login | ApiPath::GetUserProfile => "/login",
            ApiPath::Search => "/search",
            ApiPath:: GetComic => "/album",
            ApiPath::GetChapter => "/chapter",
            ApiPath::GetScrambleId => "/chapter_view_template",
            ApiPath::GetFavoriteFolder => "/favorite",
            ApiPath::GetWeeklyInfo => "/week",
            ApiPath::GetWeekly => "/week/filter",
        }
    }
}

#[derive(Clone)]
pub struct JmClient {
    app:  AppHandle,
    api_client: Arc<RwLock<ClientWithMiddleware>>,
    api_jar: Arc<Jar>,
    img_client: Arc<RwLock<ClientWithMiddleware>>,
    domain_client: Arc<RwLock<ClientWithMiddleware>>,
    /// 上次成功的 API 域名，下次请求时优先使用，减少逐个切换的耗时
    last_working_domain: Arc<RwLock<Option<String>>>,
}

impl JmClient {
    pub fn new(app: AppHandle) -> Self {
        let api_jar = Arc::new(Jar:: default());
        let api_client = create_api_client(&app, &api_jar);
        let api_client = Arc::new(RwLock::new(api_client));

        let img_client = create_img_client(&app);
        let img_client = Arc::new(RwLock:: new(img_client));

        // ✨ 新增：创建域名获取客户端
        let domain_client = create_domain_client(&app);
        let domain_client = Arc::new(RwLock::new(domain_client));

        Self {
            app,
            api_client,
            api_jar,
            img_client,
            domain_client,
            last_working_domain: Arc::new(RwLock::new(None)),
        }
    }

    pub fn reload_client(&self) {
        let api_client = create_api_client(&self.app, &self.api_jar);
        *self.api_client.write() = api_client;
        let img_client = create_img_client(&self.app);
        *self.img_client.write() = img_client;
        // ✨ 新增：重新加载域名获取客户端
        let domain_client = create_domain_client(&self.app);
        *self.domain_client.write() = domain_client;
    }

    /// 启动预热：后台快速探测可用 API 域名，减少首次搜索/下载的顿挫感。
    ///
    /// - 不解析业务数据，只判断是否返回 HTML/异常状态。
    /// - 成功后会更新内存里的 `last_working_domain`，并落盘到配置的 `last_working_api_domain`。
    pub async fn warm_up_api_domain(&self) -> anyhow::Result<Option<String>> {
        // 先尝试刷新动态域名（受 24h 节流限制）。即使失败也不影响后续探测。
        if let Err(err) = self.update_api_domains_if_needed().await {
            tracing::debug!("启动预热：刷新动态API域名失败（忽略）：{err:#}");
        }

        let domains = {
            let config_state = self.app.get_config();
            let config_guard = config_state.read();
            config_guard.get_api_domain_candidates()
        };

        // 如果配置里已有上次成功域名，先写入内存，让后续请求优先走单线快速尝试。
        if let Some(first) = domains.first().cloned() {
            *self.last_working_domain.write() = Some(first);
        }

        const PROBE_MAX: usize = 3;
        let domains_to_try: Vec<String> = domains.into_iter().take(PROBE_MAX).collect();
        if domains_to_try.is_empty() {
            return Ok(None);
        }

        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let tokenparam = format!("{ts},{APP_VERSION}");
        let token = utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET}"));
        let path = ApiPath::GetWeeklyInfo.as_str();

        let client = create_api_probe_client(&self.app)?;
        let futures: Vec<_> = domains_to_try
            .into_iter()
            .map(|domain| {
                let client = client.clone();
                let token = token.clone();
                let tokenparam = tokenparam.clone();
                async move {
                    let url = format!("https://{domain}{path}");
                    let req = client
                        .get(&url)
                        .header("token", token)
                        .header("tokenparam", tokenparam)
                        .header(
                            "user-agent",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                        );

                    let resp = match tokio::time::timeout(Duration::from_secs(3), req.send()).await {
                        Ok(Ok(resp)) => resp,
                        _ => return Err(()),
                    };

                    if resp.status() != StatusCode::OK {
                        return Err(());
                    }

                    let is_html = resp
                        .headers()
                        .get(CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.trim_start().starts_with("text/html"))
                        .unwrap_or(false);
                    if is_html {
                        return Err(());
                    }

                    // 兜底：若 content-type 缺失，尝试读一点内容判断是否 HTML。
                    if resp.headers().get(CONTENT_TYPE).is_none() {
                        let text = match tokio::time::timeout(Duration::from_secs(3), resp.text()).await
                        {
                            Ok(Ok(text)) => text,
                            _ => return Err(()),
                        };
                        if text.trim_start().starts_with('<') {
                            return Err(());
                        }
                    }

                    Ok::<String, ()>(domain)
                }
                .boxed()
            })
            .collect();

        match select_ok(futures).await {
            Ok((domain, _)) => {
                *self.last_working_domain.write() = Some(domain.clone());
                let config_state = self.app.get_config();
                let mut config_guard = config_state.write();
                crate::config::Config::set_last_working_api_domain_if_changed(
                    &mut config_guard,
                    &domain,
                    &self.app,
                );
                tracing::debug!("启动预热：已选定可用API域名 `{domain}`");
                Ok(Some(domain))
            }
            Err(_) => Ok(None),
        }
    }

    async fn fetch_api_domains_from_servers(&self) -> anyhow::Result<Vec<String>> {
        // 从服务器获取最新的API域名
        let server_list = crate::config::Config::get_api_domain_server_list();
        let secret = crate::config::Config::get_api_domain_server_secret();

        for server_url in server_list {
            match self.req_api_domain_server(server_url, secret).await {
                Ok(domains) => return Ok(domains),
                Err(e) => {
                    tracing::warn!("Failed to get API domains from {}: {}", server_url, e);
                    continue;
                }
            }
        }

        Err(anyhow!(
            "Failed to get API domains from all servers, using default domains"
        ))
    }

    /// 按需刷新动态 API 域名（受 24h 节流限制）。
    pub async fn update_api_domains_if_needed(&self) -> anyhow::Result<()> {
        let config = self.app.get_config();
        if !config.read().should_update_dynamic_api_domains() {
            return Ok(());
        }

        let domains = self.fetch_api_domains_from_servers().await?;
        let mut config_guard = config.write();
        config_guard.merge_dynamic_api_domains(domains);
        config_guard.last_api_domain_update_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = config_guard.save(&self.app);
        Ok(())
    }

    /// 强制刷新动态 API 域名（用于手动点击“刷新动态API域名”，不受 24h 节流限制）。
    pub async fn update_api_domains_force(&self) -> anyhow::Result<()> {
        let domains = self.fetch_api_domains_from_servers().await?;

        let config = self.app.get_config();
        let mut config_guard = config.write();
        config_guard.merge_dynamic_api_domains(domains);
        config_guard.last_api_domain_update_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = config_guard.save(&self.app);
        Ok(())
    }

    // ✨ 新增：请求API域名服务器
    async fn req_api_domain_server(
        &self,
        url: &str,
        secret: &str,
    ) -> anyhow::Result<Vec<String>> {
        let resp = self.domain_client.read().get(url).send().await?;
        let mut text = resp.text().await?;

        // 去掉开头非ascii字符
        while ! text.is_empty() && !text.chars().next().unwrap().is_ascii() {
            text = text[1..]. to_string();
        }

        // 如果返回的是明显的HTML/Cloudflare页面，直接给出更友好的错误信息
        let trimmed = text.trim_start();
        if trimmed.starts_with('<') {
            return Err(anyhow!(
                "API域名服务器返回HTML页面，可能被Cloudflare或防火墙拦截，请开启代理或更换网络后重试"
            ));
        }

        // 解密响应数据
        let res_json = decrypt_api_domain_server_data(&text, secret)?;
        let res_data: serde_json::Value = serde_json::from_str(&res_json)?;

        // 检查返回值：支持 Server 为字符串或字符串数组
        if let Some(server_val) = res_data.get("Server") {
            if let Some(s) = server_val.as_str() {
                if !s.is_empty() {
                    return Ok(vec![s.to_string()]);
                }
            } else if let Some(arr) = server_val.as_array() {
                let domains: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                if !domains.is_empty() {
                    return Ok(domains);
                }
            }
        }

        Err(anyhow!(
            "Failed to parse API domain server response: {}",
            res_json
        ))
    }

    async fn jm_request(
        &self,
        method: reqwest::Method,
        path: ApiPath,
        query:  Option<serde_json::Value>,
        form: Option<serde_json:: Value>,
        ts: u64,
    ) -> anyhow::Result<reqwest::Response> {
        let tokenparam = format!("{ts},{APP_VERSION}");
        let token = if path == ApiPath::GetScrambleId {
            utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET_2}"))
        } else {
            utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET}"))
        };

        // 读取候选域名池（动态优先 + 当前静态 + 其余静态）
        let mut domains = {
            let config_state = self.app.get_config();
            let config_guard = config_state.read();
            config_guard.get_api_domain_candidates()
        };

        // 若上次有成功的域名且在候选中，将其移到最前，减少逐个切换的耗时
        if let Some(ref last) = *self.last_working_domain.read() {
            if let Some(pos) = domains.iter().position(|d| d == last) {
                if pos > 0 {
                    let d = domains.remove(pos);
                    domains.insert(0, d);
                }
            }
        }

        let path_str = path.as_str().to_string();
        const MAX_DOMAIN_TRIES: usize = 5;

        let is_transient_status = |status: StatusCode| -> bool {
            matches!(
                status,
                StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
            ) || matches!(status.as_u16(), 521 | 522 | 524)
        };

        let is_html_resp = |resp: &reqwest::Response| -> bool {
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.trim_start().starts_with("text/html"))
                .unwrap_or(false)
        };

        // 单线快速尝试：如果候选池首位域名可用，则直接返回，避免每次都并行打满 5 条线路造成顿挫。
        // 若失败（超时/HTML/临时错误等），再回退到原有的“多域名并行 + 顺序重试”策略。
        let config_state = self.app.get_config();
        let send_with_domain = |domain: &str| {
            let domain = domain.to_string();
            let client = self.api_client.read().clone();
            let method = method.clone();
            let query = query.clone();
            let form = form.clone();
            let token = token.clone();
            let tokenparam = tokenparam.clone();
            let url = format!("https://{domain}{}", path.as_str());

            async move {
                let request = client
                    .request(method, &url)
                    .header("token", token)
                    .header("tokenparam", tokenparam)
                    .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");

                let resp = match form {
                    Some(payload) => request.query(&query).form(&payload).send().await,
                    None => request.query(&query).send().await,
                };

                resp.map_err(|e| {
                    if e.is_timeout() {
                        anyhow::Error::from(e).context("连接超时，请使用代理或换条线路重试")
                    } else {
                        anyhow::Error::from(e)
                    }
                })
            }
        };

        if let Some(domain) = domains.iter().take(MAX_DOMAIN_TRIES).next().cloned() {
            let attempt =
                tokio::time::timeout(Duration::from_secs(4), send_with_domain(&domain)).await;

            if let Ok(Ok(resp)) = attempt {
                let status = resp.status();
                if !is_html_resp(&resp) && !is_transient_status(status) {
                    *self.last_working_domain.write() = Some(domain.clone());
                    let mut config_guard = config_state.write();
                    crate::config::Config::set_last_working_api_domain_if_changed(
                        &mut config_guard,
                        &domain,
                        &self.app,
                    );
                    return Ok(resp);
                }
            }

            // 已经快速尝试过首选域名，后续并行/顺序阶段跳过它，减少重复等待。
            if domains.first().map(|d| d == &domain).unwrap_or(false) {
                domains.remove(0);
            }
        }

        // 并行尝试多个域名，取首个返回有效 JSON 的响应，减少首包延迟
        let domains_to_try: Vec<String> = domains.iter().take(MAX_DOMAIN_TRIES).cloned().collect();
        let client = self.api_client.read().clone();

        let futures: Vec<_> = domains_to_try
            .iter()
            .map(|domain| {
                let client = client.clone();
                let method = method.clone();
                let query = query.clone();
                let form = form.clone();
                let token = token.clone();
                let tokenparam = tokenparam.clone();
                let path_str = path_str.clone();
                let domain = domain.clone();

                async move {
                    let url = format!("https://{domain}{path_str}");
                    let request = client
                        .request(method, &url)
                        .header("token", token)
                        .header("tokenparam", tokenparam)
                        .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");

                    let resp = match form {
                        Some(payload) => request.query(&query).form(&payload).send().await,
                        None => request.query(&query).send().await,
                    };

                    let resp = resp.map_err(|_| ())?;
                    let status = resp.status();
                    let is_html = resp
                        .headers()
                        .get(CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.trim_start().starts_with("text/html"))
                        .unwrap_or(false);

                    if is_html || is_transient_status(status) {
                        Err(())
                    } else {
                        Ok((domain, resp))
                    }
                }
                .boxed()
            })
            .collect();

        match select_ok(futures).await {
            Ok(((domain, resp), _remaining)) => {
                *self.last_working_domain.write() = Some(domain.clone());
                let config_state = self.app.get_config();
                let mut config_guard = config_state.write();
                crate::config::Config::set_last_working_api_domain_if_changed(
                    &mut config_guard, &domain, &self.app,
                );
                return Ok(resp);
            }
            Err(_) => {
                // 并行全部失败，回退到顺序重试以获取详细错误信息
                let mut last_err: Option<anyhow::Error> = None;
                let mut last_transient_resp: Option<reqwest::Response> = None;

                for (idx, domain) in domains.iter().take(MAX_DOMAIN_TRIES).enumerate() {
                    match send_with_domain(domain).await {
                        Ok(resp) => {
                            let status = resp.status();
                            let is_html = is_html_resp(&resp);

                            if is_html || is_transient_status(status) {
                                last_transient_resp = Some(resp);
                                let next_domain = domains
                                    .iter()
                                    .take(MAX_DOMAIN_TRIES)
                                    .nth(idx + 1)
                                    .cloned()
                                    .unwrap_or_default();
                                if !next_domain.is_empty() {
                                    tracing::warn!(
                                        "使用域名 `{}` 请求失败（status={:?}, html={}），尝试切换到 `{}`",
                                        domain, status, is_html, next_domain
                                    );
                                }
                                continue;
                            }
                            *self.last_working_domain.write() = Some(domain.clone());
                            let mut config_guard = config_state.write();
                            crate::config::Config::set_last_working_api_domain_if_changed(
                                &mut config_guard, domain, &self.app,
                            );
                            return Ok(resp);
                        }
                        Err(err) => {
                            last_err = Some(err);
                            let next_domain = domains
                                .iter()
                                .take(MAX_DOMAIN_TRIES)
                                .nth(idx + 1)
                                .cloned()
                                .unwrap_or_default();
                            if !next_domain.is_empty() {
                                tracing::warn!(
                                    "使用域名 `{}` 请求出错，尝试切换到 `{}`",
                                    domain, next_domain
                                );
                            }
                            continue;
                        }
                    }
                }

                if let Some(resp) = last_transient_resp {
                    return Ok(resp);
                }
                Err(last_err.unwrap_or_else(|| anyhow!("未找到可用的 API 域名候选项")))
            }
        }
    }

    async fn jm_get(
        &self,
        path: ApiPath,
        query:  Option<serde_json::Value>,
        ts: u64,
    ) -> anyhow::Result<reqwest::Response> {
        self.jm_request(reqwest::Method::GET, path, query, None, ts)
            .await
    }

    async fn jm_post(
        &self,
        path: ApiPath,
        query: Option<serde_json::Value>,
        payload: Option<serde_json::Value>,
        ts: u64,
    ) -> anyhow::Result<reqwest::Response> {
        self.jm_request(reqwest::Method::POST, path, query, payload, ts)
            .await
    }

    // ...  (其他方法保持不变) ...
    pub async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<GetUserProfileRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?. as_secs();
        let form = json!({
            "username": username,
            "password": password,
        });
        // 发送登录请求
        let http_resp = self.jm_post(ApiPath::Login, None, Some(form), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "使用账号密码登录失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!(
    "使用账号密码登录失败，预料之外的code: {:?}",
    jm_resp
));

        }
        // 检查JmResp的data字段
        let data = jm_resp.data.as_str().context(format!(
            "使用账号密码登录失败，data字段不是字符串: {jm_resp:?}"
        ))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetUserProfileRespData
        let mut user_profile = serde_json::from_str::<GetUserProfileRespData>(&data).context(
            format!("将解密后的data字段解析为GetUserProfileRespData失败: {data}"),
        )?;
        user_profile.photo = format!("https://{IMAGE_DOMAIN}/media/users/{}", user_profile.photo);

        Ok(user_profile)
    }

    pub async fn get_user_profile(&self) -> anyhow::Result<GetUserProfileRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // 发送获取用户信息请求
        let http_resp = self
            .jm_post(ApiPath::GetUserProfile, None, None, ts)
            .await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status == reqwest::StatusCode:: UNAUTHORIZED {
            return Err(anyhow! ("获取用户信息失败，Cookie无效或已过期，请重新登录"));
        } else if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "获取用户信息失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!(
    "获取用户信息失败，预料之外的code: {:?}",
    jm_resp
));

        }
        // 检查JmResp的data字段
        let data = jm_resp
            .data
            .as_str()
            .context(format!("获取用户信息失败，data字段不是字符串: {jm_resp:? }"))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetUserProfileRespData
        let mut user_profile = serde_json::from_str::<GetUserProfileRespData>(&data).context(
            format!("将解密后的data字段解析为GetUserProfileRespData失败: {data}"),
        )?;
        user_profile. photo = format!("https://{IMAGE_DOMAIN}/media/users/{}", user_profile.photo);

        Ok(user_profile)
    }

    pub async fn search(
        &self,
        keyword: &str,
        page:  i64,
        sort:  SearchSort,
    ) -> anyhow::Result<SearchResp> {
        let query = json!({
            "main_tag": 0,
            "search_query": keyword,
            "page":  page,
            "o":  sort.as_str(),
        });
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // 发送搜索请求
        let http_resp = self.jm_get(ApiPath::Search, Some(query), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow! ("搜索失败，预料之外的状态码({status}): {body}"));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败:  {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("搜索失败，预料之外的code: {jm_resp:? }"));
        }
        // 检查JmResp的data字段
        let data = jm_resp
            .data
            .as_str()
            .context(format!("搜索失败，data字段不是字符串: {jm_resp:?}"))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的数据解析为 RedirectRespData
        if let Ok(redirect_resp_data) = serde_json::from_str::<RedirectRespData>(&data) {
            let comic_resp_data = self
                .get_comic(redirect_resp_data.redirect_aid. parse()?)
                .await?;
            return Ok(SearchResp:: ComicRespData(Box::new(comic_resp_data)));
        }
        // 尝试将解密后的data字段解析为 SearchRespData
        if let Ok(search_resp_data) = serde_json::from_str::<SearchRespData>(&data) {
            return Ok(SearchResp::SearchRespData(search_resp_data));
        }
        Err(anyhow!(
            "将解密后的数据解析为SearchRespData或RedirectRespData失败:  {data}"
        ))
    }

    pub async fn get_comic(&self, aid: i64) -> anyhow::Result<GetComicRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let query = json!({"id": aid,});
        // 发送获取漫画请求
        let http_resp = self.jm_get(ApiPath::GetComic, Some(query), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!("获取漫画失败，预料之外的状态码({status}): {body}"));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format! ("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp. code != 200 {
            return Err(anyhow! ("获取漫画失败，预料之外的code:  {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp
            .data
            .as_str()
            .context(format!("获取漫画失败，data字段不是字符串: {jm_resp:?}"))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetComicRespData
        let comic = serde_json::from_str::<GetComicRespData>(&data).context(format!(
            "将解密后的data字段解析为GetComicRespData失败: {data}"
        ))?;
        Ok(comic)
    }

    pub async fn get_chapter(&self, id: i64) -> anyhow::Result<GetChapterRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let query = json!({"id": id,});
        // 发送获取章节请求
        let http_resp = self.jm_get(ApiPath::GetChapter, Some(query), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow! ("获取章节失败，预料之外的状态码({status}): {body}"));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json:: from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("获取章节失败，预料之外的code: {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp
            .data
            .as_str()
            .context(format! ("获取章节失败，data字段不是字符串: {jm_resp:? }"))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetChapterRespData
        let chapter = serde_json::from_str::<GetChapterRespData>(&data).context(format!(
            "将解密后的data字段解析为GetChapterRespData失败: {data}"
        ))?;
        Ok(chapter)
    }

    /// 在同一个域名下获取章节详情和 scramble_id，确保下载前只做一次域名选择。
    pub async fn get_chapter_bootstrap(
        &self,
        id: i64,
    ) -> anyhow::Result<(i64, GetChapterRespData)> {
        let config_state = self.app.get_config();
        let domains = {
            let guard = config_state.read();
            guard.get_api_domain_candidates()
        };

        const MAX_TRIES: usize = 5;
        let candidate_domains: Vec<String> = domains.into_iter().take(MAX_TRIES).collect();
        if candidate_domains.is_empty() {
            return Err(anyhow!("获取章节启动信息失败：没有可用的API域名候选项"));
        }

        for domain in candidate_domains {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            // 根据接口类型分别生成 token
            let token_chapter = utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET}"));
            let token_scramble = utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET_2}"));
            let tokenparam = format!("{ts},{APP_VERSION}");

            let chapter_query = json!({
                "id": id,
            });
            let scramble_query = json!({
                "id": id,
                "v": ts,
                "mode": "vertical",
                "page": 0,
                "app_img_shunt": 1,
                "express": "off",
            });

            let client = self.api_client.read().clone();
            let chapter_url = format!("https://{domain}{}", ApiPath::GetChapter.as_str());
            let scramble_url = format!("https://{domain}{}", ApiPath::GetScrambleId.as_str());

            let chapter_req = client
                .get(&chapter_url)
                .header("token", token_chapter.clone())
                .header("tokenparam", tokenparam.clone())
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                )
                .query(&chapter_query);

            let scramble_req = client
                .get(&scramble_url)
                .header("token", token_scramble.clone())
                .header("tokenparam", tokenparam.clone())
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                )
                .query(&scramble_query);

            let res = tokio::time::timeout(Duration::from_secs(6), async {
                tokio::join!(chapter_req.send(), scramble_req.send())
            })
            .await;

            let (chapter_res, scramble_res) = match res {
                Ok(tuple) => tuple,
                Err(_) => {
                    tracing::warn!(
                        "章节启动：域名 `{domain}` 在 6 秒内未同时返回章节与scramble_id响应，尝试下一个域名"
                    );
                    continue;
                }
            };

            let chapter_resp = match chapter_res {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::warn!(
                        "章节启动：域名 `{domain}` 章节请求出错: {err:#}"
                    );
                    continue;
                }
            };

            let scramble_resp = match scramble_res {
                Ok(resp) => resp,
                Err(err) => {
                    tracing::warn!(
                        "章节启动：域名 `{domain}` 获取scramble_id请求出错: {err:#}"
                    );
                    continue;
                }
            };

            let chapter_status = chapter_resp.status();
            let scramble_status = scramble_resp.status();

            let chapter_body: String = match chapter_resp.text().await {
                Ok(text) => text,
                Err(err) => {
                    tracing::warn!(
                        "章节启动：域名 `{domain}` 读取章节响应失败: {err:#}"
                    );
                    continue;
                }
            };

            let scramble_body: String = match scramble_resp.text().await {
                Ok(text) => text,
                Err(err) => {
                    tracing::warn!(
                        "章节启动：域名 `{domain}` 读取scramble_id响应失败: {err:#}"
                    );
                    continue;
                }
            };

            if chapter_status != reqwest::StatusCode::OK {
                tracing::warn!(
                    "章节启动：域名 `{domain}` 返回章节非200状态码({chapter_status})，尝试下一个域名"
                );
                continue;
            }

            if scramble_status != reqwest::StatusCode::OK {
                tracing::warn!(
                    "章节启动：域名 `{domain}` 返回scramble_id非200状态码({scramble_status})，尝试下一个域名"
                );
                continue;
            }

            let scramble_id = scramble_body
                .split("var scramble_id = ")
                .nth(1)
                .and_then(|s| s.split(';').next())
                .and_then(|s| s.parse::<i64>().ok());

            if scramble_id.is_none() {
                tracing::warn!(
                    "章节启动：域名 `{domain}` 的scramble_id响应未包含有效的 `var scramble_id =` 字段，可能是拦截页，尝试下一个域名"
                );
                continue;
            }

            let jm_resp = serde_json::from_str::<JmResp>(&chapter_body).context(format!(
                "将解密前的章节body解析为JmResp失败（域名 `{domain}`）: {chapter_body}"
            ))?;

            if jm_resp.code != 200 {
                tracing::warn!(
                    "章节启动：域名 `{domain}` 章节接口返回预料之外的code: {jm_resp:?}"
                );
                continue;
            }

            let data = jm_resp.data.as_str().ok_or_else(|| {
                anyhow!(
                    "章节启动：域名 `{domain}` 章节data字段不是字符串: {jm_resp:?}"
                )
            })?;

            let data = decrypt_data(ts, data)?;
            let chapter = serde_json::from_str::<GetChapterRespData>(&data).context(format!(
                "将解密后的章节data解析为GetChapterRespData失败（域名 `{domain}`）: {data}"
            ))?;

            let scramble_id = scramble_id.unwrap();

            *self.last_working_domain.write() = Some(domain.clone());
            let mut cfg_guard = config_state.write();
            crate::config::Config::set_last_working_api_domain_if_changed(
                &mut cfg_guard,
                &domain,
                &self.app,
            );

            return Ok((scramble_id, chapter));
        }

        Err(anyhow!(
            "获取章节启动信息失败：所有候选域名均未返回有效的章节数据和scramble_id，请开启代理或更换线路重试"
        ))
    }

    pub async fn get_scramble_id(&self, id: i64) -> anyhow::Result<i64> {
        // 为避免普通 API 的 HTML 拦截逻辑干扰，这里不走 jm_get/jm_request，而是按域名自行尝试，
        // 并且严格要求返回体中包含 `var scramble_id =` 才视为成功。
        let config_state = self.app.get_config();
        let domains = {
            let guard = config_state.read();
            guard.get_api_domain_candidates()
        };

        const MAX_TRIES: usize = 5;
        let candidate_domains: Vec<String> = domains.into_iter().take(MAX_TRIES).collect();
        if candidate_domains.is_empty() {
            return Err(anyhow!("获取scramble_id失败：没有可用的API域名候选项"));
        }

        for domain in candidate_domains {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let tokenparam = format!("{ts},{APP_VERSION}");
            let token = utils::md5_hex(&format!("{ts}{APP_TOKEN_SECRET_2}"));

            let query = json!({
                "id": id,
                "v": ts,
                "mode": "vertical",
                "page": 0,
                "app_img_shunt": 1,
                "express": "off",
            });

            let client = self.api_client.read().clone();
            let url = format!("https://{domain}{}", ApiPath::GetScrambleId.as_str());

            let request = client
                .get(&url)
                .header("token", token)
                .header("tokenparam", tokenparam)
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                )
                .query(&query);

            let resp = match tokio::time::timeout(Duration::from_secs(4), request.send()).await {
                Ok(Ok(resp)) => resp,
                _ => {
                    tracing::warn!("获取scramble_id：域名 `{domain}` 请求超时或出错，尝试下一个域名");
                    continue;
                }
            };

            let status = resp.status();
            let body = match resp.text().await {
                Ok(text) => text,
                Err(err) => {
                    tracing::warn!(
                        "获取scramble_id：域名 `{domain}` 读取响应失败: {err:#}"
                    );
                    continue;
                }
            };

            if status != reqwest::StatusCode::OK {
                tracing::warn!(
                    "获取scramble_id：域名 `{domain}` 返回非200状态码({status})，尝试下一个域名"
                );
                continue;
            }

            let scramble_id = body
                .split("var scramble_id = ")
                .nth(1)
                .and_then(|s| s.split(';').next())
                .and_then(|s| s.parse::<i64>().ok());

            if let Some(id) = scramble_id {
                *self.last_working_domain.write() = Some(domain.clone());
                let mut config_guard = config_state.write();
                crate::config::Config::set_last_working_api_domain_if_changed(
                    &mut config_guard,
                    &domain,
                    &self.app,
                );
                return Ok(id);
            }

            tracing::warn!(
                "获取scramble_id：域名 `{domain}` 响应未找到有效的 `var scramble_id =` 字段，可能是拦截页，尝试下一个域名"
            );
        }

        Err(anyhow!(
            "获取scramble_id失败：所有候选域名均未返回有效的 scramble_id，请开启代理或更换线路重试"
        ))
    }

    pub async fn get_favorite_folder(
        &self,
        folder_id: i64,
        page: i64,
        sort:  FavoriteSort,
    ) -> anyhow::Result<GetFavoriteRespData> {
        let ts = SystemTime:: now().duration_since(UNIX_EPOCH)?.as_secs();
        let query = json!({
            "page": page,
            "o": sort.as_str(),
            "folder_id": folder_id,
        });
        // 发送获取收藏夹请求
        let http_resp = self
            .jm_get(ApiPath::GetFavoriteFolder, Some(query), ts)
            .await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "获取收藏夹失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json:: from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("获取收藏夹失败，预料之外的code: {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp
            .data
            . as_str()
            .context(format!("获取收藏夹失败，data字段不是字符串: {jm_resp:?}"))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetFavoriteRespData
        let favorite = serde_json::from_str::<GetFavoriteRespData>(&data).context(format!(
            "将解密后的data字段解析为GetFavoriteRespData失败: {data}"
        ))?;
        Ok(favorite)
    }

    pub async fn get_weekly_info(&self) -> anyhow::Result<GetWeeklyInfoRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let http_resp = self.jm_get(ApiPath::GetWeeklyInfo, None, ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "获取每周必看信息失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json:: from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("获取每周必看信息失败，预料之外的code: {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp. data.as_str().context(format!(
            "获取每周必看信息失败，data字段不是字符串: {jm_resp:? }"
        ))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetWeeklyInfoRespData
        let weekly_info = serde_json::from_str::<GetWeeklyInfoRespData>(&data).context(format!(
            "将解密后的data字段解析为GetWeeklyInfoRespData失败: {data}"
        ))?;
        Ok(weekly_info)
    }

    pub async fn get_weekly(
        &self,
        category_id: &str,
        type_id: &str,
    ) -> anyhow::Result<GetWeeklyRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let query = json!({
            "id": category_id,
            "type": type_id,
        });
        let http_resp = self.jm_get(ApiPath::GetWeekly, Some(query), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "获取每周必看信息失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("获取每周必看信息失败，预料之外的code:  {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp. data.as_str().context(format!(
            "获取每周必看信息失败，data字段不是字符串: {jm_resp:? }"
        ))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为GetWeeklyRespData
        let get_weekly_resp_data = serde_json::from_str::<GetWeeklyRespData>(&data).context(
            format!("将解密后的data字段解析为GetWeeklyRespData失败: {data}"),
        )?;
        Ok(get_weekly_resp_data)
    }

    pub async fn toggle_favorite_comic(&self, aid: i64) -> anyhow::Result<ToggleFavoriteRespData> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let form = json!({
            "aid": aid,
        });
        // 发送 收藏/取消收藏 请求
        let http_resp = self
            .jm_post(ApiPath::GetFavoriteFolder, None, Some(form), ts)
            .await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(anyhow!(
                "收藏/取消收藏 失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 尝试将body解析为JmResp
        let jm_resp = serde_json::from_str::<JmResp>(&body)
            .context(format!("将body解析为JmResp失败: {body}"))?;
        // 检查JmResp的code字段
        if jm_resp.code != 200 {
            return Err(anyhow!("收藏/取消收藏 失败，预料之外的code: {jm_resp:?}"));
        }
        // 检查JmResp的data字段
        let data = jm_resp.data.as_str().context(format!(
            "收藏/取消收藏 失败，data字段不是字符串: {jm_resp:?}"
        ))?;
        // 解密data字段
        let data = decrypt_data(ts, data)?;
        // 尝试将解密后的data字段解析为ToggleFavoriteRespData
        let toggle_favorite_resp_data = serde_json::from_str::<ToggleFavoriteRespData>(&data)
            .context(format!(
                "将解密后的data字段解析为ToggleFavoriteRespData失败: {data}"
            ))?;
        Ok(toggle_favorite_resp_data)
    }

    pub async fn get_img_data_and_format(&self, url: &str) -> anyhow::Result<(Bytes, ImageFormat)> {
        let request = self.img_client.read().get(url);

        let http_resp = request.send().await?;
        let status = http_resp.status();
        if status != StatusCode::OK {
            let text = http_resp.text().await?;
            let err = anyhow! ("下载图片`{url}`失败，预料之外的状态码:  {text}");
            return Err(err);
        }

        let mut headers = http_resp.headers().clone();
        let mut image_data = http_resp.bytes().await?;

        if image_data.is_empty() {
            // 如果图片为空，说明jm那边缓存失效了，带上时间戳再次请求，以避免缓存
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let query = json!({"ts": ts});
            let request = self.img_client.read().get(url).query(&query);

            let http_resp = request.send().await?;
            let status = http_resp.status();
            if status != StatusCode:: OK {
                let text = http_resp.text().await?;
                let err = anyhow!("下载图片`{url}`失败，预料之外的状态码: {text}");
                return Err(err);
            }

            headers = http_resp.headers().clone();
            image_data = http_resp.bytes().await?;
        }
        // 获取 resp headers 的 content-type 字段
        let content_type = headers
            .get("content-type")
            .ok_or(anyhow!("响应中没有content-type字段"))?
            .to_str()
            .context("响应中的content-type字段不是utf-8字符串")?
            .to_string();
        // 确定原始图片格式
        let format = match content_type.as_str() {
            "image/webp" => ImageFormat::WebP,
            "image/gif" => ImageFormat:: Gif,
            _ => return Err(anyhow!("原图出现了意料之外的格式: {content_type}")),
        };

        Ok((image_data, format))
    }
}

pub fn create_api_client(app:  &AppHandle, jar: &Arc<Jar>) -> ClientWithMiddleware {
    // 为所有 API 请求增加一个整体超时，避免在网络半断开时长时间卡住顺序回退
    let builder = reqwest::ClientBuilder::new()
        .cookie_provider(jar.clone())
        .timeout(Duration::from_secs(6));

    let proxy_mode = app.get_config().read().proxy_mode.clone();
    let builder = match proxy_mode {
        ProxyMode::System => builder,
        ProxyMode::NoProxy => builder.no_proxy(),
        ProxyMode::Custom => {
            let config = app.get_config();
            let config = config.read();
            let proxy_host = &config.proxy_host;
            let proxy_port = &config.proxy_port;
            let proxy_url = format!("http://{proxy_host}:{proxy_port}");

            match reqwest::Proxy::all(&proxy_url).map_err(anyhow::Error::from) {
                Ok(proxy) => builder.proxy(proxy),
                Err(err) => {
                    let err_title = format!("`JmClient`设置代理`{proxy_url}`失败");
                    let string_chain = err. to_string_chain();
                    tracing::error!(err_title, message = string_chain);
                    builder
                }
            }
        }
    };

    let retry_policy = ExponentialBackoff::builder()
        .base(1)
        .jitter(Jitter::Bounded)
        .build_with_total_retry_duration(Duration::from_secs(5));

    reqwest_middleware::ClientBuilder::new(builder. build().unwrap())
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}

pub fn create_img_client(app: &AppHandle) -> ClientWithMiddleware {
    let builder = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(8)); // 封面/图片请求超时，Cloudflare 拦截时快速失败

    let proxy_mode = app.get_config().read().proxy_mode.clone();
    let builder = match proxy_mode {
        ProxyMode::System => builder,
        ProxyMode:: NoProxy => builder.no_proxy(),
        ProxyMode::Custom => {
            let config = app.get_config();
            let config = config.read();
            let proxy_host = &config. proxy_host;
            let proxy_port = &config.proxy_port;
            let proxy_url = format!("http://{proxy_host}:{proxy_port}");

            match reqwest:: Proxy::all(&proxy_url).map_err(anyhow:: Error::from) {
                Ok(proxy) => builder.proxy(proxy),
                Err(err) => {
                    let err_title = format!("`DownloadManager`设置代理`{proxy_url}`失败");
                    let string_chain = err. to_string_chain();
                    tracing::error!(err_title, message = string_chain);
                    builder
                }
            }
        }
    };

    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(2);

    reqwest_middleware:: ClientBuilder::new(builder.build().unwrap())
        .with(RetryTransientMiddleware:: new_with_policy(retry_policy))
        .build()
}

// ✨ 新增：为域名获取创建专用的HTTP客户端
pub fn create_domain_client(app: &AppHandle) -> ClientWithMiddleware {
    // 给动态域名服务器请求一个较短的超时，避免启动/刷新时卡顿
    let builder = reqwest::ClientBuilder::new().timeout(Duration::from_secs(3));

    let proxy_mode = app.get_config().read().proxy_mode.clone();
    let builder = match proxy_mode {
        ProxyMode::System => builder,
        ProxyMode::NoProxy => builder.no_proxy(),
        ProxyMode:: Custom => {
            let config = app.get_config();
            let config = config.read();
            let proxy_host = &config.proxy_host;
            let proxy_port = &config.proxy_port;
            let proxy_url = format!("http://{proxy_host}:{proxy_port}");

            match reqwest:: Proxy::all(&proxy_url).map_err(anyhow::Error::from) {
                Ok(proxy) => builder.proxy(proxy),
                Err(err) => {
                    let err_title = format!("`DomainClient`设置代理`{proxy_url}`失败");
                    let string_chain = err. to_string_chain();
                    tracing::error!(err_title, message = string_chain);
                    builder
                }
            }
        }
    };

    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);

    reqwest_middleware:: ClientBuilder::new(builder.build().unwrap())
        .with(RetryTransientMiddleware:: new_with_policy(retry_policy))
        .build()
}

fn create_api_probe_client(app: &AppHandle) -> anyhow::Result<reqwest::Client> {
    // 预热探测专用：整体超时短，避免阻塞用户的首次操作
    let builder = reqwest::ClientBuilder::new().timeout(Duration::from_secs(3));

    let proxy_mode = app.get_config().read().proxy_mode.clone();
    let builder = match proxy_mode {
        ProxyMode::System => builder,
        ProxyMode::NoProxy => builder.no_proxy(),
        ProxyMode::Custom => {
            let config = app.get_config();
            let config = config.read();
            let proxy_host = &config.proxy_host;
            let proxy_port = &config.proxy_port;
            let proxy_url = format!("http://{proxy_host}:{proxy_port}");

            match reqwest::Proxy::all(&proxy_url).map_err(anyhow::Error::from) {
                Ok(proxy) => builder.proxy(proxy),
                Err(err) => {
                    let err_title = format!("`ProbeClient`设置代理`{proxy_url}`失败");
                    let string_chain = err.to_string_chain();
                    tracing::error!(err_title, message = string_chain);
                    builder
                }
            }
        }
    };

    builder.build().map_err(anyhow::Error::from)
}

fn decrypt_data(ts: u64, data: &str) -> anyhow::Result<String> {
    // 使用Base64解码传入的数据，得到AES-256-ECB加密的数据
    let aes256_ecb_encrypted_data = general_purpose:: STANDARD. decode(data)?;
    // 生成密钥
    let key = utils::md5_hex(&format!("{ts}{APP_DATA_SECRET}"));
    // 使用AES-256-ECB进行解密
    let cipher = Aes256:: new(GenericArray::from_slice(key.as_bytes()));
    let decrypted_data_with_padding:  Vec<u8> = aes256_ecb_encrypted_data
        .chunks(16)
        .map(GenericArray::clone_from_slice)
        .flat_map(|mut block| {
            cipher.decrypt_block(&mut block);
            block. to_vec()
        })
        .collect();
    // 去除PKCS#7填充，根据最后一个字节的值确定填充长度
    let padding_length = decrypted_data_with_padding.last().copied().unwrap() as usize;
    let decrypted_data_without_padding =
        decrypted_data_with_padding[..decrypted_data_with_padding.len() - padding_length].to_vec();
    // 将解密后的数据转换为UTF-8字符串
    let decrypted_data = String::from_utf8(decrypted_data_without_padding)?;
    Ok(decrypted_data)
}

// ✨ 新增：解密API域名服务器返回的数据（使用不同的密钥）
fn decrypt_api_domain_server_data(data: &str, secret: &str) -> anyhow::Result<String> {
    // 使用Base64解码传入的数据
    let encrypted_data = general_purpose:: STANDARD.decode(data)?;
    // 生成密钥（使用提供的secret而不是时间戳）
    let key = utils::md5_hex(secret);
    // 使用AES-256-ECB进行解密
    let cipher = Aes256::new(GenericArray::from_slice(key.as_bytes()));
    let decrypted_data_with_padding: Vec<u8> = encrypted_data
        .chunks(16)
        .map(GenericArray::clone_from_slice)
        .flat_map(|mut block| {
            cipher.decrypt_block(&mut block);
            block.to_vec()
        })
        .collect();
    // 去除PKCS#7填充
    let padding_length = decrypted_data_with_padding. last().copied().unwrap() as usize;
    let decrypted_data_without_padding =
        decrypted_data_with_padding[..decrypted_data_with_padding.len() - padding_length].to_vec();
    // 将解密后的数据转换为UTF-8字符串
    let decrypted_data = String::from_utf8(decrypted_data_without_padding)?;
    Ok(decrypted_data)
}
