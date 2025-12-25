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
    // ✨ 新增：用于获取动态API域名的HTTP客户端
    domain_client: Arc<RwLock<ClientWithMiddleware>>,
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

    // ✨ 新增：获取最新的API域名
    pub async fn update_api_domains(&self) -> anyhow::Result<()> {
        let config = self.app.get_config();
        let mut config_guard = config.write();

        // 检查是否需要更新
        if ! config_guard.should_update_dynamic_api_domains() {
            return Ok(());
        }

        drop(config_guard); // 释放写锁

        // 从服务器获取最新的API域名
        let server_list = crate::config::Config::get_api_domain_server_list();
        let secret = crate::config::Config:: get_api_domain_server_secret();

        for server_url in server_list {
            match self.req_api_domain_server(server_url, secret).await {
                Ok(domains) => {
                    let mut config_guard = config.write();
                    config_guard.update_dynamic_api_domains(domains);
                    let _ = config_guard.save(&self.app);
                    return Ok(());
                }
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

    // ✨ 新增：请求API域名服务器
    async fn req_api_domain_server(
        &self,
        url: &str,
        secret: &str,
    ) -> anyhow::Result<Vec<String>> {
        let resp = self. domain_client.read().get(url).send().await?;
        let mut text = resp.text().await?;

        // 去掉开头非ascii字符
        while ! text.is_empty() && !text.chars().next().unwrap().is_ascii() {
            text = text[1..]. to_string();
        }

        // 解密响应数据
        let res_json = decrypt_api_domain_server_data(&text, secret)?;
        let res_data: serde_json::Value = serde_json::from_str(&res_json)?;

        // 检查返回值
        if let Some(server) = res_data.get("Server").and_then(|v| v.as_str()) {
            if ! server.is_empty() {
                // 将服务器返回的单个域名转换为列表
                return Ok(vec![server.to_string()]);
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

        // ✨ 改进：尝试动态获取最新的API域名
        let api_domain = {
            let config = self.app.get_config();
            let config_guard = config.read();
            
            if config_guard.should_update_dynamic_api_domains() {
                drop(config_guard);
                // 在后台更新域名
                let _ = self.update_api_domains().await;
                self.app.get_config().read().get_api_domain()
            } else {
                config_guard.get_api_domain()
            }
        };

        let path = path.as_str();
        let request = self
            .api_client
            . read()
            .request(method, format!("https://{api_domain}{path}").as_str())
            .header("token", token)
            .header("tokenparam", tokenparam)
            .header("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");

        let http_resp = match form {
            Some(payload) => request.query(&query).form(&payload).send().await,
            None => request.query(&query).send().await,
        }
        .map_err(|e| {
            if e.is_timeout() {
                anyhow:: Error::from(e).context("连接超时，请使用代理或换条线路重试")
            } else {
                anyhow::Error::from(e)
            }
        })?;

        Ok(http_resp)
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

    pub async fn get_scramble_id(&self, id: i64) -> anyhow::Result<i64> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let query = json! ({
            "id": id,
            "v": ts,
            "mode": "vertical",
            "page": 0,
            "app_img_shunt": 1,
            "express":  "off",
        });
        // 发送获取scramble_id请求
        let http_resp = self.jm_get(ApiPath::GetScrambleId, Some(query), ts).await?;
        // 检查http响应状态码
        let status = http_resp.status();
        let body = http_resp.text().await?;
        if status != reqwest:: StatusCode::OK {
            return Err(anyhow!(
                "获取scramble_id失败，预料之外的状态码({status}): {body}"
            ));
        }
        // 从body中提取scramble_id，如果提取失败则使用默认值
        let scramble_id = body
            .split("var scramble_id = ")
            .nth(1)
            .and_then(|s| s. split(';').next())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(220_980);
        Ok(scramble_id)
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
    let builder = reqwest::ClientBuilder::new().cookie_provider(jar.clone());

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
    let builder = reqwest::ClientBuilder::new();

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
    let builder = reqwest::ClientBuilder:: new();

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
