use std::collections::HashMap;
use std::io::Cursor;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use bytes::Bytes;
use image::codecs::png;
use image::codecs::png::PngEncoder;
use image::{ImageFormat, RgbImage};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use specta::Type;
use tauri::AppHandle;
use tauri_specta::Event;
use tokio::sync::{watch, Semaphore, SemaphorePermit};
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::events::{DownloadSleepingEvent, DownloadTaskEvent};
use crate::extensions::{AnyhowErrorToStringChain, AppHandleExt};
use crate::types::{ChapterInfo, Comic, DownloadFormat};
use crate::utils::filename_filter;
use crate::{utils, DownloadSpeedEvent};
use chrono::prelude::*;   // ← 加在文件顶部所有 use 的最下面
pub const IMAGE_DOMAIN: &str = "cdn-msp2.jmapiproxy2.cc";

/// 用于管理下载任务
///
/// 克隆 `DownloadManager` 的开销极小，性能开销几乎可以忽略不计。
/// 可以放心地在多个线程中传递和使用它的克隆副本。
///
/// 具体来说：
/// - `client`和`app`的克隆开销很小。
/// - 其他字段都被 `Arc` 包裹，这些字段的克隆操作仅仅是增加引用计数。
#[derive(Clone)]
pub struct DownloadManager {
    app: AppHandle,
    chapter_sem: Arc<Semaphore>,
    img_sem: Arc<Semaphore>,
    byte_per_sec: Arc<AtomicU64>,
    download_tasks: Arc<RwLock<HashMap<i64, DownloadTask>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum DownloadTaskState {
    Pending,
    Downloading,
    Paused,
    Cancelled,
    Completed,
    Failed,
}

impl DownloadManager {
    pub fn new(app: AppHandle) -> Self {
        let (chapter_concurrency, img_concurrency) = {
            let config = app.get_config();
            let config = config.read();
            (config.chapter_concurrency, config.img_concurrency)
        };

        let manager = DownloadManager {
            app,
            chapter_sem: Arc::new(Semaphore::new(chapter_concurrency)),
            img_sem: Arc::new(Semaphore::new(img_concurrency)),
            byte_per_sec: Arc::new(AtomicU64::new(0)),
            download_tasks: Arc::new(RwLock::new(HashMap::new())),
        };

        tauri::async_runtime::spawn(manager.clone().emit_download_speed_loop());

        manager
    }

    pub fn create_download_task(&self, comic: Comic, chapter_id: i64) -> anyhow::Result<()> {
        use DownloadTaskState::{Downloading, Paused, Pending};
        let mut tasks = self.download_tasks.write();
        if let Some(task) = tasks.get(&chapter_id) {
            // 如果任务已经存在，且状态是`Pending`、`Downloading`或`Paused`，则不创建新任务
            let state = *task.state_sender.borrow();
            if matches!(state, Pending | Downloading | Paused) {
                return Err(anyhow!("章节ID为`{chapter_id}`的下载任务已存在"));
            }
        }
        tasks.remove(&chapter_id);
        let task = DownloadTask::new(self.app.clone(), comic, chapter_id)
            .context("DownloadTask创建失败")?;
        tauri::async_runtime::spawn(task.clone().process());
        tasks.insert(chapter_id, task);
        Ok(())
    }

    pub fn pause_download_task(&self, chapter_id: i64) -> anyhow::Result<()> {
        let tasks = self.download_tasks.read();
        let Some(task) = tasks.get(&chapter_id) else {
            return Err(anyhow!("未找到章节ID为`{chapter_id}`的下载任务"));
        };
        task.set_state(DownloadTaskState::Paused);
        Ok(())
    }

    pub fn resume_download_task(&self, chapter_id: i64) -> anyhow::Result<()> {
        let tasks = self.download_tasks.read();
        let Some(task) = tasks.get(&chapter_id) else {
            return Err(anyhow!("未找到章节ID为`{chapter_id}`的下载任务"));
        };
        task.set_state(DownloadTaskState::Pending);
        Ok(())
    }

    pub fn cancel_download_task(&self, chapter_id: i64) -> anyhow::Result<()> {
        let tasks = self.download_tasks.read();
        let Some(task) = tasks.get(&chapter_id) else {
            return Err(anyhow!("未找到章节ID为`{chapter_id}`的下载任务"));
        };
        task.set_state(DownloadTaskState::Cancelled);
        Ok(())
    }

    /// 后台循环，根据 `byte_per_sec` 定期计算下载速度并发送事件
    async fn emit_download_speed_loop(self) {
        loop {
            // 每秒统计一次下载字节数
            sleep(Duration::from_secs(1)).await;
            let bytes = self.byte_per_sec.swap(0, Ordering::Relaxed);

            let speed = Self::format_speed(bytes);

            let _ = DownloadSpeedEvent { speed }.emit(&self.app);
        }
    }

    /// 将字节数格式化为人类可读的下载速度字符串
    fn format_speed(bytes: u64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = 1024.0 * 1024.0;
        const GB: f64 = 1024.0 * 1024.0 * 1024.0;

        if bytes == 0 {
            "0 B/s".to_string()
        } else if (bytes as f64) < KB {
            format!("{bytes} B/s")
        } else if (bytes as f64) < MB {
            format!("{:.2} KB/s", (bytes as f64) / KB)
        } else if (bytes as f64) < GB {
            format!("{:.2} MB/s", (bytes as f64) / MB)
        } else {
            format!("{:.2} GB/s", (bytes as f64) / GB)
        }
    }
}

// ==================== 【你的日期文件夹功能】年/月/日自动建文件夹 ====================
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct DateParams {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub date: String, // "2026年2月27日" 格式
}

impl DateParams {
    /// 获取今天的日期参数（使用本地时区，香港时间也没问题）
    pub fn today() -> Self {
        let now = Local::now();
        let year = now.year() as u32;
        let month = now.month();
        let day = now.day();
        Self {
            year,
            month,
            day,
            date: format!("{}年{}月{}日", year, month, day),
        }
    }

    /// 返回子文件夹路径（用于 join），单层目录名：x年x月x日
    pub fn get_date_sub_dir(&self) -> String {
        format!("{}年{}月{}日", self.year, self.month, self.day)
    }
}

// 可选：给 DownloadManager 加便捷方法（前端如果想显示“今天日期文件夹”可以调用）
impl DownloadManager {
    pub fn get_today_date_folder(&self) -> String {
        DateParams::today().get_date_sub_dir()
    }
}

/// 计算当天日期文件夹下漫画目录的目标路径（纯函数，便于测试）
/// 即 `{download_dir}/{today_sub_dir}/{漫画目录名}`
fn compute_today_comic_dir(
    download_dir: &Path,
    today_sub_dir: &str,
    comic_download_dir: &Path,
) -> anyhow::Result<PathBuf> {
    let comic_dir_name = comic_download_dir
        .file_name()
        .context("无法获取漫画目录名")?;
    Ok(download_dir.join(today_sub_dir).join(comic_dir_name))
}

/// 将整本漫画目录从旧日期文件夹移动到当天日期文件夹（纯函数，便于测试）
/// 已在当天文件夹中则不做任何操作，返回移动后的目标路径
fn move_comic_dir_to_today(
    comic_download_dir: &Path,
    download_dir: &Path,
    today_sub_dir: &str,
) -> anyhow::Result<PathBuf> {
    let today_comic_dir = compute_today_comic_dir(download_dir, today_sub_dir, comic_download_dir)?;

    // 已经在当天文件夹中，无需移动
    if comic_download_dir == today_comic_dir {
        return Ok(today_comic_dir);
    }

    // 创建当天日期文件夹
    let today_dir = download_dir.join(today_sub_dir);
    std::fs::create_dir_all(&today_dir)
        .context(format!("创建文件夹`{}`失败", today_dir.display()))?;

    // 尝试移动整个漫画目录（同一驱动器下是原子操作）
    std::fs::rename(comic_download_dir, &today_comic_dir).context(format!(
        "将 `{}` 移动到 `{}` 失败",
        comic_download_dir.display(),
        today_comic_dir.display()
    ))?;

    Ok(today_comic_dir)
}

#[derive(Clone)]
struct DownloadTask {
    app: AppHandle,
    download_manager: DownloadManager,
    comic: Arc<Comic>,
    chapter_info: Arc<ChapterInfo>,
    state_sender: watch::Sender<DownloadTaskState>,
    downloaded_img_count: Arc<AtomicU32>,
    total_img_count: Arc<AtomicU32>,
}

impl DownloadTask {
    pub fn new(app: AppHandle, mut comic: Comic, chapter_id: i64) -> anyhow::Result<Self> {
        comic
            .update_download_dir_fields_by_fmt(&app)
            .context(format!("漫画`{}`更新`download_dir`字段失败", comic.name))?;

        let chapter_info = comic
            .chapter_infos
            .iter()
            .find(|chapter| chapter.chapter_id == chapter_id)
            .cloned()
            .context(format!("未找到章节ID为`{chapter_id}`的章节信息"))?;

        let download_manager = app.get_download_manager().inner().clone();
        let (state_sender, _) = watch::channel(DownloadTaskState::Pending);

        let task = Self {
            app,
            download_manager,
            comic: Arc::new(comic),
            chapter_info: Arc::new(chapter_info),
            state_sender,
            downloaded_img_count: Arc::new(AtomicU32::new(0)),
            total_img_count: Arc::new(AtomicU32::new(0)),
        };

        Ok(task)
    }

    async fn process(self) {
        self.emit_download_task_create_event();

        let download_comic_task = self.download_chapter();
        tokio::pin!(download_comic_task);

        let mut state_receiver = self.state_sender.subscribe();
        state_receiver.mark_changed();
        let mut permit = None;
        loop {
            let state_is_downloading = *state_receiver.borrow() == DownloadTaskState::Downloading;
            let state_is_pending = *state_receiver.borrow() == DownloadTaskState::Pending;
            tokio::select! {
                () = &mut download_comic_task, if state_is_downloading && permit.is_some() => break,
                control_flow = self.acquire_chapter_permit(&mut permit), if state_is_pending => {
                    match control_flow {
                        ControlFlow::Continue(()) => continue,
                        ControlFlow::Break(()) => break,
                    }
                },
                _ = state_receiver.changed() => {
                    match self.handle_state_change(&mut permit, &mut state_receiver) {
                        ControlFlow::Continue(()) => continue,
                        ControlFlow::Break(()) => break,
                    }
                }
            }
        }
    }

    async fn download_chapter(&self) {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;
        let chapter_id = self.chapter_info.chapter_id;

        if let Err(err) = self.comic.save_comic_metadata() {
            let err_title = format!("`{comic_title}`保存元数据失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);

            self.set_state(DownloadTaskState::Failed);
            self.emit_download_task_update_event();

            return;
        }

        // 下载封面（始终启用，但失败不影响章节图片下载）
        if let Err(err) = self.download_cover().await {
            let err_title =
                format!("`{comic_title}`下载封面失败（已忽略，仅封面下载失败，不影响章节图片）");
            let string_chain = err.to_string_chain();
            tracing::warn!(err_title, message = string_chain);
            // 不中断后续流程
        }

        // 获取此章节每张图片的下载链接以及对应的block_num
        let Some(urls_with_block_num) = self.get_urls_with_block_num(chapter_id).await else {
            return;
        };
        // 记录总共需要下载的图片数量
        #[allow(clippy::cast_possible_truncation)]
        self.total_img_count
            .fetch_add(urls_with_block_num.len() as u32, Ordering::Relaxed);
        // 创建临时下载目录
        let Some(temp_download_dir) = self.create_temp_download_dir() else {
            return;
        };
        // 清理临时下载目录中与`config.download_format`对不上的文件
        self.clean_temp_download_dir(&temp_download_dir);

        let mut join_set = JoinSet::new();
        for (i, (url, block_num)) in urls_with_block_num.into_iter().enumerate() {
            // 创建下载任务
            let temp_download_dir = temp_download_dir.clone();
            let download_img_task =
                DownloadImgTask::new(self, url, i, temp_download_dir, block_num);
            join_set.spawn(download_img_task.process());
        }
        join_set.join_all().await;
        tracing::trace!(comic_title, chapter_title, "所有图片下载任务完成");
        // 检查此章节的图片是否全部下载成功
        let downloaded_img_count = self.downloaded_img_count.load(Ordering::Relaxed);
        let total_img_count = self.total_img_count.load(Ordering::Relaxed);
        if downloaded_img_count != total_img_count {
            // 此章节的图片未全部下载成功
            let err_title = format!("`{comic_title} - {chapter_title}`下载不完整");
            let err_msg =
                format!("总共有`{total_img_count}`张图片，但只下载了`{downloaded_img_count}`张");
            tracing::error!(err_title, message = err_msg);

            self.set_state(DownloadTaskState::Failed);
            self.emit_download_task_update_event();

            return;
        }
        // 至此，章节的图片全部下载成功
        if let Err(err) = self.rename_temp_download_dir(&temp_download_dir) {
            let err_title = format!("`{comic_title} - {chapter_title}`重命名临时下载目录失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);

            self.set_state(DownloadTaskState::Failed);
            self.emit_download_task_update_event();

            return;
        }

        if let Err(err) = self.chapter_info.save_chapter_metadata() {
            let err_title = format!("`{comic_title} - {chapter_title}`保存元数据失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);
        }

        // ===== 下载完成后，将整本漫画移到当天日期文件夹下 =====
        // 这样多次下载的漫画最终都会归集到最新日期，无需翻多个文件夹
        if let Err(err) = self.move_comic_to_today_folder() {
            let err_title = format!("`{comic_title}`移动到当天日期文件夹失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);
            // 移动失败不中断流程，漫画仍然保留在旧目录
        }
        // ===== 结束 =====

        self.sleep_between_chapter().await;
        tracing::info!(comic_title, chapter_title, "章节下载成功");

        self.set_state(DownloadTaskState::Completed);
        self.emit_download_task_update_event();
    }

    async fn download_cover(&self) -> anyhow::Result<()> {
        let cover_path = self.comic.get_cover_path().context("获取封面路径失败")?;
        // if cover_path.exists() {
        //     return Ok(());
        // }

        let comic_id = self.comic.id;
        // 使用 IMAGE_DOMAIN 替代 cdn-msp3.18comic.vip（后者常被 Cloudflare 拦截）
        let url = format!("https://{IMAGE_DOMAIN}/media/albums/{comic_id}.jpg");

        let (img_data, _format) = self
            .app
            .get_jm_client()
            .get_img_data_and_format(&url)
            .await
            .context(format!("下载图片`{url}`失败"))?;

        std::fs::write(&cover_path, img_data)
            .context(format!("保存图片`{}`失败", cover_path.display()))?;

        Ok(())
    }

    fn create_temp_download_dir(&self) -> Option<PathBuf> {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;

        let temp_download_dir = match self.chapter_info.get_temp_download_dir() {
            Ok(temp_download_dir) => temp_download_dir,
            Err(err) => {
                let err_title = format!("`{comic_title} - {chapter_title}`获取临时下载目录失败");
                let string_chain = err.to_string_chain();
                tracing::error!(err_title, message = string_chain);

                self.set_state(DownloadTaskState::Failed);
                self.emit_download_task_update_event();

                return None;
            }
        };

        if let Err(err) = std::fs::create_dir_all(&temp_download_dir).map_err(anyhow::Error::from) {
            let err_title = format!(
                "`{comic_title} - {chapter_title}`创建临时下载目录`{}`失败",
                temp_download_dir.display()
            );
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);

            self.set_state(DownloadTaskState::Failed);
            self.emit_download_task_update_event();

            return None;
        }

        tracing::trace!(
            comic_title,
            chapter_title,
            "创建临时下载目录`{}`成功",
            temp_download_dir.display()
        );

        Some(temp_download_dir)
    }

    fn rename_temp_download_dir(&self, temp_download_dir: &PathBuf) -> anyhow::Result<()> {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;
        let chapter_download_dir = self
            .chapter_info
            .chapter_download_dir
            .as_ref()
            .context("`chapter_download_dir`字段为`None`")?;

        if chapter_download_dir.exists() {
            std::fs::remove_dir_all(chapter_download_dir)
                .context(format!("删除 `{}` 失败", chapter_download_dir.display()))?;
        }

        std::fs::rename(temp_download_dir, chapter_download_dir).context(format!(
            "将 `{}` 重命名为 `{}` 失败",
            temp_download_dir.display(),
            chapter_download_dir.display()
        ))?;

        tracing::trace!(
            comic_title,
            chapter_title,
            "重命名临时下载目录`{}`为`{}`成功",
            temp_download_dir.display(),
            chapter_download_dir.display()
        );

        Ok(())
    }

    async fn get_urls_with_block_num(&self, chapter_id: i64) -> Option<Vec<(String, u32)>> {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;
        let jm_client = self.app.get_jm_client();

        let (scramble_id, chapter_resp_data) = match jm_client.get_chapter_bootstrap(chapter_id).await
        {
            Ok(data) => data,
            Err(err) => {
                let err_title = format!("`{comic_title} - {chapter_title}`获取图片下载链接失败");
                let string_chain = err.to_string_chain();
                tracing::error!(err_title, message = string_chain);

                self.set_state(DownloadTaskState::Failed);
                self.emit_download_task_update_event();

                return None;
            }
        };
        // 构造图片下载链接
        let urls_with_block_num: Vec<(String, u32)> = chapter_resp_data
            .images
            .into_iter()
            .filter_map(|filename| {
                let file_path = Path::new(&filename);
                let ext = file_path.extension()?.to_str()?.to_lowercase();
                let url = format!("https://{IMAGE_DOMAIN}/media/photos/{chapter_id}/{filename}");
                if ext == "gif" {
                    return Some((url, 0));
                } else if ext != "webp" {
                    return None;
                }

                let filename_without_ext = file_path.file_stem()?.to_str()?;
                let block_num = calculate_block_num(scramble_id, chapter_id, filename_without_ext);
                Some((url, block_num))
            })
            .collect();

        tracing::trace!(comic_title, chapter_title, "获取图片链接成功");

        Some(urls_with_block_num)
    }

    /// 删除临时下载目录中与`config.download_format`对不上的文件
    fn clean_temp_download_dir(&self, temp_download_dir: &Path) {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;

        let entries = match std::fs::read_dir(temp_download_dir).map_err(anyhow::Error::from) {
            Ok(entries) => entries,
            Err(err) => {
                let err_title = format!(
                    "`{comic_title}`读取临时下载目录`{}`失败",
                    temp_download_dir.display()
                );
                let string_chain = err.to_string_chain();
                tracing::error!(err_title, message = string_chain);
                return;
            }
        };

        let download_format = self.app.get_config().read().download_format;
        let extension = download_format.extension();
        for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
            // path有扩展名，且能转换为utf8，并与`config.download_format`一致或是gif，则保留
            let should_keep = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "gif" || ext == extension);
            if should_keep {
                continue;
            }
            // 否则删除文件
            if let Err(err) = std::fs::remove_file(&path).map_err(anyhow::Error::from) {
                let err_title =
                    format!("`{comic_title}`删除临时下载目录的`{}`失败", path.display());
                let string_chain = err.to_string_chain();
                tracing::error!(err_title, message = string_chain);
            }
        }

        tracing::trace!(
            comic_title,
            chapter_title,
            "清理临时下载目录`{}`成功",
            temp_download_dir.display()
        );
    }

    async fn acquire_chapter_permit<'a>(
        &'a self,
        permit: &mut Option<SemaphorePermit<'a>>,
    ) -> ControlFlow<()> {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;

        tracing::debug!(comic_title, chapter_title, "章节开始排队");

        self.emit_download_task_update_event();

        *permit = match permit.take() {
            // 如果有permit，则直接用
            Some(permit) => Some(permit),
            // 如果没有permit，则获取permit
            None => match self
                .download_manager
                .chapter_sem
                .acquire()
                .await
                .map_err(anyhow::Error::from)
            {
                Ok(permit) => Some(permit),
                Err(err) => {
                    let err_title =
                        format!("`{comic_title} - {chapter_title}`获取下载章节的permit失败");
                    let string_chain = err.to_string_chain();
                    tracing::error!(err_title, message = string_chain);

                    self.set_state(DownloadTaskState::Failed);
                    self.emit_download_task_update_event();

                    return ControlFlow::Break(());
                }
            },
        };
        // 如果当前任务状态不是`Pending`，则不将任务状态设置为`Downloading`
        if *self.state_sender.borrow() != DownloadTaskState::Pending {
            return ControlFlow::Continue(());
        }
        // 将任务状态设置为`Downloading`
        if let Err(err) = self
            .state_sender
            .send(DownloadTaskState::Downloading)
            .map_err(anyhow::Error::from)
        {
            let err_title = format!("`{comic_title} - {chapter_title}`发送状态`Downloading`失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    fn handle_state_change<'a>(
        &'a self,
        permit: &mut Option<SemaphorePermit<'a>>,
        state_receiver: &mut watch::Receiver<DownloadTaskState>,
    ) -> ControlFlow<()> {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;

        self.emit_download_task_update_event();
        let state = *state_receiver.borrow();
        match state {
            DownloadTaskState::Paused => {
                tracing::debug!(comic_title, chapter_title, "章节暂停中");
                if let Some(permit) = permit.take() {
                    drop(permit);
                }
                ControlFlow::Continue(())
            }
            DownloadTaskState::Cancelled => {
                tracing::debug!(comic_title, chapter_title, "章节取消下载");
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        }
    }

    async fn sleep_between_chapter(&self) {
        let mut remaining_sec = self.app.get_config().read().chapter_download_interval_sec;
        while remaining_sec > 0 {
            // 发送章节休眠事件
            let _ = DownloadSleepingEvent {
                id: self.chapter_info.chapter_id,
                remaining_sec,
            }
            .emit(&self.app);
            sleep(Duration::from_secs(1)).await;
            remaining_sec -= 1;
        }
    }

    fn set_state(&self, state: DownloadTaskState) {
        let comic_title = &self.comic.name;
        let chapter_title = &self.chapter_info.chapter_title;

        if let Err(err) = self.state_sender.send(state).map_err(anyhow::Error::from) {
            let err_title = format!("`{comic_title} - {chapter_title}`发送状态`{state:?}`失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);
        }
    }

    fn emit_download_task_update_event(&self) {
        let _ = DownloadTaskEvent::Update {
            chapter_id: self.chapter_info.chapter_id,
            state: *self.state_sender.borrow(),
            downloaded_img_count: self.downloaded_img_count.load(Ordering::Relaxed),
            total_img_count: self.total_img_count.load(Ordering::Relaxed),
        }
        .emit(&self.app);
    }

    fn emit_download_task_create_event(&self) {
        let _ = DownloadTaskEvent::Create {
            state: *self.state_sender.borrow(),
            comic: Box::new(self.comic.as_ref().clone()),
            chapter_info: Box::new(self.chapter_info.as_ref().clone()),
            downloaded_img_count: self.downloaded_img_count.load(Ordering::Relaxed),
            total_img_count: self.total_img_count.load(Ordering::Relaxed),
        }
        .emit(&self.app);
    }

    /// 将整个漫画目录从旧日期文件夹移动到当天日期文件夹
    /// 使得同一漫画的所有章节最终都集中在最新下载日期下
    fn move_comic_to_today_folder(&self) -> anyhow::Result<()> {
        let comic_download_dir = self
            .comic
            .comic_download_dir
            .as_ref()
            .context("comic_download_dir 为 None")?;

        let download_dir = self.app.get_config().read().download_dir.clone();
        let today_sub_dir = DateParams::today().get_date_sub_dir();

        match move_comic_dir_to_today(comic_download_dir, &download_dir, &today_sub_dir) {
            Ok(today_comic_dir) => {
                tracing::info!(
                    "已将漫画`{}`从`{}`移动到`{}`",
                    self.comic.name,
                    comic_download_dir.display(),
                    today_comic_dir.display()
                );
                Ok(())
            }
            Err(err) => {
                // 移动失败：可能已被其他章节的下载任务抢先移动了整本漫画
                // （批量下载同一漫画时并发触发），此时只把当前章节目录移过去
                tracing::debug!(
                    err = %err,
                    "移动整本漫画失败（可能已被其他任务移动），尝试仅移动当前章节"
                );
                let today_comic_dir =
                    compute_today_comic_dir(&download_dir, &today_sub_dir, comic_download_dir)?;
                self.move_current_chapter_dir_to(&today_comic_dir)?;
                Ok(())
            }
        }
    }

    /// 将当前章节的目录移动到目标漫画目录下
    /// 用于整本漫画已被其他章节任务移动、仅需迁移本章节的情况
    fn move_current_chapter_dir_to(&self, target_comic_dir: &Path) -> anyhow::Result<()> {
        let Some(chapter_download_dir) = &self.chapter_info.chapter_download_dir else {
            return Ok(());
        };
        // 若当前章节目录不存在，说明整本漫画已随其他任务移动，无需处理
        if !chapter_download_dir.exists() {
            return Ok(());
        }
        let chapter_name = chapter_download_dir
            .file_name()
            .context("无法获取章节目录名")?;
        let target = target_comic_dir.join(chapter_name);
        if target.exists() {
            return Ok(());
        }
        std::fs::rename(chapter_download_dir, &target).context(format!(
            "移动章节`{}`到`{}`失败",
            chapter_download_dir.display(),
            target.display()
        ))?;
        tracing::info!(
            "已将章节`{}`移动到`{}`",
            chapter_download_dir.display(),
            target.display()
        );
        Ok(())
    }
}

#[derive(Clone)]
struct DownloadImgTask {
    app: AppHandle,
    download_manager: DownloadManager,
    download_task: DownloadTask,
    url: String,
    index: usize,
    temp_download_path: PathBuf,
    block_num: u32,
}

impl DownloadImgTask {
    pub fn new(
        download_task: &DownloadTask,
        url: String,
        index: usize,
        temp_download_path: PathBuf,
        block_num: u32,
    ) -> Self {
        Self {
            app: download_task.app.clone(),
            download_manager: download_task.download_manager.clone(),
            download_task: download_task.clone(),
            url,
            index,
            temp_download_path,
            block_num,
        }
    }

    async fn process(self) {
        let download_img_task = self.download_img();
        tokio::pin!(download_img_task);

        let mut state_receiver = self.download_task.state_sender.subscribe();
        state_receiver.mark_changed();
        let mut permit = None;

        loop {
            let state_is_downloading = *state_receiver.borrow() == DownloadTaskState::Downloading;
            tokio::select! {
                () = &mut download_img_task, if state_is_downloading && permit.is_some() => break,
                control_flow = self.acquire_img_permit(&mut permit), if state_is_downloading && permit.is_none() => {
                    match control_flow {
                        ControlFlow::Continue(()) => continue,
                        ControlFlow::Break(()) => break,
                    }
                },
                _ = state_receiver.changed() => {
                    match self.handle_state_change(&mut permit, &mut state_receiver) {
                        ControlFlow::Continue(()) => continue,
                        ControlFlow::Break(()) => break,
                    }
                }
            }
        }
    }

    async fn download_img(&self) {
        let url = &self.url;
        let comic_title = &self.download_task.comic.name;
        let chapter_title = &self.download_task.chapter_info.chapter_title;
        let temp_download_path = &self.temp_download_path;

        let index_filename = format!("{:04}", self.index + 1);
        let download_format = self.app.get_config().read().download_format;
        let ext = download_format.extension();

        let user_format_path = temp_download_path.join(format!("{index_filename}.{ext}"));
        let gif_path = temp_download_path.join(format!("{index_filename}.gif"));

        if user_format_path.exists() || gif_path.exists() {
            // 如果图片已经存在，直接返回
            self.download_task
                .downloaded_img_count
                .fetch_add(1, Ordering::Relaxed);

            self.download_task.emit_download_task_update_event();

            tracing::trace!(url, comic_title, chapter_title, "图片已存在，跳过下载");
            return;
        }

        tracing::trace!(url, comic_title, chapter_title, "开始下载图片");

        let (img_data, format) = match self.app.get_jm_client().get_img_data_and_format(url).await {
            Ok(data) => data,
            Err(err) => {
                let err_title = format!("下载图片`{url}`失败");
                let string_chain = err.to_string_chain();
                tracing::error!(err_title, message = string_chain);
                return;
            }
        };
        let img_data_len = img_data.len() as u64;

        tracing::trace!(url, comic_title, chapter_title, "图片成功下载到内存");

        let save_path = if format == ImageFormat::Gif {
            gif_path
        } else {
            user_format_path
        };

        let block_num = self.block_num;
        // 保存图片
        if let Err(err) = save_img(&save_path, download_format, block_num, img_data, format).await {
            let err_title = format!("保存图片`{url}`失败");
            let string_chain = err.to_string_chain();
            tracing::error!(err_title, message = string_chain);
            return;
        }

        tracing::trace!(
            url,
            comic_title,
            chapter_title,
            "图片成功保存到`{}`",
            save_path.display()
        );

        // 记录下载字节数
        self.download_manager
            .byte_per_sec
            .fetch_add(img_data_len, Ordering::Relaxed);

        self.download_task
            .downloaded_img_count
            .fetch_add(1, Ordering::Relaxed);

        self.download_task.emit_download_task_update_event();

        let img_download_interval_sec = self.app.get_config().read().img_download_interval_sec;
        sleep(Duration::from_secs(img_download_interval_sec)).await;
    }

    async fn acquire_img_permit<'a>(
        &'a self,
        permit: &mut Option<SemaphorePermit<'a>>,
    ) -> ControlFlow<()> {
        let url = &self.url;
        let comic_title = &self.download_task.comic.name;
        let chapter_title = &self.download_task.chapter_info.chapter_title;

        tracing::trace!(comic_title, chapter_title, url, "图片开始排队");

        *permit = match permit.take() {
            // 如果有permit，则直接用
            Some(permit) => Some(permit),
            // 如果没有permit，则获取permit
            None => match self
                .download_manager
                .img_sem
                .acquire()
                .await
                .map_err(anyhow::Error::from)
            {
                Ok(permit) => Some(permit),
                Err(err) => {
                    let err_title =
                        format!("`{comic_title} - {chapter_title}`获取下载图片的permit失败");
                    let string_chain = err.to_string_chain();
                    tracing::error!(err_title, message = string_chain);
                    return ControlFlow::Break(());
                }
            },
        };
        ControlFlow::Continue(())
    }

    fn handle_state_change<'a>(
        &'a self,
        permit: &mut Option<SemaphorePermit<'a>>,
        state_receiver: &mut watch::Receiver<DownloadTaskState>,
    ) -> ControlFlow<()> {
        let url = &self.url;
        let comic_title = &self.download_task.comic.name;
        let chapter_title = &self.download_task.chapter_info.chapter_title;

        let state = *state_receiver.borrow();
        match state {
            DownloadTaskState::Paused => {
                tracing::trace!(comic_title, chapter_title, url, "图片暂停下载");
                if let Some(permit) = permit.take() {
                    drop(permit);
                }
                ControlFlow::Continue(())
            }
            DownloadTaskState::Cancelled => {
                tracing::trace!(comic_title, chapter_title, url, "图片取消下载");
                ControlFlow::Break(())
            }
            _ => ControlFlow::Continue(()),
        }
    }
}

fn calculate_block_num(scramble_id: i64, id: i64, filename: &str) -> u32 {
    if id < scramble_id {
        0
    } else if id < 268_850 {
        10
    } else {
        let x = if id < 421_926 { 10 } else { 8 };
        let s = format!("{id}{filename}");
        let s = utils::md5_hex(&s);
        let mut block_num = s.chars().last().unwrap() as u32;
        block_num %= x;
        block_num = block_num * 2 + 2;
        block_num
    }
}

async fn save_img(
    save_path: &Path,
    download_format: DownloadFormat,
    block_num: u32,
    src_img_data: Bytes,
    src_format: ImageFormat,
) -> anyhow::Result<()> {
    // TODO: 如果src_format是WebP，download_format也是WebP，且block_num为0，也可以直接保存
    if src_format == ImageFormat::Gif {
        // 如果是GIF格式，直接保存
        std::fs::write(save_path, src_img_data)
            .context(format!("保存图片`{}`失败", save_path.display()))?;
        return Ok(());
    }

    // 图像处理的闭包
    let save_path = save_path.to_path_buf();
    let process_img = move || -> anyhow::Result<()> {
        let mut src_img = image::load_from_memory(&src_img_data)
            .context("解码图片失败")?
            .to_rgb8();
        // 如果无需拼接，直接根据格式保存图片
        // 否则拼接图片
        let dst_img = if block_num == 0 {
            src_img
        } else {
            stitch_img(&mut src_img, block_num)
        };
        // 用来存图片编码后的数据
        let mut dst_img_data = Vec::new();
        match download_format {
            DownloadFormat::Jpeg => {
                dst_img.write_to(&mut Cursor::new(&mut dst_img_data), ImageFormat::Jpeg)?;
            }
            DownloadFormat::Png => {
                let encoder = PngEncoder::new_with_quality(
                    Cursor::new(&mut dst_img_data),
                    png::CompressionType::Best,
                    png::FilterType::default(),
                );
                dst_img.write_with_encoder(encoder)?;
            }
            DownloadFormat::Webp => {
                dst_img.write_to(&mut Cursor::new(&mut dst_img_data), ImageFormat::WebP)?;
            }
        }
        // 保存编码后的图片数据
        std::fs::write(&save_path, dst_img_data)
            .context(format!("保存图片`{}`失败", save_path.display()))?;
        Ok(())
    };
    // 因为图像处理是CPU密集型操作，所以使用rayon并发处理
    let (sender, receiver) = tokio::sync::oneshot::channel::<anyhow::Result<()>>();
    rayon::spawn(move || {
        let _ = sender.send(process_img());
    });
    // 在tokio任务中等待rayon任务的完成，避免阻塞worker threads
    receiver.await?
}

/// 拼接图片
fn stitch_img(src_img: &mut RgbImage, block_num: u32) -> RgbImage {
    // 如果block_num不为0，需要将图片拼接后再保存
    let (width, height) = src_img.dimensions();
    // 创建一张空的图片，尺寸与原图相同，用于拼接分块
    let mut stitched_img = image::ImageBuffer::new(width, height);
    // 计算原图像的高度除以num的余数
    let remainder_height = height % block_num;
    // 将图片切分为block_num块并拼接
    for i in 0..block_num {
        // 计算当前块的标准高度
        let mut block_height = height / block_num;
        // 计算源图像中当前块的Y轴起点位置
        let src_img_y_start = height - (block_height * (i + 1)) - remainder_height;
        // 计算目标图像中当前块的Y轴起点位置
        let mut dst_img_y_start = block_height * i;
        // 第一块需要加上余数高度，以确保拼接完整
        if i == 0 {
            block_height += remainder_height;
        } else {
            dst_img_y_start += remainder_height;
        }
        // 逐行复制当前块
        for y in 0..block_height {
            let src_y = src_img_y_start + y;
            let dst_y = dst_img_y_start + y;
            // 复制整行像素到目标图像
            for x in 0..width {
                stitched_img.put_pixel(x, dst_y, *src_img.get_pixel(x, src_y));
            }
        }
    }

    stitched_img
}

impl Comic {
    /// 根据fmt更新`comic_download_dir`和`chapter_infos.chapter_download_dir`字段
    fn update_download_dir_fields_by_fmt(&mut self, app: &AppHandle) -> anyhow::Result<()> {
        if self.chapter_infos.is_empty() {
            return Err(anyhow!("没有章节信息，无法更新下载目录字段"));
        }

        let mut first_chapter_download_dir = None;

        // 如果漫画已有已知的下载目录（之前下载过，前端传入），将其作为日期文件夹选择的优先依据
        let known_comic_download_dir = self.comic_download_dir.clone();

        for chapter_info in &mut self.chapter_infos {
            let chapter_title = &chapter_info.chapter_title;

            let dir_fmt_params = DirFmtParams {
                comic_id: self.id,
                comic_title: self.name.clone(),
                author: self.author.join(", "),
                chapter_id: chapter_info.chapter_id,
                chapter_title: chapter_info.chapter_title.clone(),
                order: chapter_info.order,
            };

            let chapter_download_dir = ChapterInfo::get_chapter_download_dir_by_fmt(
                app,
                &dir_fmt_params,
                known_comic_download_dir.as_deref(),
            )
            .context(format!("章节`{chapter_title}`根据fmt获取章节下载目录失败"))?;

            if first_chapter_download_dir.is_none() {
                first_chapter_download_dir = Some(chapter_download_dir.clone());
            }

            chapter_info.chapter_download_dir = Some(chapter_download_dir);
        }

        let Some(first_chapter_download_dir) = first_chapter_download_dir else {
            return Err(anyhow!(
                "处理完所有章节后first_chapter_download_dir仍然为None"
            ));
        };

        let comic_download_dir = first_chapter_download_dir.parent().context(format!(
            "第一个章节下载目录`{}`没有父目录",
            first_chapter_download_dir.display()
        ))?;

        self.comic_download_dir = Some(comic_download_dir.to_path_buf());

        Ok(())
    }
}

#[derive(Default, Debug, PartialEq, Clone, Serialize, Deserialize, Type)]
pub struct DirFmtParams {
    pub comic_id: i64,
    pub comic_title: String,
    pub author: String,
    pub chapter_id: i64,
    pub chapter_title: String,
    pub order: i64,
}

/// 在下载目录下查找已存在的漫画目录的实际路径
/// 找到则返回该漫画目录的完整路径（如 `{download_dir}/2026年3月2日/[作者]漫画A(111)`），否则返回 None
///
/// 匹配优先级（保证复用已存在目录的实际路径，无论标题如何变化）：
/// 1. 已知的漫画下载目录（已下载过的漫画，前端传入），校验结构合法且真实存在后直接复用其实际路径
/// 2. 按漫画目录名（dir_fmt 第一个分段格式化结果）在已有日期文件夹中查找
/// 3. 按漫画ID在`元数据.json`中查找（漫画标题变化后仍能匹配）
fn find_existing_comic_dir(
    download_dir: &Path,
    dir_fmt: &str,
    vars: &HashMap<String, String>,
    comic_id: i64,
    known_comic_download_dir: Option<&Path>,
) -> Option<PathBuf> {
    use strfmt::strfmt;

    // 1. 已知的漫画下载目录：结构形如 `{download_dir}/{日期}/{漫画目录}` 且真实存在，直接复用其实际路径
    if let Some(known_dir) = known_comic_download_dir {
        let date_dir = known_dir.parent()?;
        // 日期文件夹必须是 download_dir 的直接子目录且漫画目录真实存在于磁盘
        if date_dir.parent() == Some(download_dir) && known_dir.is_dir() {
            let name = date_dir.file_name()?.to_string_lossy().to_string();
            // 名称符合 "X年X月X日" 格式才视为日期文件夹
            if name.contains('年') && name.contains('月') && name.contains('日') {
                tracing::debug!(name, "复用已知漫画下载目录的实际路径");
                return Some(known_dir.to_path_buf());
            }
        }
    }

    // 2. 按漫画目录名查找：获取 dir_fmt 的第一个分段（即漫画文件夹名的格式），例如 "{comic_title}"
    // 注意：格式化失败时仅跳过名称匹配，不影响后续的ID匹配
    let comic_dir_name = dir_fmt
        .split('/')
        .next()
        .and_then(|fmt| strfmt(fmt, vars).ok())
        .map(|name| filename_filter(&name))
        .unwrap_or_default();
    if !comic_dir_name.is_empty() {
        tracing::debug!(comic_dir_name, "按漫画目录名在已有日期文件夹中查找");
        // 遍历下载目录下的直接子文件夹（即日期文件夹，如 "2026年7月22日"）
        let entries = std::fs::read_dir(download_dir).ok()?;
        for entry in entries {
            let entry = entry.ok()?;
            if !entry.file_type().ok()?.is_dir() {
                continue;
            }
            let date_dir_name = entry.file_name().to_string_lossy().to_string();
            // 检查该日期文件夹下是否有对应漫画的目录
            let comic_dir = download_dir.join(&date_dir_name).join(&comic_dir_name);
            if comic_dir.is_dir() {
                tracing::debug!(date_dir_name, "在已有日期文件夹中找到漫画目录");
                return Some(comic_dir);
            }
        }
    }

    // 3. 按漫画ID在元数据中查找（比名称匹配更可靠：即使漫画标题发生变化，也能找到其原有的目录）
    tracing::debug!(comic_id, "按漫画ID在元数据中查找已有漫画目录");
    let entries = std::fs::read_dir(download_dir).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        if !entry.file_type().ok()?.is_dir() {
            continue;
        }
        let date_dir_name = entry.file_name().to_string_lossy().to_string();
        let date_dir = download_dir.join(&date_dir_name);

        // 该日期文件夹下的每个子目录都可能是漫画目录
        for comic_entry in std::fs::read_dir(&date_dir).ok()? {
            let comic_entry = comic_entry.ok()?;
            if !comic_entry.file_type().ok()?.is_dir() {
                continue;
            }
            let metadata_path = comic_entry.path().join("元数据.json");
            if !metadata_path.is_file() {
                continue;
            }
            let Ok(metadata_str) = std::fs::read_to_string(&metadata_path) else {
                continue;
            };
            let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&metadata_str) else {
                continue;
            };
            if json_value.get("id").and_then(serde_json::Value::as_i64) == Some(comic_id) {
                tracing::debug!(date_dir_name, comic_id, "按漫画ID找到已有漫画目录");
                return Some(comic_entry.path());
            }
        }
    }
    None
}

/// 根据下载目录、目录格式、变量和已知漫画目录计算章节下载目录（纯函数，便于测试）
///
/// 行为（与需求一致）：
/// - 已下载过的漫画（无论标题如何变化）：直接复用其目录在磁盘上的实际路径，只追加章节目录名；
/// - 全新漫画：在当天日期文件夹下按 dir_fmt 创建目录。
///
/// 查找优先级：
/// 1. 已知的漫画下载目录（已下载过的漫画，前端传入）
/// 2. 按漫画目录名在已有日期文件夹中查找（下载时复用旧文件夹）
/// 3. 按漫画ID在元数据.json中查找（漫画标题变化后仍能匹配）
fn compute_chapter_download_dir(
    download_dir: &Path,
    dir_fmt: &str,
    vars: &HashMap<String, String>,
    comic_id: i64,
    known_comic_download_dir: Option<&Path>,
) -> anyhow::Result<PathBuf> {
    use strfmt::strfmt;

    let existing_comic_dir = find_existing_comic_dir(
        download_dir,
        dir_fmt,
        vars,
        comic_id,
        known_comic_download_dir,
    );

    let dir_fmt_parts: Vec<&str> = dir_fmt.split('/').collect();
    let mut dir_names = Vec::new();
    for fmt in dir_fmt_parts {
        let dir_name = strfmt(fmt, vars).context("格式化目录名失败")?;
        let dir_name = filename_filter(&dir_name);
        if !dir_name.is_empty() {
            dir_names.push(dir_name);
        }
    }
    if dir_names.len() < 2 {
        let err_msg = "配置中的下载目录格式至少要有两个层级，例如：{comic_title}/{chapter_title}";
        return Err(anyhow!(err_msg));
    }

    let chapter_download_dir = if let Some(existing_comic_dir) = existing_comic_dir {
        // 复用已存在漫画目录的实际路径，只追加章节目录名（dir_fmt 第一个分段之后的部分）
        tracing::debug!(
            comic_id,
            existing_dir = %existing_comic_dir.display(),
            "复用已存在漫画目录的实际路径，仅追加章节目录名"
        );
        let mut dir = existing_comic_dir;
        for dir_name in dir_names.iter().skip(1) {
            dir = dir.join(dir_name);
        }
        dir
    } else {
        // 未找到已存在的漫画目录，使用当天日期创建新目录
        let today_sub_dir = DateParams::today().get_date_sub_dir();
        tracing::debug!(
            comic_id,
            today_sub_dir,
            "未找到已存在的漫画目录，使用当天日期创建新目录"
        );
        let mut dir = download_dir.join(&today_sub_dir);
        for dir_name in &dir_names {
            dir = dir.join(dir_name);
        }
        dir
    };

    Ok(chapter_download_dir)
}

impl ChapterInfo {
    fn get_chapter_download_dir_by_fmt(
        app: &AppHandle,
        fmt_params: &DirFmtParams,
        known_comic_download_dir: Option<&Path>,
    ) -> anyhow::Result<PathBuf> {
        let json_value =
            serde_json::to_value(fmt_params).context("将DirFmtParams转为serde_json::Value失败")?;
        let json_map = json_value.as_object().context("DirFmtParams不是JSON对象")?;
        let vars: HashMap<String, String> = json_map
            .into_iter()
            .map(|(k, v)| {
                let key = k.clone();
                let value = match v {
                    serde_json::Value::String(s) => s.clone(),
                    _ => v.to_string(),
                };
                (key, value)
            })
            .collect();
        let (download_dir, dir_fmt) = {
            let config = app.get_config();
            let config = config.read();
            (config.download_dir.clone(), config.dir_fmt.clone())
        };

        compute_chapter_download_dir(
            &download_dir,
            &dir_fmt,
            &vars,
            fmt_params.comic_id,
            known_comic_download_dir,
        )
    }

    fn get_temp_download_dir(&self) -> anyhow::Result<PathBuf> {
        let chapter_download_dir = self
            .chapter_download_dir
            .as_ref()
            .context("`chapter_download_dir`字段为`None`")?;

        let chapter_download_dir_name = self
            .get_chapter_download_dir_name()
            .context("获取章节下载目录名失败")?;

        let parent = chapter_download_dir.parent().context(format!(
            "`{}`的父目录不存在",
            chapter_download_dir.display()
        ))?;

        let temp_download_dir = parent.join(format!(".下载中-{chapter_download_dir_name}"));
        Ok(temp_download_dir)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// 创建临时测试目录结构：
    /// {temp}/download_dir/2026年3月2日/[作者]漫画A(111)/元数据.json + 章节目录
    /// {temp}/download_dir/2026年3月2日/[作者]漫画A(111)/第1话
    /// {temp}/download_dir/2026年7月1日/[作者]漫画B(222)/元数据.json
    fn setup_test_dir() -> (tempfile::TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().expect("创建临时目录失败");
        let download_dir = temp_dir.path().join("download_dir");

        // 漫画A在2026年3月2日下载过
        let comic_a_old = download_dir
            .join("2026年3月2日")
            .join("[作者]漫画A(111)");
        fs::create_dir_all(comic_a_old.join("第1话")).expect("创建漫画A目录失败");
        fs::write(
            comic_a_old.join("元数据.json"),
            r#"{"id":111,"name":"漫画A"}"#,
        )
        .expect("写入漫画A元数据失败");

        // 漫画B在2026年7月1日下载过
        let comic_b = download_dir.join("2026年7月1日").join("[作者]漫画B(222)");
        fs::create_dir_all(&comic_b).expect("创建漫画B目录失败");
        fs::write(
            comic_b.join("元数据.json"),
            r#"{"id":222,"name":"漫画B"}"#,
        )
        .expect("写入漫画B元数据失败");

        (temp_dir, download_dir)
    }

    #[test]
    fn test_find_existing_comic_dir_by_known_dir() {
        let (_temp, download_dir) = setup_test_dir();

        // 已知目录是 download_dir/日期/漫画目录 结构，应直接复用其实际路径
        let known_dir = download_dir.join("2026年3月2日").join("[作者]漫画A(111)");
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &HashMap::new(),
            111,
            Some(&known_dir),
        );
        assert_eq!(found, Some(known_dir.clone()));

        // 不存在的目录（如漫画已被删除）应回退到其他匹配方式
        let missing_dir = download_dir.join("2026年5月1日").join("不存在的漫画");
        let mut vars = HashMap::new();
        vars.insert("comic_title".to_string(), "[作者]漫画A(111)".to_string());
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            Some(&missing_dir),
        );
        assert_eq!(found, Some(known_dir.clone()));

        // 目录不是 download_dir 的直接子目录时（旧版本无日期文件夹结构）应回退
        let legacy_dir = download_dir.join("[作者]漫画A(111)");
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            Some(&legacy_dir),
        );
        assert_eq!(found, Some(known_dir.clone()));

        // 传入 None 时按其他方式匹配
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            None,
        );
        assert_eq!(found, Some(known_dir));
    }

    #[test]
    fn test_find_existing_comic_dir_by_name() {
        let (_temp, download_dir) = setup_test_dir();

        let mut vars = HashMap::new();
        vars.insert("comic_title".to_string(), "[作者]漫画A(111)".to_string());

        // 漫画A在2026年3月2日，名称匹配应返回该目录实际路径
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            None,
        );
        assert_eq!(
            found,
            Some(download_dir.join("2026年3月2日").join("[作者]漫画A(111)"))
        );

        // 未下载过的漫画应返回 None
        let mut vars_new = HashMap::new();
        vars_new.insert("comic_title".to_string(), "未下载的漫画".to_string());
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars_new,
            999,
            None,
        );
        assert_eq!(found, None);
    }

    #[test]
    fn test_find_existing_comic_dir_by_id() {
        let (_temp, download_dir) = setup_test_dir();

        // 标题已变化的场景：名称匹配不到，但按ID仍应找到旧目录的实际路径
        let mut vars_changed = HashMap::new();
        vars_changed.insert("comic_title".to_string(), "[新标题]漫画A(111)".to_string());

        // 漫画A的ID是111，应在2026年3月2日找到
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars_changed,
            111,
            None,
        );
        assert_eq!(
            found,
            Some(download_dir.join("2026年3月2日").join("[作者]漫画A(111)"))
        );

        // 漫画B的ID是222，应在2026年7月1日找到
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars_changed,
            222,
            None,
        );
        assert_eq!(
            found,
            Some(download_dir.join("2026年7月1日").join("[作者]漫画B(222)"))
        );

        // 不存在的漫画ID应返回 None
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars_changed,
            999,
            None,
        );
        assert_eq!(found, None);
    }

    #[test]
    fn test_find_existing_comic_dir_priority() {
        let (_temp, download_dir) = setup_test_dir();

        // 场景1：已知目录优先于名称匹配
        let known_dir = download_dir.join("2026年3月2日").join("[作者]漫画A(111)");
        let mut vars = HashMap::new();
        vars.insert("comic_title".to_string(), "[作者]漫画A(111)".to_string());
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            Some(&known_dir),
        );
        assert_eq!(found, Some(known_dir.clone()));

        // 场景2：已知目录不存在时，回退到ID匹配（漫画标题已变化的场景）
        let stale_known_dir = download_dir.join("2026年5月1日").join("[作者]漫画A(111)");
        let mut vars_changed = HashMap::new();
        vars_changed.insert("comic_title".to_string(), "[新标题]漫画A(111)".to_string());
        let found = find_existing_comic_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars_changed,
            111,
            Some(&stale_known_dir),
        );
        assert_eq!(
            found,
            Some(download_dir.join("2026年3月2日").join("[作者]漫画A(111)"))
        );
    }

    /// 构造漫画A的 vars（标题不变场景）
    fn comic_a_vars(chapter_title: &str) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("comic_title".to_string(), "[作者]漫画A(111)".to_string());
        vars.insert("chapter_title".to_string(), chapter_title.to_string());
        vars.insert("comic_id".to_string(), "111".to_string());
        vars.insert("chapter_id".to_string(), "900".to_string());
        vars.insert("author".to_string(), "作者".to_string());
        vars.insert("order".to_string(), "9".to_string());
        vars
    }

    /// 行为验证（标题不变）：漫画A旧目录 2026年3月2日/[作者]漫画A(111)
    /// 下载新章节 → 章节写入 2026年3月2日/[作者]漫画A(111)/第X话（复用旧路径，只追加章节目录名）
    #[test]
    fn test_compute_chapter_download_dir_reuse_old_dir_title_unchanged() {
        let (_temp, download_dir) = setup_test_dir();

        let vars = comic_a_vars("第X话");
        let known_dir = download_dir.join("2026年3月2日").join("[作者]漫画A(111)");

        // 已知目录（前端传入）优先：直接复用其实际路径，只追加章节目录名
        let chapter_dir = compute_chapter_download_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            Some(&known_dir),
        )
        .unwrap();
        assert_eq!(chapter_dir, known_dir.join("第X话"));

        // 未传已知目录时，按名称匹配也能复用旧目录实际路径
        let chapter_dir = compute_chapter_download_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            None,
        )
        .unwrap();
        assert_eq!(chapter_dir, known_dir.join("第X话"));
    }

    /// 行为验证（标题变化）：标题变化后名称匹配不到，但按ID仍复用旧目录实际路径
    #[test]
    fn test_compute_chapter_download_dir_reuse_old_dir_title_changed() {
        let (_temp, download_dir) = setup_test_dir();

        let mut vars = comic_a_vars("第X话");
        vars.insert("comic_title".to_string(), "[新标题]漫画A(111)".to_string());

        let chapter_dir = compute_chapter_download_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            None,
        )
        .unwrap();
        assert_eq!(
            chapter_dir,
            download_dir
                .join("2026年3月2日")
                .join("[作者]漫画A(111)")
                .join("第X话")
        );
    }

    /// 行为验证：全新漫画（磁盘上不存在）时，在当天日期文件夹下按 dir_fmt 创建
    #[test]
    fn test_compute_chapter_download_dir_new_comic_uses_today() {
        let (_temp, download_dir) = setup_test_dir();

        let mut vars = HashMap::new();
        vars.insert("comic_title".to_string(), "全新漫画".to_string());
        vars.insert("chapter_title".to_string(), "第1话".to_string());
        vars.insert("comic_id".to_string(), "999".to_string());
        vars.insert("chapter_id".to_string(), "1".to_string());
        vars.insert("author".to_string(), "作者".to_string());
        vars.insert("order".to_string(), "1".to_string());

        let chapter_dir = compute_chapter_download_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            999,
            None,
        )
        .unwrap();
        let today_sub_dir = DateParams::today().get_date_sub_dir();
        assert_eq!(chapter_dir, download_dir.join(&today_sub_dir).join("全新漫画").join("第1话"));
    }

    /// 行为验证：下载完成后将整本漫画移动到当天日期文件夹
    /// 旧目录 2026年3月2日/[作者]漫画A(111) → 今天/[作者]漫画A(111)
    #[test]
    fn test_move_comic_dir_to_today() {
        let (_temp, download_dir) = setup_test_dir();

        let old_comic_dir = download_dir.join("2026年3月2日").join("[作者]漫画A(111)");
        let today_sub_dir = "2026年8月3日";

        // 移动前旧目录存在
        assert!(old_comic_dir.is_dir());

        let target = move_comic_dir_to_today(&old_comic_dir, &download_dir, today_sub_dir).unwrap();
        assert_eq!(
            target,
            download_dir.join(today_sub_dir).join("[作者]漫画A(111)")
        );

        // 旧目录已不存在，新目录存在且保留了章节目录
        assert!(!old_comic_dir.exists());
        assert!(target.is_dir());
        assert!(target.join("第1话").is_dir());
        assert!(target.join("元数据.json").is_file());

        // 已在当天文件夹中时，再次移动应无副作用
        let again = move_comic_dir_to_today(&target, &download_dir, today_sub_dir).unwrap();
        assert_eq!(again, target);
        assert!(target.is_dir());
    }

    /// 端到端行为验证（标题不变）：
    /// 漫画A旧目录 2026年3月2日/[作者]漫画A(111)，下载新章节第X话
    /// → 章节写入 2026年3月2日/[作者]漫画A(111)/第X话（复用旧路径）
    /// → 完成后整本移动到 当天日期/[作者]漫画A(111)/
    #[test]
    fn test_end_to_end_append_chapter_then_move_to_today() {
        let (_temp, download_dir) = setup_test_dir();

        let old_comic_dir = download_dir.join("2026年3月2日").join("[作者]漫画A(111)");
        let today_sub_dir = "2026年8月3日";

        // 1. 计算新章节下载目录：复用旧目录实际路径，只追加章节目录名
        let vars = comic_a_vars("第X话");
        let chapter_dir = compute_chapter_download_dir(
            &download_dir,
            "{comic_title}/{chapter_title}",
            &vars,
            111,
            Some(&old_comic_dir),
        )
        .unwrap();
        assert_eq!(chapter_dir, old_comic_dir.join("第X话"));

        // 2. 模拟章节下载完成：创建章节目录
        std::fs::create_dir_all(&chapter_dir).expect("创建章节目录失败");

        // 3. 下载完成后整本移动到当天日期文件夹
        let target = move_comic_dir_to_today(&old_comic_dir, &download_dir, today_sub_dir).unwrap();
        assert_eq!(
            target,
            download_dir.join(today_sub_dir).join("[作者]漫画A(111)")
        );

        // 旧目录已不存在，新目录包含新章节与旧章节
        assert!(!old_comic_dir.exists());
        assert!(target.join("第X话").is_dir());
        assert!(target.join("第1话").is_dir());
        assert!(target.join("元数据.json").is_file());
    }
}
