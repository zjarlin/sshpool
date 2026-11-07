use crate::{
    archive,
    config::Build,
    model::{Job, Phase, now},
    runner,
    state::State,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Path, Request, State as AppState},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use futures_util::StreamExt;
use std::{fs, io::SeekFrom, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

pub struct ApiError(anyhow::Error);
impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // 只认 `unauthorized` 这一个字面量，其余一律 400：鉴权失败不区分原因，
        // 避免通过状态码或正文探测「凭据库坏了」「标识存在但摘要不匹配」这类差异。
        let status = if self.0.to_string() == "unauthorized" {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, format!("{:#}", self.0)).into_response()
    }
}
type ApiResult<T> = Result<T, ApiError>;

/// 请求主体：根 token 用于控制面运维，短期凭据用于借出的工作台或一次性脚本。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Root,
    Credential(crate::credentials::Grant),
}

impl Principal {
    /// 审计与日志用的主体名；根 token 没有主体，用固定字符串代替。
    pub fn subject(&self) -> &str {
        match self {
            Self::Root => "root",
            Self::Credential(grant) => &grant.subject,
        }
    }
}

/// 鉴权：先比根 token（恒时比较），不匹配再查短期凭据库。
///
/// 凭据库损坏必须拒绝（fail-closed），错误写到 stderr 供运维发现；
/// 对客户端只回 401，不泄露存储状态。
fn authorized(headers: &HeaderMap, state: &State) -> ApiResult<Principal> {
    let actual = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", state.token);
    let root_match = actual.len() == expected.len()
        && actual
            .bytes()
            .zip(expected.bytes())
            .fold(0_u8, |v, (a, b)| v | (a ^ b))
            == 0;
    if root_match {
        return Ok(Principal::Root);
    }
    let token = actual.strip_prefix("Bearer ").unwrap_or("");
    match crate::credentials::verify(&state.home, token, crate::model::now()) {
        Ok(Some(grant)) => Ok(Principal::Credential(grant)),
        Ok(None) => Err(anyhow::anyhow!("unauthorized").into()),
        Err(error) => {
            eprintln!("sshpool: credential store unusable, rejecting request: {error:#}");
            Err(anyhow::anyhow!("unauthorized").into())
        }
    }
}
pub fn routes(state: Arc<State>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/nodes/{name}/enable", post(enable_node))
        .route("/v1/nodes/{name}/disable", post(disable_node))
        .route("/v1/nodes/{name}/reconcile", post(reconcile_node))
        .route("/v1/nodes/reconcile", post(reconcile_all))
        .route("/v1/jobs", get(jobs).post(submit))
        .route("/v1/jobs/{id}", get(job))
        .route("/v1/jobs/{id}/cancel", post(cancel))
        .route("/v1/jobs/{id}/log", get(log))
        .route("/v1/jobs/{id}/events", get(events))
        .route("/v1/jobs/{id}/artifacts", get(artifacts))
        .with_state(state)
}
async fn status(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(&headers, &state)?;
    let nodes = state.nodes().await;
    // 状态查询本身就是一次探测：它不在调度锁内，可以让调度复用同一份新鲜快照。
    Ok(axum::Json(state.refresh_health(&nodes).await))
}
async fn enable_node(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<impl IntoResponse> {
    set_node_enabled(state, headers, name, true).await
}
async fn disable_node(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<impl IntoResponse> {
    set_node_enabled(state, headers, name, false).await
}
async fn set_node_enabled(
    state: Arc<State>,
    headers: HeaderMap,
    name: String,
    enabled: bool,
) -> ApiResult<axum::Json<crate::config::Node>> {
    let _principal = authorized(&headers, &state)?;
    let node = state.set_node_enabled(&name, enabled).await?;
    Ok(axum::Json(node))
}
/// 只核对指定节点的未确认清理，并用远端看门狗证据解除隔离。
async fn reconcile_node(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<axum::Json<crate::reconcile::Report>> {
    let _principal = authorized(&headers, &state)?;
    Ok(axum::Json(
        crate::reconcile::reconcile(&state, Some(&name)).await?,
    ))
}
async fn reconcile_all(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
) -> ApiResult<axum::Json<crate::reconcile::Report>> {
    let _principal = authorized(&headers, &state)?;
    Ok(axum::Json(crate::reconcile::reconcile(&state, None).await?))
}

async fn jobs(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(&headers, &state)?;
    let mut jobs = state
        .jobs
        .lock()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    jobs.sort_by_key(|job| std::cmp::Reverse(job.created_at));
    Ok(axum::Json(jobs))
}
async fn job(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(&headers, &state)?;
    let job = state
        .jobs
        .lock()
        .await
        .get(&id)
        .cloned()
        .context("unknown job")?;
    Ok(axum::Json(job))
}
async fn cancel(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(&headers, &state)?;
    // 与首次领取任务共用调度锁，避免取消和进入 Running 的窄竞态。
    let _scheduling = state.scheduling.lock().await;
    let _transition = state.transitions.lock().await;
    let candidate = {
        let jobs = state.jobs.lock().await;
        let mut candidate = jobs.get(&id).cloned().context("unknown job")?;
        if !candidate.phase.terminal() {
            candidate.cancel_requested = true;
        }
        candidate
    };
    let result = state.checkpoint_candidate_locked(candidate).await;
    state.wake_queue();
    let (record, _) = result?;
    Ok(axum::Json(record))
}
async fn submit(
    AppState(state): AppState<Arc<State>>,
    request: Request,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(request.headers(), &state)?;
    let encoded = request
        .headers()
        .get("x-sshpool-build")
        .context("missing build header")?
        .to_str()
        .map_err(anyhow::Error::from)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(anyhow::Error::from)?;
    let expected_source_sha256 = request
        .headers()
        .get("x-sshpool-source-sha256")
        .context("missing source digest")?
        .to_str()
        .map_err(anyhow::Error::from)?
        .to_string();
    if expected_source_sha256.len() != 64
        || !expected_source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            anyhow::anyhow!("source digest must be 64 lowercase hexadecimal characters").into(),
        );
    }
    let build: Build = serde_json::from_slice(&decoded).map_err(anyhow::Error::from)?;
    build.validate()?;
    let queue_timeout_secs = build.queue_timeout_secs;
    let permit = state
        .uploads
        .clone()
        .try_acquire_owned()
        .context("controller busy; try later")?;
    ensure_disk(&state)?;
    let id = Uuid::new_v4();
    let directory = state.dir(id);
    fs::create_dir(&directory).map_err(anyhow::Error::from)?;
    let source = directory.join("source.tar");
    let maximum = state.config.max_upload_mib * 1048576;
    let transfer = async {
        let mut output = tokio::fs::File::create(&source).await?;
        let mut stream = request.into_body().into_data_stream();
        let mut size = 0;
        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;
            size += bytes.len() as u64;
            ensure!(size <= maximum, "upload quota exceeded");
            output.write_all(&bytes).await?;
        }
        output.flush().await?;
        output.sync_all().await?;
        archive::validate(&source, maximum, None)?;
        let actual = archive::sha256_file(&source)?;
        ensure!(
            actual == expected_source_sha256,
            "source digest mismatch: archive was changed in transit"
        );
        Ok::<_, anyhow::Error>(actual)
    };
    let transfer = tokio::time::timeout(std::time::Duration::from_secs(120), transfer).await;
    let source_sha256 = match transfer {
        Ok(value) => value,
        Err(_) => Err(anyhow::anyhow!("upload timed out")),
    };
    let source_sha256 = match source_sha256 {
        Ok(value) => value,
        Err(error) => {
            // 此目录由本次请求创建且尚未发布，只删除该请求自己的部分上传。
            fs::remove_dir_all(&directory).map_err(anyhow::Error::from)?;
            return Err(error.into());
        }
    };
    let created_at = now();
    let queue_deadline =
        (queue_timeout_secs > 0).then_some(created_at.saturating_add(queue_timeout_secs));
    let job = Job {
        id,
        revision: 0,
        build,
        phase: Phase::Queued,
        created_at,
        finished_at: None,
        attempts: Vec::new(),
        exit_code: None,
        message: None,
        artifacts: false,
        cancel_requested: false,
        cleanup_confirmed: false,
        queue_deadline,
        source_sha256: Some(source_sha256.clone()),
    };
    // 首个必须成功的 checkpoint 同时包含提交事件，避免事件只留在本机。
    state
        .event(
            id,
            "submitted",
            &format!("source validated sha256:{source_sha256}"),
        )
        .await?;
    let job = match state.checkpoint_candidate(job).await {
        Ok((job, _)) => job,
        Err(error) => {
            // 请求尚未对客户端发布；保留本地诊断副本，绝不删除可能已被远端引用的源码。
            return Err(error.into());
        }
    };
    state.wake_queue();
    runner::spawn_job(state, id, permit);
    Ok((StatusCode::ACCEPTED, axum::Json(job)))
}
fn ensure_disk(state: &State) -> Result<()> {
    let free = fs2::available_space(&state.home)?;
    let needed = (state.config.min_free_disk_mib
        + state.config.max_active_jobs as u64
            * (state.config.max_upload_mib
                + state.config.max_artifact_mib
                + state.config.max_log_mib))
        * 1048576;
    ensure!(free >= needed, "controller disk reserve reached");
    Ok(())
}
async fn log(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Response> {
    let _principal = authorized(&headers, &state)?;
    ensure_job(&state, id).await?;
    let offset = query
        .get("offset")
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(anyhow::Error::from)?
        .unwrap_or(0);
    let path = state.dir(id).join("log.txt");
    if !path.exists() {
        return Ok(Vec::<u8>::new().into_response());
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(anyhow::Error::from)?;
    file.seek(SeekFrom::Start(offset))
        .await
        .map_err(anyhow::Error::from)?;
    let mut bytes = Vec::new();
    file.take(256 * 1024)
        .read_to_end(&mut bytes)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(bytes.into_response())
}
async fn ensure_job(state: &State, id: Uuid) -> Result<Job> {
    state
        .jobs
        .lock()
        .await
        .get(&id)
        .cloned()
        .context("unknown job")
}
async fn artifacts(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    let _principal = authorized(&headers, &state)?;
    if !ensure_job(&state, id).await?.artifacts {
        return Err(anyhow::anyhow!("no artifacts available").into());
    }
    let file = tokio::fs::File::open(state.dir(id).join("artifacts.tar"))
        .await
        .map_err(anyhow::Error::from)?;
    Ok((
        [("content-type", "application/x-tar")],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

async fn events(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let _principal = authorized(&headers, &state)?;
    ensure_job(&state, id).await?;
    let path = state.dir(id).join("events.jsonl");
    // 和追加事件共用锁，避免读取到尚未写完的 JSON 行。
    let _guard = state.audit.lock().await;
    let text = if path.exists() {
        tokio::fs::read_to_string(path)
            .await
            .map_err(anyhow::Error::from)?
    } else {
        String::new()
    };
    let events = text
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)?;
    Ok(axum::Json(events))
}
