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

pub struct ApiError {
    status: StatusCode,
    error: anyhow::Error,
}

impl ApiError {
    fn new(status: StatusCode, error: anyhow::Error) -> Self {
        Self { status, error }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        // 默认 400：其余状态码必须显式声明，避免实现里随便一个错误就变成 401/403。
        Self::new(StatusCode::BAD_REQUEST, error)
    }
}
impl ApiError {
    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, anyhow::anyhow!("unauthorized"))
    }

    /// 审计不可用时拒绝执行：宁可这次请求失败，也不要产生没有访问记录的动作。
    fn audit_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            anyhow::anyhow!("access audit is not writable"),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, format!("{:#}", self.error)).into_response()
    }
}
type ApiResult<T> = Result<T, ApiError>;

/// 鉴权失败时只回 401，并带一个仅供审计的原因。
///
/// 原因区分「缺 token」「不认识」「凭据库坏了」是为了运维能定位问题；
/// 它只进审计日志，响应体永远是同一个 `unauthorized`。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Denial {
    Missing,
    Unknown,
    StoreUnusable,
}

impl Denial {
    fn reason(self) -> &'static str {
        match self {
            Self::Missing => "missing-token",
            Self::Unknown => "unknown-token",
            Self::StoreUnusable => "store-unusable",
        }
    }
}

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

    /// 身份来源：写进审计，便于把「谁用根 token 运维」与「谁借了短期凭据」分开。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Credential(_) => "credential",
        }
    }

    fn credential(&self) -> Option<String> {
        match self {
            Self::Root => None,
            Self::Credential(grant) => Some(grant.id.to_string()),
        }
    }
}

/// 中间件已经把鉴权结果放进 extensions；处理器只能取到「已经允许」的主体。
impl axum::extract::FromRequestParts<Arc<State>> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &Arc<State>,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or_else(ApiError::unauthorized)
    }
}

/// 鉴权：先比根 token（恒时比较），不匹配再查短期凭据库。
///
/// 凭据库损坏必须拒绝（fail-closed），错误写到 stderr 供运维发现；
/// 对客户端只回 401，不泄露存储状态。
fn authenticate(headers: &HeaderMap, state: &State) -> std::result::Result<Principal, Denial> {
    let actual = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if actual.is_empty() {
        return Err(Denial::Missing);
    }
    let expected = format!("Bearer {}", state.token);
    let root_match = actual.len() == expected.len()
        && actual
            .bytes()
            .zip(expected.bytes())
            .fold(0_u8, |value, (a, b)| value | (a ^ b))
            == 0;
    if root_match {
        return Ok(Principal::Root);
    }
    let token = actual.strip_prefix("Bearer ").unwrap_or("");
    match crate::credentials::verify(&state.home, token, crate::model::now()) {
        Ok(Some(grant)) => Ok(Principal::Credential(grant)),
        Ok(None) => Err(Denial::Unknown),
        Err(error) => {
            eprintln!("sshpool: credential store unusable, rejecting request: {error:#}");
            Err(Denial::StoreUnusable)
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
        .route("/v1/access", get(access))
        // 一边鉴权一边记审计：处理器不再各自重复鉴权，也就不会出现「某个接口忘了记」。
        // 用 `layer` 而不是 `route_layer`：未命中路由的探测请求同样要留痕。
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            audit_access,
        ))
        .with_state(state)
}

/// 审计查询本身也是被审计的访问，所以它同样走中间件；这里只负责过滤与返回。
async fn access(
    AppState(state): AppState<Arc<State>>,
    // 中间件已经拦过未鉴权请求；这里再取一次，保证处理器本身也要求主体。
    _principal: Principal,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ApiResult<impl IntoResponse> {
    let filter = crate::access::Filter {
        subject: query.get("subject").cloned(),
        decision: query.get("decision").cloned(),
        since: query
            .get("since")
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(anyhow::Error::from)?,
        limit: query
            .get("limit")
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(anyhow::Error::from)?
            .unwrap_or(crate::access::DEFAULT_LIMIT),
    };
    Ok(axum::Json(crate::access::read(&state.home, &filter)?))
}

/// 一次请求的审计字段，先收集再在响应后落盘。
struct AccessRecord {
    request: String,
    subject: String,
    kind: String,
    credential: Option<String>,
    reason: String,
    method: String,
    route: String,
    job: Option<String>,
}

/// 每个请求的访问审计：鉴权 → 记录 → 执行 → 记录状态码。
///
/// 写副作用请求前先确认审计可写，写不进去就拒绝执行 —— 审计不了的动作不做。
/// 记录里不会有 token、请求头或正文：`AccessRecord` 的字段就是全部内容。
async fn audit_access(
    AppState(state): AppState<Arc<State>>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let job = request_id_from_path(request.uri().path());
    let mut record = AccessRecord {
        request: request_id(request.headers()),
        subject: String::new(),
        kind: "anonymous".into(),
        credential: None,
        reason: String::new(),
        method: method.clone(),
        route: route.clone(),
        job: job.map(|id| id.to_string()),
    };

    let (principal, denial) = match authenticate(request.headers(), &state) {
        Ok(principal) => (Some(principal), None),
        Err(denial) => (None, Some(denial)),
    };
    match (&principal, denial) {
        (Some(principal), _) => {
            record.subject = principal.subject().into();
            record.kind = principal.kind().into();
            record.credential = principal.credential();
            record.reason = if principal == &Principal::Root {
                "root-token".into()
            } else {
                "credential".into()
            };
        }
        (None, Some(denial)) => {
            record.reason = denial.reason().into();
            // 拒绝也要有记录：否则「有人一直在试 token」在日志里完全看不见。
            write_access(&state, &record, StatusCode::UNAUTHORIZED).await;
            return ApiError::unauthorized().into_response();
        }
        (None, None) => unreachable!("authenticate returns one of the two"),
    }

    // 副作用请求先确认审计可写；只读请求不为此多付一次系统调用。
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
        && let Err(error) = crate::access::ensure_writable(&state.home)
    {
        eprintln!(
            "sshpool: refusing {} {} without a writable access log: {error:#}",
            method, route
        );
        return ApiError::audit_unavailable().into_response();
    }

    let (mut parts, body) = request.into_parts();
    if let Some(principal) = principal {
        parts.extensions.insert(principal);
    }
    let response = next.run(Request::from_parts(parts, body)).await;
    write_access(&state, &record, response.status()).await;
    response
}

async fn write_access(state: &State, record: &AccessRecord, status: StatusCode) {
    let entry = crate::access::Entry {
        schema: crate::access::SCHEMA,
        time: now(),
        request: record.request.clone(),
        subject: record.subject.clone(),
        kind: record.kind.clone(),
        credential: record.credential.clone(),
        decision: if status == StatusCode::UNAUTHORIZED {
            "denied".into()
        } else {
            "allowed".into()
        },
        reason: record.reason.clone(),
        method: record.method.clone(),
        route: record.route.clone(),
        job: record.job.clone(),
        status: status.as_u16(),
    };
    let _guard = state.access.lock().await;
    if let Err(error) = crate::access::append(&state.home, &entry) {
        // 记录写不进去是控制面故障：必须在 stderr 留痕，且不能把响应改成失败。
        eprintln!("sshpool: cannot write access audit: {error:#}");
    }
}

/// 客户端可用 `x-request-id` 提供关联标识；服务端只接受安全字符，否则换一个。
fn request_id(headers: &HeaderMap) -> String {
    let supplied = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let acceptable = !supplied.is_empty()
        && supplied.len() <= 128
        && supplied
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte));
    if acceptable {
        supplied.to_owned()
    } else {
        Uuid::new_v4().to_string()
    }
}

/// 路由模板里的任务标识；只有规范 UUID 才作为一行结构化字段记录。
fn request_id_from_path(path: &str) -> Option<Uuid> {
    path.split('/')
        .filter_map(|segment| Uuid::parse_str(segment).ok())
        .next()
}
async fn status(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
) -> ApiResult<impl IntoResponse> {
    let nodes = state.nodes().await;
    // 状态查询本身就是一次探测：它不在调度锁内，可以让调度复用同一份新鲜快照。
    Ok(axum::Json(state.refresh_health(&nodes).await))
}
async fn enable_node(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<impl IntoResponse> {
    set_node_enabled(state, name, true).await
}
async fn disable_node(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<impl IntoResponse> {
    set_node_enabled(state, name, false).await
}
async fn set_node_enabled(
    state: Arc<State>,
    name: String,
    enabled: bool,
) -> ApiResult<axum::Json<crate::config::Node>> {
    let node = state.set_node_enabled(&name, enabled).await?;
    Ok(axum::Json(node))
}
/// 只核对指定节点的未确认清理，并用远端看门狗证据解除隔离。
async fn reconcile_node(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<axum::Json<crate::reconcile::Report>> {
    Ok(axum::Json(
        crate::reconcile::reconcile(&state, Some(&name)).await?,
    ))
}
async fn reconcile_all(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
) -> ApiResult<axum::Json<crate::reconcile::Report>> {
    Ok(axum::Json(crate::reconcile::reconcile(&state, None).await?))
}

async fn jobs(
    AppState(state): AppState<Arc<State>>,
    _principal: Principal,
) -> ApiResult<impl IntoResponse> {
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
    _principal: Principal,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
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
    _principal: Principal,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
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
    _principal: Principal,
    request: Request,
) -> ApiResult<impl IntoResponse> {
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
    _principal: Principal,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Response> {
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
    _principal: Principal,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
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
    _principal: Principal,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
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
