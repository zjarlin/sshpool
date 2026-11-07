use crate::{
    archive,
    config::Build,
    model::{Job, Phase, now},
    probe, runner,
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
        let status = if self.0.to_string() == "unauthorized" {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, format!("{:#}", self.0)).into_response()
    }
}
type ApiResult<T> = Result<T, ApiError>;
fn authorized(headers: &HeaderMap, state: &State) -> Result<()> {
    let actual = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = format!("Bearer {}", state.token);
    ensure!(
        actual.len() == expected.len()
            && actual
                .bytes()
                .zip(expected.bytes())
                .fold(0_u8, |v, (a, b)| v | (a ^ b))
                == 0,
        "unauthorized"
    );
    Ok(())
}
pub fn routes(state: Arc<State>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/nodes/{name}/enable", post(enable_node))
        .route("/v1/nodes/{name}/disable", post(disable_node))
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
    authorized(&headers, &state)?;
    let nodes = state.nodes().await;
    Ok(axum::Json(probe::all(&nodes).await))
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
    authorized(&headers, &state)?;
    let node = state.set_node_enabled(&name, enabled).await?;
    Ok(axum::Json(node))
}
async fn jobs(
    AppState(state): AppState<Arc<State>>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorized(&headers, &state)?;
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
    authorized(&headers, &state)?;
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
    authorized(&headers, &state)?;
    // 与首次领取任务共用调度锁，避免取消和进入 Running 的窄竞态。
    let _scheduling = state.scheduling.lock().await;
    let mut jobs = state.jobs.lock().await;
    let job = jobs.get_mut(&id).context("unknown job")?;
    if !job.phase.terminal() {
        job.cancel_requested = true;
        state.persist(job)?;
    }
    let record = job.clone();
    drop(jobs);
    state.wake_queue();
    Ok(axum::Json(record))
}
async fn submit(
    AppState(state): AppState<Arc<State>>,
    request: Request,
) -> ApiResult<impl IntoResponse> {
    authorized(request.headers(), &state)?;
    let encoded = request
        .headers()
        .get("x-sshpool-build")
        .context("missing build header")?
        .to_str()
        .map_err(anyhow::Error::from)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(anyhow::Error::from)?;
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
        archive::validate(&source, maximum, None)?;
        Ok::<_, anyhow::Error>(())
    };
    let transfer = tokio::time::timeout(std::time::Duration::from_secs(120), transfer).await;
    let result = match transfer {
        Ok(value) => value,
        Err(_) => Err(anyhow::anyhow!("upload timed out")),
    };
    if let Err(error) = result {
        // 此目录由本次请求创建且尚未发布，只删除该请求自己的部分上传。
        fs::remove_dir_all(&directory).map_err(anyhow::Error::from)?;
        return Err(error.into());
    }
    let created_at = now();
    let queue_deadline =
        (queue_timeout_secs > 0).then_some(created_at.saturating_add(queue_timeout_secs));
    let job = Job {
        id,
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
    };
    state.persist(&job)?;
    state.jobs.lock().await.insert(id, job.clone());
    state.event(id, "submitted", "source validated").await?;
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
    authorized(&headers, &state)?;
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
    authorized(&headers, &state)?;
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
    authorized(&headers, &state)?;
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
