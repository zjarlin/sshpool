use crate::{
    archive,
    config::Build,
    model::{Job, Phase},
};
use anyhow::{Context, Result, ensure};
use base64::Engine;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

/// 客户端可运行在 Linux 工作台，节点凭据只留在控制面的宿主上。
pub struct Client {
    http: reqwest::Client,
    endpoint: String,
    token: String,
}
impl Client {
    pub fn new(endpoint: String, token_file: &Path) -> Result<Self> {
        let url = reqwest::Url::parse(&endpoint)?;
        ensure!(
            ["http", "https"].contains(&url.scheme()),
            "endpoint must be HTTP(S)"
        );
        let token = std::fs::read_to_string(token_file)?.trim().to_string();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(150))
            .no_proxy()
            .build()?;
        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').into(),
            token,
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.endpoint))
            .bearer_auth(&self.token)
    }
    async fn response(response: reqwest::Response) -> Result<reqwest::Response> {
        ensure!(
            response.status().is_success(),
            "controller: {}",
            response.text().await?
        );
        Ok(response)
    }
    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        Ok(
            Self::response(self.request(reqwest::Method::GET, path).send().await?)
                .await?
                .json()
                .await?,
        )
    }
    pub async fn cancel(&self, id: Uuid) -> Result<()> {
        Self::response(
            self.request(reqwest::Method::POST, &format!("/v1/jobs/{id}/cancel"))
                .send()
                .await?,
        )
        .await?;
        Ok(())
    }
    pub async fn run(&self, project: &Path, build: Build) -> Result<i32> {
        build.validate()?;
        let archive = std::env::temp_dir().join(format!("sshpool-{}.tar", Uuid::new_v4()));
        let upload = async {
            archive::snapshot(project, &archive, 256 * 1048576)?;
            let file = tokio::fs::File::open(&archive).await?;
            let header =
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&build)?);
            let response = self
                .request(reqwest::Method::POST, "/v1/jobs")
                .header("x-sshpool-build", header)
                .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
                .send()
                .await?;
            Ok::<_, anyhow::Error>(Self::response(response).await?.json::<Job>().await?)
        }
        .await;
        if archive.exists() {
            tokio::fs::remove_file(&archive).await?;
        }
        let job = upload?;
        eprintln!("sshpool: job {}", job.id);
        tokio::select! {
            result = self.follow(job.id) => result,
            result = tokio::signal::ctrl_c() => { result?; self.cancel(job.id).await?; eprintln!("sshpool: cancellation requested; inspect job {} for confirmed cleanup", job.id); Ok(130) }
        }
    }
    pub async fn follow(&self, id: Uuid) -> Result<i32> {
        let mut offset = 0;
        let mut seen_attempts = 0;
        loop {
            let job: Job = serde_json::from_value(self.get(&format!("/v1/jobs/{id}")).await?)?;
            for attempt in job.attempts.iter().skip(seen_attempts) {
                eprintln!(
                    "sshpool: worker={} platform={} cpu={} memory={}MiB container={}",
                    attempt.node,
                    job.build.platform,
                    job.build.cpus,
                    job.build.memory_mib,
                    attempt.container
                );
            }
            seen_attempts = job.attempts.len();
            loop {
                let response = self
                    .request(
                        reqwest::Method::GET,
                        &format!("/v1/jobs/{id}/log?offset={offset}"),
                    )
                    .send()
                    .await?;
                let bytes = Self::response(response).await?.bytes().await?;
                if bytes.is_empty() {
                    break;
                }
                offset += bytes.len();
                tokio::io::stdout().write_all(&bytes).await?;
            }
            if job.phase.terminal() {
                let worker = job
                    .attempts
                    .last()
                    .map(|a| a.node.as_str())
                    .unwrap_or("none");
                eprintln!(
                    "sshpool: {:?} on {} — {}",
                    job.phase,
                    worker,
                    job.message.as_deref().unwrap_or("")
                );
                if job.artifacts {
                    eprintln!("sshpool: fetch outputs with: sshpool fetch {id}");
                }
                return Ok(job.exit_code.unwrap_or(if job.phase == Phase::Succeeded {
                    0
                } else {
                    1
                }));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    pub async fn fetch(&self, id: Uuid, output: &Path) -> Result<PathBuf> {
        ensure!(
            !output.exists(),
            "output path already exists; never overwrite existing files"
        );
        let parent = output.parent().context("output needs a parent directory")?;
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".sshpool-{}.partial", Uuid::new_v4()));
        let download = async {
            let response = self
                .request(reqwest::Method::GET, &format!("/v1/jobs/{id}/artifacts"))
                .send()
                .await?;
            let mut response = Self::response(response).await?;
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await?;
            let mut size = 0;
            while let Some(chunk) = response.chunk().await? {
                size += chunk.len();
                ensure!(size <= 256 * 1048576, "download quota exceeded");
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            archive::unpack_new(&temporary, output, 256 * 1048576)?;
            Ok::<_, anyhow::Error>(output.to_path_buf())
        }
        .await;
        if temporary.exists() {
            tokio::fs::remove_file(&temporary).await?;
        }
        download
    }
}
