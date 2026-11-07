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
    /// `ca_file` 为空时使用系统信任链；显式给出时只信任该 CA 文件。
    ///
    /// 不提供「跳过校验」参数：跨不可信网络时能关掉的校验等于没有校验。
    pub fn new(endpoint: String, token_file: &Path, ca_file: Option<&Path>) -> Result<Self> {
        let url = reqwest::Url::parse(&endpoint)?;
        ensure!(
            ["http", "https"].contains(&url.scheme()),
            "endpoint must be HTTP(S)"
        );
        ensure!(
            url.scheme() == "https" || ca_file.is_none(),
            "a CA file only applies to an https endpoint"
        );
        let token = std::fs::read_to_string(token_file)?.trim().to_string();
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(150))
            .no_proxy();
        if let Some(ca_file) = ca_file {
            let mut roots = crate::tls::client_roots(ca_file)?;
            // 只用这份 CA，不叠加系统根：内网部署的信任边界应当是明确的。
            builder = builder.tls_built_in_root_certs(false);
            for certificate in roots.drain(..) {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build()?;
        Ok(Self {
            http,
            endpoint: endpoint.trim_end_matches('/').into(),
            token,
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        // 每个请求带一个标识，控制面的访问审计据此把客户端动作与服务端记录对上。
        self.http
            .request(method, format!("{}{path}", self.endpoint))
            .header("x-request-id", Uuid::new_v4().to_string())
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
    /// 请求控制面在线启停节点；控制面负责持久化配置并执行活动任务保护。
    pub async fn set_node_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let action = if enabled { "enable" } else { "disable" };
        let response = self
            .request(reqwest::Method::POST, &format!("/v1/nodes/{name}/{action}"))
            .send()
            .await?;
        Self::response(response).await?;
        Ok(())
    }
    /// 在线核对未确认清理；只返回证据结果，不在客户端做任何推断。
    pub async fn reconcile_node(&self, name: Option<&str>) -> Result<serde_json::Value> {
        let path = match name {
            Some(name) => format!("/v1/nodes/{name}/reconcile"),
            None => "/v1/nodes/reconcile".into(),
        };
        Ok(
            Self::response(self.request(reqwest::Method::POST, &path).send().await?)
                .await?
                .json()
                .await?,
        )
    }
    /// 读取任务日志的原始字节；`offset` 是已消费的字节数，接口不返回 JSON。
    ///
    /// 一次最多返回 256 KiB，调用方需要按返回长度推进 `offset` 直到空响应。
    pub async fn log(&self, id: Uuid, offset: u64) -> Result<Vec<u8>> {
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/v1/jobs/{id}/log?offset={offset}"),
            )
            .send()
            .await?;
        Ok(Self::response(response).await?.bytes().await?.to_vec())
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
            let snapshot = archive::snapshot(project, &archive, 256 * 1048576)?;
            let file = tokio::fs::File::open(&archive).await?;
            let header =
                base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&build)?);
            let response = self
                .request(reqwest::Method::POST, "/v1/jobs")
                .header("x-sshpool-build", header)
                .header("x-sshpool-source-sha256", snapshot.sha256)
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
                let bytes = self.log(id, offset).await?;
                if bytes.is_empty() {
                    break;
                }
                offset += bytes.len() as u64;
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
