//! 任务状态的跨主机复制与恢复；远端只保存经过摘要核对的内容寻址归档。
use crate::{
    archive,
    config::{Config, Node, Replica},
    model::{Job, now},
    transport,
};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const ALLOWED_FILES: &[&str] = &[
    "job.json",
    ".revision",
    "source.tar",
    "log.txt",
    "events.jsonl",
    "artifacts.tar",
];

/// 远端发布指针引用不可变对象；恢复方不能只凭任务目录中的任意文件信任状态。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub job: Uuid,
    /// 每个 revision 都是不可变历史；发布指针损坏时默认拒绝回退更旧版本。
    pub revision: u64,
    pub bundle_sha256: String,
    pub bytes: u64,
    pub created_at: u64,
}

/// 单个副本的提交证明只宣称该副本已落盘，是否同时写入本地由恢复方计数。
///
/// 配置的 quorum 由恢复方按多个副本的实际可读故障域重新计数；
/// 一个副本不能替尚未确认写入的节点作证。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CommitProof {
    schema: u32,
    job: Uuid,
    revision: u64,
    bundle_sha256: String,
    required_domains: usize,
    failure_domains: Vec<String>,
    /// 远端证明携带本地先落盘的回执；M3 整机丢失后仍能核对这次参与。
    local_receipt: LocalReceipt,
}

/// 在远端写入前持久化的本地提交意图。它本身不等于 quorum 已成功。
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalReceipt {
    schema: u32,
    job: Uuid,
    revision: u64,
    bundle_sha256: String,
    required_domains: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RemoteJob {
    schema: u32,
    job: Uuid,
    /// 已发布的 revision 文件，可能包含尚未完成提交证明的写入。
    revisions: Vec<u64>,
    /// 已写入提交文件的 revision；是否达到 quorum 还要跨副本计数。
    #[serde(default)]
    committed: Vec<u64>,
    legacy: bool,
}

/// 单个副本的校验结果；错误保留在列表中，不因另一个副本健康而隐藏。
#[derive(Clone, Debug, Serialize)]
pub struct ReplicaHealth {
    pub name: String,
    pub failure_domain: String,
    pub host_id_sha256: String,
    pub healthy: bool,
    pub error: Option<String>,
}

fn replica_node(replica: &Replica) -> Node {
    Node {
        name: replica.name.clone(),
        ssh: replica.ssh.clone(),
        images: Vec::new(),
        ssh_config: replica.ssh_config.clone(),
        enabled: replica.enabled,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
        slo: Default::default(),
    }
}

/// 任务目录只打包固定文件，使用规范化元数据生成可校验的恢复归档。
pub fn create_bundle(job_dir: &Path, destination: &Path, limit: u64) -> Result<Manifest> {
    let job: Job = serde_json::from_slice(&fs::read(job_dir.join("job.json"))?)?;
    create_bundle_for_job(job_dir, destination, limit, &job)
}

/// 用内存中的候选状态生成归档，使终态能在本地发布前先获得远端确认。
fn create_bundle_for_job(
    job_dir: &Path,
    destination: &Path,
    limit: u64,
    job: &Job,
) -> Result<Manifest> {
    let directory_name = job_dir
        .file_name()
        .and_then(|value| value.to_str())
        .context("job directory has no UTF-8 name")?;
    ensure!(
        directory_name == job.id.to_string(),
        "job directory identity mismatch"
    );
    let source = job_dir.join("source.tar");
    ensure!(source.is_file(), "source archive is missing");
    archive::validate(&source, limit, None)?;
    let source_digest = job
        .source_sha256
        .as_deref()
        .context("source digest is missing")?;
    ensure!(
        archive::sha256_file(&source)? == source_digest,
        "source digest changed before replication"
    );
    let artifacts = job_dir.join("artifacts.tar");
    if job.artifacts {
        ensure!(artifacts.is_file(), "declared artifacts archive is missing");
        archive::validate(&artifacts, limit, None)?;
    }
    let job_json = serde_json::to_vec_pretty(job)?;
    let file = File::create(destination)?;
    let mut builder = tar::Builder::new(file);
    for name in ALLOWED_FILES {
        let (size, input): (u64, Box<dyn std::io::Read>) = if *name == "job.json" {
            (
                job_json.len() as u64,
                Box::new(std::io::Cursor::new(&job_json)),
            )
        } else if *name == ".revision" {
            let revision = job.revision.to_string();
            (
                revision.len() as u64,
                Box::new(std::io::Cursor::new(revision.into_bytes())),
            )
        } else {
            let path = job_dir.join(name);
            if !path.exists() {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "replica file is not a regular file: {name}"
            );
            (metadata.len(), Box::new(File::open(&path)?))
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o600);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, name, input)?;
    }
    builder.finish()?;
    drop(builder);
    File::open(destination)?.sync_all()?;
    let bytes = fs::metadata(destination)?.len();
    ensure!(bytes <= limit, "job replica exceeds configured size limit");
    let sha256 = archive::sha256_file(destination)?;
    Ok(Manifest {
        schema: 2,
        job: job.id,
        revision: job.revision,
        bundle_sha256: sha256,
        bytes,
        // 同一候选重试必须得到同一清单，不能因当前时间不同撞上不可变候选。
        created_at: job.created_at,
    })
}

/// 恢复先写入临时目录，核对任务标识、源码摘要和允许文件后才原子发布。
pub fn install_bundle(home: &Path, expected: Uuid, bundle: &Path, limit: u64) -> Result<PathBuf> {
    archive::validate(bundle, limit, None)?;
    let jobs = home.join("jobs");
    fs::create_dir_all(&jobs)?;
    let final_dir = jobs.join(expected.to_string());
    ensure!(
        !final_dir.exists(),
        "job already exists; restore never overwrites local state"
    );
    let stage = jobs.join(format!(".restore-{}", Uuid::new_v4()));
    fs::create_dir(&stage)?;
    let result = (|| {
        let mut tar = tar::Archive::new(File::open(bundle)?);
        let mut seen_job = false;
        let mut seen_source = false;
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.into_owned();
            let name = path.to_str().context("non-UTF8 replica path")?;
            ensure!(
                ALLOWED_FILES.contains(&name),
                "undeclared replica file: {name}"
            );
            ensure!(
                entry.header().entry_type().is_file(),
                "replica bundle contains a non-file entry"
            );
            seen_job |= name == "job.json";
            seen_source |= name == "source.tar";
            entry.unpack_in(&stage)?;
        }
        ensure!(
            seen_job && seen_source,
            "replica is missing job.json or source.tar"
        );
        let job: Job = serde_json::from_slice(&fs::read(stage.join("job.json"))?)?;
        ensure!(job.id == expected, "replica job identity mismatch");
        match fs::read_to_string(stage.join(".revision")) {
            Ok(value) => {
                let revision = value
                    .trim()
                    .parse::<u64>()
                    .context("replica has an invalid revision reservation")?;
                ensure!(
                    revision == job.revision,
                    "replica revision reservation and job state disagree"
                );
            }
            // schema 1 旧归档没有单独版本文件；只允许原无版本任务兼容恢复。
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && job.revision == 0 => {}
            Err(error) => return Err(error.into()),
        }
        let source = stage.join("source.tar");
        archive::validate(&source, limit, None)?;
        let expected_digest = job
            .source_sha256
            .as_deref()
            .context("replica source digest is missing")?;
        ensure!(
            archive::sha256_file(&source)? == expected_digest,
            "replica source digest mismatch"
        );
        if job.artifacts {
            let artifacts = stage.join("artifacts.tar");
            ensure!(
                artifacts.is_file(),
                "successful replica has no artifacts archive"
            );
            archive::validate(&artifacts, limit, None)?;
        }
        fs::rename(&stage, &final_dir)?;
        File::open(&jobs)?.sync_all()?;
        Ok(final_dir.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

/// Linux 优先使用硬件 DMI 身份，macOS 使用平台 UUID；摘要不会进入普通日志。
const HOST_IDENTITY_PY: &str = r#"import hashlib,os,platform,subprocess
def host_identity():
    if platform.system()=='Linux':
        candidates=['/sys/class/dmi/id/product_uuid','/etc/machine-id','/var/lib/dbus/machine-id']
        for path in candidates:
            try:
                raw=open(path,encoding='ascii').read().strip()
            except OSError:
                continue
            if raw:
                return hashlib.sha256((path+'\n'+raw).encode()).hexdigest()
        raise SystemExit('host identity is unavailable')
    if platform.system()=='Darwin':
        output=subprocess.run(['ioreg','-rd1','-c','IOPlatformExpertDevice'],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,check=True).stdout
        marker='"IOPlatformUUID" = "'
        start=output.find(marker)
        if start<0:
            raise SystemExit('macOS hardware identity is unavailable')
        start+=len(marker)
        end=output.find('"',start)
        if end<=start:
            raise SystemExit('macOS hardware identity is invalid')
        return hashlib.sha256(output[start:end].encode()).hexdigest()
    raise SystemExit('unsupported replica operating system')
host_id=host_identity()
"#;

fn host_identity_prelude(expected: &str) -> String {
    format!(
        r#"{HOST_IDENTITY_PY}
expected={expected:?}
if host_id!=expected:
    raise SystemExit('replica host identity changed')
"#
    )
}

/// 登记副本前只创建专用隐藏目录，并返回不可逆主机身份摘要。
pub async fn prepare(ssh: &str, ssh_config: Option<&Path>, namespace: &str) -> Result<String> {
    crate::config::validate_replica(&Replica {
        name: "replica-admission".into(),
        ssh: ssh.into(),
        namespace: namespace.into(),
        failure_domain: "replica-admission".into(),
        expected_host_id_sha256: "0".repeat(64),
        ssh_config: ssh_config.map(Path::to_path_buf),
        enabled: false,
    })?;
    let node = Node {
        name: "replica-admission".into(),
        ssh: ssh.into(),
        images: Vec::new(),
        ssh_config: ssh_config.map(Path::to_path_buf),
        enabled: false,
        max_jobs: 1,
        reserve_memory_mib: 0,
        reserve_disk_mib: 0,
        max_load_per_cpu: 1.0,
        priority: 0,
        slo: Default::default(),
    };
    crate::config::validate_node(&node)?;
    let root = format!("~/.sshpool-replica/{namespace}");
    let source = format!(
        r#"{HOST_IDENTITY_PY}
import json
root=os.path.expanduser({root:?})
if os.path.islink(root) or (os.path.exists(root) and not os.path.isdir(root)):
    raise SystemExit('replica root is not a directory')
os.makedirs(root,mode=0o700,exist_ok=True)
os.chmod(root,0o700)
for name in ('objects','jobs'):
    path=os.path.join(root,name)
    if os.path.islink(path) or (os.path.exists(path) and not os.path.isdir(path)):
        raise SystemExit('replica child is not a directory')
    os.makedirs(path,mode=0o700,exist_ok=True)
    os.chmod(path,0o700)
print(json.dumps({{'schema':1,'host_id_sha256':host_id}}))
"#
    );
    let script = format!("python3 -c {}", transport::quote(&source));
    let output = transport::checked(&node, &script, 30).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&output).context("replica admission returned invalid JSON")?;
    let host_id = value
        .get("host_id_sha256")
        .and_then(serde_json::Value::as_str)
        .context("replica admission did not return host identity")?
        .to_string();
    ensure!(
        host_id.len() == 64
            && host_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "replica admission returned invalid host identity"
    );
    Ok(host_id)
}

fn push_script(replica: &Replica, manifest: &Manifest) -> Result<String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(manifest)?);
    let digest = manifest.bundle_sha256.clone();
    let job = manifest.job.to_string();
    let revision = manifest.revision;
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import base64,hashlib,json,os,sys,tempfile
root=os.path.expanduser({root:?})
if os.path.islink(root) or (os.path.exists(root) and not os.path.isdir(root)):
    raise SystemExit('replica root is not a directory')
os.makedirs(root,mode=0o700,exist_ok=True)
os.chmod(root,0o700)
objects=os.path.join(root,'objects')
manifests=os.path.join(root,'jobs')
for path in (objects,manifests):
    if os.path.islink(path) or (os.path.exists(path) and not os.path.isdir(path)):
        raise SystemExit('replica child is not a directory')
    os.makedirs(path,mode=0o700,exist_ok=True)
    os.chmod(path,0o700)
manifest=json.loads(base64.b64decode({encoded:?}))
expected={digest:?}
job={job:?}
revision={revision}
if manifest.get('schema')!=2 or manifest.get('job')!=job or manifest.get('revision')!=revision or manifest.get('bundle_sha256')!=expected:
    raise SystemExit('manifest identity mismatch')
fd,temp=tempfile.mkstemp(prefix='.object-',dir=objects)
hasher=hashlib.sha256()
try:
    with os.fdopen(fd,'wb') as output:
        while True:
            data=sys.stdin.buffer.read(65536)
            if not data:
                break
            hasher.update(data)
            output.write(data)
        output.flush()
        os.fsync(output.fileno())
    actual=hasher.hexdigest()
    if actual!=expected:
        raise SystemExit('bundle digest mismatch')
    target=os.path.join(objects,expected+'.tar')
    if os.path.exists(target):
        stored=hashlib.sha256()
        with open(target,'rb') as source:
            for chunk in iter(lambda:source.read(65536),b''):
                stored.update(chunk)
        if stored.hexdigest()!=expected:
            raise SystemExit('existing object digest mismatch')
        os.unlink(temp)
    else:
        os.chmod(temp,0o600)
        os.replace(temp,target)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
directory=os.open(objects,os.O_RDONLY)
os.fsync(directory)
os.close(directory)
job_dir=os.path.join(manifests,job)
if os.path.islink(job_dir) or (os.path.exists(job_dir) and not os.path.isdir(job_dir)):
    raise SystemExit('job history is not a directory')
os.makedirs(job_dir,mode=0o700,exist_ok=True)
os.chmod(job_dir,0o700)
manifest_path=os.path.join(job_dir,str(revision)+'.candidate.json')
if os.path.exists(manifest_path):
    existing=json.load(open(manifest_path))
    if existing!=manifest:
        raise SystemExit('immutable revision conflict')
fd,temp=tempfile.mkstemp(prefix='.manifest-',dir=job_dir)
try:
    with os.fdopen(fd,'w') as output:
        output.write(json.dumps(manifest,sort_keys=True))
        output.write(chr(10))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temp,0o600)
    if not os.path.exists(manifest_path):
        os.replace(temp,manifest_path)
    else:
        os.unlink(temp)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
directory=os.open(job_dir,os.O_RDONLY)
os.fsync(directory)
os.close(directory)
print(json.dumps(manifest,sort_keys=True))
"#
    );
    Ok(format!("python3 -c {}", transport::quote(&source)))
}

/// 向一个副本准备候选；成功只表示对象和候选清单已落盘，尚不可用于恢复。
pub async fn push(replica: &Replica, manifest: &Manifest, bundle: &Path) -> Result<String> {
    let node = replica_node(replica);
    let script = push_script(replica, manifest)?;
    let output = transport::upload_capture(&node, &script, bundle, 180).await?;
    let received: Manifest =
        serde_json::from_slice(&output).context("replica returned an invalid manifest")?;
    ensure!(
        received == *manifest,
        "replica manifest acknowledgement mismatch"
    );
    Ok(replica.name.clone())
}

const COMMIT_VALIDATION_PY: &str = r#"def valid_commit(manifest,proof,job,revision,expected,replica_domain):
    if proof.get('schema')!=2 or proof.get('job')!=job or proof.get('revision')!=revision or proof.get('bundle_sha256')!=expected:
        return False
    domains=proof.get('failure_domains')
    required=proof.get('required_domains')
    local_receipt=proof.get('local_receipt')
    if not isinstance(domains,list) or not isinstance(required,int) or isinstance(required,bool):
        return False
    if required<2:
        return False
    if any(not isinstance(value,str) or not value or len(value)>128 for value in domains):
        return False
    if len(domains)!=1 or len(set(domains))!=1:
        return False
    if replica_domain not in domains:
        return False
    if not isinstance(local_receipt,dict):
        return False
    if local_receipt.get('schema')!=1 or local_receipt.get('job')!=job or local_receipt.get('revision')!=revision or local_receipt.get('bundle_sha256')!=expected or local_receipt.get('required_domains')!=required:
        return False
    return True
"#;

fn commit_script(replica: &Replica, manifest: &Manifest, proof: &CommitProof) -> Result<String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(manifest)?);
    let digest = manifest.bundle_sha256.clone();
    let job = manifest.job.to_string();
    let revision = manifest.revision;
    let proof = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(proof)?);
    let replica_domain = replica.failure_domain.clone();
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
{COMMIT_VALIDATION_PY}
import base64,hashlib,json,os,tempfile
root=os.path.expanduser({root:?})
objects=os.path.join(root,'objects')
manifests=os.path.join(root,'jobs')
manifest=json.loads(base64.b64decode({encoded:?}))
proof=json.loads(base64.b64decode({proof:?}))
expected={digest:?}
job={job:?}
revision={revision}
replica_domain={replica_domain:?}
if manifest.get('schema')!=2 or manifest.get('job')!=job or manifest.get('revision')!=revision or manifest.get('bundle_sha256')!=expected:
    raise SystemExit('manifest identity mismatch')
if not valid_commit(manifest,proof,job,revision,expected,replica_domain):
    raise SystemExit('commit proof mismatch')
job_dir=os.path.join(manifests,job)
candidate_path=os.path.join(job_dir,str(revision)+'.candidate.json')
published_path=os.path.join(job_dir,str(revision)+'.json')
proof_path=os.path.join(job_dir,str(revision)+'.commit.json')
candidate=json.load(open(candidate_path))
if candidate!=manifest:
    raise SystemExit('candidate manifest mismatch')
if os.path.exists(published_path):
    if json.load(open(published_path))!=manifest:
        raise SystemExit('immutable published revision conflict')
    if os.path.exists(proof_path) and json.load(open(proof_path))!=proof:
        raise SystemExit('immutable commit proof conflict')
object_path=os.path.join(objects,expected+'.tar')
hasher=hashlib.sha256()
with open(object_path,'rb') as source:
    for chunk in iter(lambda:source.read(65536),b''):
        hasher.update(chunk)
if hasher.hexdigest()!=expected:
    raise SystemExit('stored object digest mismatch')
if not os.path.exists(published_path):
    os.replace(candidate_path,published_path)
if not os.path.exists(proof_path):
    fd,temp=tempfile.mkstemp(prefix='.proof-',dir=job_dir)
    try:
        with os.fdopen(fd,'w') as output:
            output.write(json.dumps(proof,sort_keys=True))
            output.write(chr(10))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp,0o600)
        os.replace(temp,proof_path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
directory=os.open(job_dir,os.O_RDONLY)
os.fsync(directory)
os.close(directory)
latest_path=os.path.join(manifests,job+'.json')
fd,temp=tempfile.mkstemp(prefix='.latest-',dir=manifests)
try:
    with os.fdopen(fd,'w') as output:
        output.write(json.dumps({{'schema':2,'job':job,'revision':revision}},sort_keys=True))
        output.write(chr(10))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temp,0o600)
    os.replace(temp,latest_path)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
directory=os.open(manifests,os.O_RDONLY)
os.fsync(directory)
os.close(directory)
print(json.dumps(manifest,sort_keys=True))
"#
    );
    Ok(format!("python3 -c {}", transport::quote(&source)))
}

/// 发布候选清单；只有这一步成功后的 revision 才能被恢复扫描到。
async fn commit_replica(
    replica: &Replica,
    manifest: &Manifest,
    proof: &CommitProof,
) -> Result<String> {
    let node = replica_node(replica);
    let script = commit_script(replica, manifest, proof)?;
    let output = transport::checked(&node, &script, 30).await?;
    let received: Manifest =
        serde_json::from_slice(&output).context("replica returned an invalid commit")?;
    ensure!(
        received == *manifest,
        "replica commit acknowledgement mismatch"
    );
    Ok(replica.name.clone())
}

fn check_script(replica: &Replica) -> String {
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import json,os,tempfile
root=os.path.expanduser({root:?})
if os.path.islink(root) or not os.path.isdir(root):
    raise SystemExit('replica directory is missing')
if os.stat(root).st_uid!=os.getuid():
    raise SystemExit('replica directory is not owned by the SSH user')
for name in ('objects','jobs'):
    path=os.path.join(root,name)
    if os.path.islink(path) or not os.path.isdir(path):
        raise SystemExit('replica child directory is missing')
    if os.stat(path).st_uid!=os.getuid():
        raise SystemExit('replica child directory is not owned by the SSH user')
fd,temp=tempfile.mkstemp(prefix='.health-',dir=os.path.join(root,'jobs'))
try:
    os.write(fd,b'ok')
    os.fsync(fd)
finally:
    os.close(fd)
os.unlink(temp)
directory=os.open(os.path.join(root,'jobs'),os.O_RDONLY)
os.fsync(directory)
os.close(directory)
print(json.dumps({{'schema':1,'objects':True,'jobs':True,'host_id_sha256':host_id}}))
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

pub async fn health(config: &Config) -> Vec<ReplicaHealth> {
    join_all(
        config
            .replicas
            .iter()
            .filter(|replica| replica.enabled)
            .map(|replica| async move {
                let node = replica_node(replica);
                let result = transport::checked(&node, &check_script(replica), 20).await;
                ReplicaHealth {
                    name: replica.name.clone(),
                    failure_domain: replica.failure_domain.clone(),
                    host_id_sha256: replica.expected_host_id_sha256.clone(),
                    healthy: result.is_ok(),
                    error: result.err().map(|error| format!("{error:#}")),
                }
            }),
    )
    .await
}

fn fetch_script(replica: &Replica, id: Uuid, revision: u64) -> String {
    let id = id.to_string();
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import hashlib,json,os,sys
job={id:?}
revision={revision}
root=os.path.expanduser({root:?})
manifest=json.load(open(os.path.join(root,'jobs',job,str(revision)+'.json')))
if manifest.get('schema')!=2 or manifest.get('job')!=job or manifest.get('revision')!=revision:
    raise SystemExit('manifest identity mismatch')
digest=manifest.get('bundle_sha256','')
if len(digest)!=64:
    raise SystemExit('invalid bundle digest')
path=os.path.join(root,'objects',digest+'.tar')
hasher=hashlib.sha256()
with open(path,'rb') as source:
    for chunk in iter(lambda:source.read(65536),b''):
        hasher.update(chunk)
if hasher.hexdigest()!=digest:
    raise SystemExit('stored object digest mismatch')
with open(path,'rb') as source:
    while True:
        data=source.read(65536)
        if not data:
            break
        sys.stdout.buffer.write(data)
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

fn fetch_legacy_script(replica: &Replica, id: Uuid) -> String {
    let id = id.to_string();
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import hashlib,json,os,sys
job={id:?}
root=os.path.expanduser({root:?})
manifest=json.load(open(os.path.join(root,'jobs',job+'.json')))
if manifest.get('schema')!=1 or manifest.get('job')!=job:
    raise SystemExit('legacy manifest identity mismatch')
digest=manifest.get('bundle_sha256','')
if len(digest)!=64:
    raise SystemExit('invalid bundle digest')
path=os.path.join(root,'objects',digest+'.tar')
hasher=hashlib.sha256()
with open(path,'rb') as source:
    for chunk in iter(lambda:source.read(65536),b''):
        hasher.update(chunk)
if hasher.hexdigest()!=digest:
    raise SystemExit('stored object digest mismatch')
with open(path,'rb') as source:
    while True:
        data=source.read(65536)
        if not data:
            break
        sys.stdout.buffer.write(data)
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

async fn download_version(
    replica: &Replica,
    id: Uuid,
    revision: Option<u64>,
    destination: &Path,
    limit: u64,
    required_domains: usize,
) -> Result<Option<CommitProof>> {
    let node = replica_node(replica);
    let (script, proof_path) = match revision {
        Some(revision) => (
            fetch_script(replica, id, revision),
            destination.with_extension("commit.json"),
        ),
        None => (fetch_legacy_script(replica, id), destination.to_path_buf()),
    };
    if let Some(revision) = revision {
        transport::download(&node, &script, destination, 180).await?;
        let proof_script = fetch_proof_script(replica, id, revision);
        transport::download(&node, &proof_script, &proof_path, 16).await?;
        ensure!(
            fs::metadata(&proof_path)?.len() <= 65536,
            "fetched commit proof exceeds size limit"
        );
        let proof: CommitProof =
            serde_json::from_slice(&fs::read(&proof_path)?).context("invalid commit proof")?;
        validate_commit_proof(
            &proof,
            id,
            revision,
            required_domains,
            &replica.failure_domain,
        )?;
        ensure!(
            archive::sha256_file(destination)? == proof.bundle_sha256,
            "commit proof digest does not match the downloaded bundle"
        );
        let _ = fs::remove_file(&proof_path);
        ensure!(
            fs::metadata(destination)?.len() <= limit,
            "fetched replica exceeds size limit"
        );
        return Ok(Some(proof));
    }
    transport::download(&node, &script, destination, 180).await?;
    ensure!(
        fs::metadata(destination)?.len() <= limit,
        "fetched replica exceeds size limit"
    );
    Ok(None)
}

fn fetch_proof_script(replica: &Replica, id: Uuid, revision: u64) -> String {
    let id = id.to_string();
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import os,sys
job={id:?}
revision={revision}
root=os.path.expanduser({root:?})
path=os.path.join(root,'jobs',job,str(revision)+'.commit.json')
with open(path,'rb') as source:
    while True:
        data=source.read(65536)
        if not data:
            break
        sys.stdout.buffer.write(data)
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

fn versions_script(replica: &Replica, id: Uuid) -> String {
    let id = id.to_string();
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import json,os
job={id:?}
root=os.path.expanduser({root:?})
directory=os.path.join(root,'jobs')
if os.path.islink(root) or not os.path.isdir(root) or os.stat(root).st_uid!=os.getuid():
    raise SystemExit('replica root is unavailable')
job_dir=os.path.join(directory,job)
revisions=[]
committed=[]
if os.path.isdir(job_dir) and not os.path.islink(job_dir):
    for name in os.listdir(job_dir):
        if name.endswith('.json') and not name.startswith('.'):
            try:
                value=int(name[:-5])
            except ValueError:
                continue
            if value>=0:
                revisions.append(value)
    for name in os.listdir(job_dir):
        if name.endswith('.commit.json') and not name.startswith('.'):
            try:
                value=int(name[:-len('.commit.json')])
            except ValueError:
                continue
            if value>=0:
                committed.append(value)
legacy=False
pointer=os.path.join(directory,job+'.json')
if os.path.isfile(pointer) and not os.path.islink(pointer):
    manifest=json.load(open(pointer))
    legacy=manifest.get('schema')==1 and manifest.get('job')==job
print(json.dumps({{'schema':2,'job':job,'revisions':sorted(set(revisions)),'committed':sorted(set(committed)),'legacy':legacy}},sort_keys=True))
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

async fn versions(replica: &Replica, id: Uuid) -> Result<(Vec<u64>, Vec<u64>, bool)> {
    let node = replica_node(replica);
    let output = transport::checked(&node, &versions_script(replica, id), 20).await?;
    let value: RemoteJob = serde_json::from_slice(&output)?;
    ensure!(value.schema == 2, "unsupported replica version schema");
    ensure!(value.job == id, "replica version identity mismatch");
    Ok((value.revisions, value.committed, value.legacy))
}

fn list_script(replica: &Replica) -> String {
    let identity = host_identity_prelude(&replica.expected_host_id_sha256);
    let root = format!("~/.sshpool-replica/{}", replica.namespace);
    let source = format!(
        r#"{identity}
import json,os,uuid
root=os.path.expanduser({root:?})
directory=os.path.join(root,'jobs')
if os.path.islink(root) or not os.path.isdir(root) or os.stat(root).st_uid!=os.getuid():
    raise SystemExit('replica root is unavailable')
if os.path.islink(directory) or not os.path.isdir(directory) or os.stat(directory).st_uid!=os.getuid():
    raise SystemExit('replica jobs directory is unavailable')
values=[]
if os.path.isdir(directory):
    for name in sorted(os.listdir(directory)):
        if name.startswith('.'):
            continue
        if name.endswith('.json'):
            try:
                uuid.UUID(name[:-5])
            except ValueError:
                continue
            values.append(name[:-5])
            continue
        path=os.path.join(directory,name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        try:
            uuid.UUID(name)
        except ValueError:
            continue
        values.append(name)
print(json.dumps(sorted(set(values))))
"#
    );
    format!("python3 -c {}", transport::quote(&source))
}

pub async fn list(replica: &Replica) -> Result<Vec<Uuid>> {
    let node = replica_node(replica);
    let output = transport::checked(&node, &list_script(replica), 20).await?;
    Ok(serde_json::from_slice(&output)?)
}

/// 将当前任务镜像到配置副本；低于 min_ack 就返回错误，调用方不得提交成功结果。
pub async fn sync_job(config: &Config, home: &Path, id: Uuid) -> Result<Vec<String>> {
    let job: Job = serde_json::from_slice(&fs::read(
        home.join("jobs").join(id.to_string()).join("job.json"),
    )?)?;
    ensure!(job.id == id, "job identity mismatch");
    sync_job_state(config, home, &job).await
}

fn receipt_directory(home: &Path) -> PathBuf {
    home.join("replica-receipts")
}

fn receipt_path(home: &Path, id: Uuid, revision: u64) -> PathBuf {
    receipt_directory(home).join(format!("{id}-{revision}.json"))
}

/// 在任何远端写入前落盘本地意图；同一 revision 出现不同摘要时永久拒绝。
fn persist_local_receipt(home: &Path, receipt: &LocalReceipt) -> Result<()> {
    let directory = receipt_directory(home);
    let created = !directory.exists();
    fs::create_dir_all(&directory)?;
    if created {
        File::open(home)?.sync_all()?;
    }
    let path = receipt_path(home, receipt.job, receipt.revision);
    let bytes = serde_json::to_vec_pretty(receipt)?;
    if path.exists() {
        let stored: LocalReceipt = serde_json::from_slice(&fs::read(&path)?)
            .context("invalid local durability receipt")?;
        ensure!(stored == *receipt, "immutable local receipt conflict");
    } else {
        crate::config::atomic_write(&path, &bytes)?;
    }
    Ok(())
}

fn read_local_receipt(home: &Path, id: Uuid, revision: u64) -> Result<Option<LocalReceipt>> {
    let path = receipt_path(home, id, revision);
    match fs::read(&path) {
        Ok(bytes) => {
            let receipt: LocalReceipt =
                serde_json::from_slice(&bytes).context("invalid local durability receipt")?;
            ensure!(
                receipt.schema == 1
                    && receipt.job == id
                    && receipt.revision == revision
                    && receipt.required_domains >= 2,
                "local durability receipt identity mismatch"
            );
            Ok(Some(receipt))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// 复制内存候选状态；远端确认完成后调用方才能持久化并发布本地终态。
pub async fn sync_job_state(config: &Config, home: &Path, job: &Job) -> Result<Vec<String>> {
    let enabled = config
        .replicas
        .iter()
        .filter(|replica| replica.enabled)
        .collect::<Vec<_>>();
    if enabled.is_empty() {
        ensure!(config.replica_min_ack == 0, "no enabled state replica");
        return Ok(Vec::new());
    }
    ensure!(
        config.replica_min_ack >= 2 && config.replica_min_ack <= enabled.len() + 1,
        "state durability quorum exceeds local plus enabled replicas"
    );
    let stage = home.join("replica-stage");
    fs::create_dir_all(&stage)?;
    let bundle = stage.join(format!("{}-{}.tar", job.id, Uuid::new_v4()));
    let limit =
        (config.max_upload_mib + config.max_artifact_mib + config.max_log_mib + 16) * 1048576;
    let manifest = create_bundle_for_job(
        &home.join("jobs").join(job.id.to_string()),
        &bundle,
        limit,
        job,
    )?;
    let local_receipt = LocalReceipt {
        schema: 1,
        job: job.id,
        revision: job.revision,
        bundle_sha256: manifest.bundle_sha256.clone(),
        required_domains: config.replica_min_ack,
    };
    persist_local_receipt(home, &local_receipt)?;
    let prepared = join_all(
        enabled
            .iter()
            .map(|replica| async { push(replica, &manifest, &bundle).await }),
    )
    .await;
    let _ = fs::remove_file(&bundle);
    let required_remote = config.replica_min_ack - 1;
    let mut prepared_replicas = Vec::new();
    let mut errors = Vec::new();
    for (replica, result) in enabled.into_iter().zip(prepared) {
        match result {
            Ok(_) => prepared_replicas.push(replica),
            Err(error) => errors.push(format!("{} prepare: {error:#}", replica.name)),
        }
    }
    if prepared_replicas.len() < required_remote {
        bail!(
            "state durability quorum not met while preparing: local + {} replicas/{} required; {}",
            prepared_replicas.len(),
            config.replica_min_ack,
            errors.join("; ")
        );
    }
    // 每个副本只证明自己已经落盘；不能替稍后失败的其他副本作证。
    let commits = prepared_replicas
        .into_iter()
        .map(|replica| {
            let proof = CommitProof {
                schema: 2,
                job: job.id,
                revision: job.revision,
                bundle_sha256: manifest.bundle_sha256.clone(),
                required_domains: config.replica_min_ack,
                failure_domains: vec![replica.failure_domain.clone()],
                local_receipt: local_receipt.clone(),
            };
            (replica, proof)
        })
        .collect::<Vec<_>>();
    let committed = join_all(
        commits
            .iter()
            .map(|(replica, proof)| async { commit_replica(replica, &manifest, proof).await }),
    )
    .await;
    let mut acknowledgements = Vec::new();
    for result in committed {
        match result {
            Ok(name) => acknowledgements.push(name),
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    if acknowledgements.len() < required_remote {
        bail!(
            "state durability quorum not met while committing: local + {} replicas/{} required; {}",
            acknowledgements.len(),
            config.replica_min_ack,
            errors.join("; ")
        );
    }
    if !errors.is_empty() {
        eprintln!("sshpool: state replica warnings: {}", errors.join("; "));
    }
    Ok(acknowledgements)
}

/// 启动时按状态版本和副本 quorum 恢复；旧本地目录保留在备份区，不直接覆盖。
pub async fn restore_missing(config: &Config, home: &Path) -> Result<Vec<Uuid>> {
    if config.replicas.is_empty() || config.replica_min_ack == 0 {
        return Ok(Vec::new());
    }
    let jobs = home.join("jobs");
    fs::create_dir_all(&jobs)?;
    let stage = home
        .join("replica-stage")
        .join(format!("restore-run-{}", Uuid::new_v4()));
    fs::create_dir_all(&stage)?;
    let limit =
        (config.max_upload_mib + config.max_artifact_mib + config.max_log_mib + 16) * 1048576;
    let mut healthy = 0;
    let mut failures = Vec::new();
    let mut unreadable_jobs = BTreeSet::<Uuid>::new();
    let mut candidates = BTreeMap::<Uuid, Vec<ReplicaJob>>::new();
    let mut commit_marks = BTreeMap::<Uuid, BTreeMap<u64, BTreeSet<String>>>::new();
    for replica in config.replicas.iter().filter(|replica| replica.enabled) {
        let ids = match list(replica).await {
            Ok(ids) => {
                healthy += 1;
                ids
            }
            Err(error) => {
                eprintln!("sshpool: cannot list replica {}: {error:#}", replica.name);
                failures.push(format!("{}: {error:#}", replica.name));
                continue;
            }
        };
        for id in ids {
            let fetched =
                match fetch_candidates(&stage, replica, id, limit, config.replica_min_ack).await {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!(
                            "sshpool: cannot read {id} from replica {}: {error:#}",
                            replica.name
                        );
                        failures.push(format!("{}:{id}: {error:#}", replica.name));
                        unreadable_jobs.insert(id);
                        continue;
                    }
                };
            for revision in fetched.committed {
                commit_marks
                    .entry(id)
                    .or_default()
                    .entry(revision)
                    .or_default()
                    .insert(replica.failure_domain.clone());
            }
            if !fetched.errors.is_empty() {
                eprintln!(
                    "sshpool: unreadable published history for {id} on {}: {}; another verified copy must cover the same published revision",
                    replica.name,
                    fetched.errors.join("; ")
                );
            }
            for candidate in fetched.values {
                candidates.entry(id).or_default().push(candidate);
            }
        }
    }
    if healthy == 0 && !local_job_ids(home)?.is_empty() && !failures.is_empty() {
        eprintln!(
            "sshpool: all remote replicas unavailable; accepting new commits requires the configured quorum"
        );
    }
    let result = restore_candidates(RestoreCandidates {
        config,
        home,
        stage: &stage,
        limit,
        remote_healthy: healthy,
        candidates: &candidates,
        commit_marks: &commit_marks,
        unreadable_jobs: &unreadable_jobs,
    })
    .await;
    let _ = fs::remove_dir_all(&stage);
    result
}

/// 恢复所需的只读输入；集中传递可让恢复入口只展开一次状态依赖。
struct RestoreCandidates<'a> {
    config: &'a Config,
    home: &'a Path,
    stage: &'a Path,
    limit: u64,
    remote_healthy: usize,
    candidates: &'a BTreeMap<Uuid, Vec<ReplicaJob>>,
    commit_marks: &'a BTreeMap<Uuid, BTreeMap<u64, BTreeSet<String>>>,
    unreadable_jobs: &'a BTreeSet<Uuid>,
}

async fn restore_candidates(input: RestoreCandidates<'_>) -> Result<Vec<Uuid>> {
    let RestoreCandidates {
        config,
        home,
        stage,
        limit,
        remote_healthy,
        candidates,
        commit_marks,
        unreadable_jobs,
    } = input;
    let local_ids = local_job_ids(home)?;
    ensure_startup_quorum(config, remote_healthy)?;
    let mut restored = Vec::new();
    for (id, copies) in candidates {
        let local = load_local_job(home, *id, limit)?;
        let minimum_remote = config.replica_min_ack.saturating_sub(1);
        let highest_published = commit_marks
            .get(id)
            .and_then(|revisions| {
                revisions
                    .iter()
                    .rev()
                    .find(|(_, domains)| domains.len() >= minimum_remote)
                    .map(|(revision, _)| *revision)
            })
            .unwrap_or(0);
        let selected = select_quorum(
            copies,
            *id,
            minimum_remote,
            config.replica_min_ack,
            highest_published,
        )?;
        let local_acknowledged = match &local {
            Some(local) => local_acknowledges(home, *id, local, selected)?,
            None => false,
        };
        match local {
            Some(_) if !local_acknowledged => {
                // 完整远端 quorum 才是权威状态；本地不确定目录只移入备份区。
                persist_selected_receipt(home, selected)?;
                install_selected(home, *id, &selected.bundle, limit)?;
                restored.push(*id);
            }
            Some(local) if selected.job.revision > local.job.revision => {
                // 本地先落盘回执、远端后提交；控制面掉电后可完成本地发布。
                persist_selected_receipt(home, selected)?;
                install_selected(home, *id, &selected.bundle, limit)?;
                restored.push(*id);
            }
            Some(local) if selected.job.revision == local.job.revision => {
                ensure!(
                    same_job_state(&local.job, &selected.job)?,
                    "local job {id} differs from quorum state at revision {}",
                    local.job.revision
                );
                if let Some(proof) = &selected.proof {
                    ensure!(
                        local.bundle_sha256 == proof.bundle_sha256,
                        "local job {id} bundle differs from quorum state at revision {}",
                        local.job.revision
                    );
                    ensure!(
                        local.local_receipt.as_ref() == Some(&proof.local_receipt),
                        "local job {id} lacks the durable receipt referenced by quorum state"
                    );
                }
            }
            Some(_) => {
                // 更高的本地目录没有回执证明时不能自动提升。
                persist_selected_receipt(home, selected)?;
                install_selected(home, *id, &selected.bundle, limit)?;
                restored.push(*id);
            }
            None => {
                persist_selected_receipt(home, selected)?;
                install_selected(home, *id, &selected.bundle, limit)?;
                restored.push(*id);
            }
        }
    }
    for id in &local_ids {
        if candidates.contains_key(id) {
            continue;
        }
        ensure!(
            !unreadable_jobs.contains(id),
            "live replica has unreadable history for local job {id}; refusing to overwrite or assume durability"
        );
        // 没有远端历史的本地目录可能是失败诊断或升级前数据，启动不能自动授予 quorum。
        bail!(
            "local job {id} has no durable replica history; adopt it explicitly before quorum recovery"
        );
    }
    for id in unreadable_jobs {
        // 只存在候选清单、从未在任何故障域提交的孤立任务不能被恢复，
        // 但它也不拥有已发布版本。它不能让无关任务或整个控制面拒绝启动。
        let matters = local_ids.contains(id)
            || commit_marks
                .get(id)
                .is_some_and(|versions| !versions.is_empty());
        ensure!(
            !matters || candidates.contains_key(id),
            "live replica has unreadable published history for {id}; no independently verified quorum is available"
        );
        if !matters {
            eprintln!(
                "sshpool: ignored uncommitted candidate history for {id} with no published quorum"
            );
        }
    }
    // 阶段目录只暂存已下载对象；不让遗留临时目录进入正式恢复结果。
    let _ = stage;
    Ok(restored)
}

/// 启动机始终是当前本地故障域；本地目录丢失时，远端提交证明仍携带当时的本地回执。
/// 具体任务必须再由 `select_quorum` 核对证明和副本数，不能仅凭恢复机目录存在。
fn ensure_startup_quorum(config: &Config, remote_healthy: usize) -> Result<()> {
    let live = remote_healthy + 1;
    ensure!(
        live >= config.replica_min_ack,
        "state durability quorum not met at startup: {} live fault domains/{} required; refusing to start",
        live,
        config.replica_min_ack
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct ReplicaJob {
    replica: String,
    failure_domain: String,
    job: Job,
    bundle: PathBuf,
    proof: Option<CommitProof>,
}

/// 本地任务和本次生成的归档摘要；装载时同时确认源码和已声明产物完整。
struct LocalJob {
    job: Job,
    bundle_sha256: String,
    local_receipt: Option<LocalReceipt>,
}

struct FetchedCandidates {
    values: Vec<ReplicaJob>,
    committed: Vec<u64>,
    errors: Vec<String>,
}

async fn fetch_candidates(
    stage: &Path,
    replica: &Replica,
    id: Uuid,
    limit: u64,
    required_domains: usize,
) -> Result<FetchedCandidates> {
    let (revisions, committed, legacy) = versions(replica, id).await?;
    let mut values = Vec::new();
    let mut errors = Vec::new();
    let has_history = !revisions.is_empty();
    for revision in revisions {
        let download = stage.join(format!(
            "fetch-{}-{}-{}-{}.tar",
            replica.name,
            id,
            revision,
            Uuid::new_v4()
        ));
        let result = async {
            let proof = download_version(
                replica,
                id,
                Some(revision),
                &download,
                limit,
                required_domains,
            )
            .await?
            .context("revision has no durable commit proof")?;
            let job = inspect_bundle(&download, id, limit)?;
            ensure!(
                job.revision == revision,
                "replica revision manifest disagrees with job"
            );
            Ok::<_, anyhow::Error>(ReplicaJob {
                replica: replica.name.clone(),
                failure_domain: replica.failure_domain.clone(),
                job,
                bundle: download.clone(),
                proof: Some(proof),
            })
        }
        .await;
        match result {
            Ok(value) => values.push(value),
            Err(error) => errors.push(format!("revision {revision}: {error:#}")),
        }
    }
    if legacy {
        let download = stage.join(format!(
            "fetch-{}-{}-legacy-{}.tar",
            replica.name,
            id,
            Uuid::new_v4()
        ));
        let result = async {
            download_version(replica, id, None, &download, limit, required_domains).await?;
            let job = inspect_bundle(&download, id, limit)?;
            Ok::<_, anyhow::Error>(ReplicaJob {
                replica: replica.name.clone(),
                failure_domain: replica.failure_domain.clone(),
                job,
                bundle: download.clone(),
                proof: None,
            })
        }
        .await;
        match result {
            Ok(value) => values.push(value),
            Err(error) => errors.push(format!("legacy: {error:#}")),
        }
    }
    if values.is_empty() && (has_history || legacy) {
        bail!("replica has no readable versions: {}", errors.join("; "));
    }
    Ok(FetchedCandidates {
        values,
        committed,
        errors,
    })
}

fn inspect_bundle(bundle: &Path, id: Uuid, limit: u64) -> Result<Job> {
    let inspect_home = bundle.with_extension("inspect");
    fs::create_dir(&inspect_home)?;
    let result = install_bundle(&inspect_home, id, bundle, limit).and_then(|directory| {
        serde_json::from_slice(&fs::read(directory.join("job.json"))?).map_err(anyhow::Error::from)
    });
    let _ = fs::remove_dir_all(inspect_home);
    result
}

fn local_job_ids(home: &Path) -> Result<Vec<Uuid>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(home.join("jobs"))? {
        let entry = entry?;
        if let Ok(id) = Uuid::parse_str(&entry.file_name().to_string_lossy()) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

fn load_local_job(home: &Path, id: Uuid, limit: u64) -> Result<Option<LocalJob>> {
    let directory = home.join("jobs").join(id.to_string());
    if !directory.exists() {
        return Ok(None);
    }
    let job: Job = serde_json::from_slice(&fs::read(directory.join("job.json"))?)?;
    ensure!(job.id == id, "local job identity mismatch");
    let bundle = home
        .join("replica-stage")
        .join(format!("local-{}-{}.tar", id, Uuid::new_v4()));
    let manifest = create_bundle(&directory, &bundle, limit)?;
    let _ = fs::remove_file(bundle);
    Ok(Some(LocalJob {
        local_receipt: read_local_receipt(home, id, job.revision)?
            .filter(|receipt| receipt.bundle_sha256 == manifest.bundle_sha256),
        job,
        bundle_sha256: manifest.bundle_sha256,
    }))
}

fn local_acknowledges(
    home: &Path,
    id: Uuid,
    local: &LocalJob,
    selected: &ReplicaJob,
) -> Result<bool> {
    let Some(proof) = &selected.proof else {
        return Ok(local.job.revision == 0);
    };
    // job.json 可以在远端提交后才发布；独立回执先落盘即可证明本地已参与本次提交。
    Ok(read_local_receipt(home, id, selected.job.revision)?.as_ref() == Some(&proof.local_receipt))
}

fn persist_selected_receipt(home: &Path, selected: &ReplicaJob) -> Result<()> {
    if let Some(proof) = &selected.proof {
        persist_local_receipt(home, &proof.local_receipt)?;
    }
    Ok(())
}

fn select_quorum(
    copies: &[ReplicaJob],
    id: Uuid,
    minimum: usize,
    required_domains: usize,
    minimum_revision: u64,
) -> Result<&ReplicaJob> {
    let mut by_revision = BTreeMap::<u64, Vec<&ReplicaJob>>::new();
    for copy in copies {
        let committed = match &copy.proof {
            Some(proof) => validate_commit_proof(
                proof,
                id,
                copy.job.revision,
                required_domains,
                &copy.failure_domain,
            )
            .is_ok(),
            None => copy.job.revision == 0,
        };
        if committed {
            by_revision.entry(copy.job.revision).or_default().push(copy);
        }
    }
    for (revision, exact) in by_revision.iter().rev() {
        let unique = exact
            .iter()
            .map(|copy| copy.failure_domain.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() < minimum {
            continue;
        }
        ensure!(
            *revision >= minimum_revision,
            "published revision {minimum_revision} for {id} is unreadable; refusing fallback to revision {revision}"
        );
        let first = exact[0];
        for other in exact.iter().skip(1) {
            let same_bundle = first.proof.as_ref().map(|proof| &proof.bundle_sha256)
                == other.proof.as_ref().map(|proof| &proof.bundle_sha256);
            let same_receipt = first.proof.as_ref().map(|proof| &proof.local_receipt)
                == other.proof.as_ref().map(|proof| &proof.local_receipt);
            ensure!(
                same_job_state(&first.job, &other.job)? && same_bundle && same_receipt,
                "replica conflict for {id} revision {revision}: {} vs {}",
                first.replica,
                other.replica
            );
        }
        return Ok(first);
    }
    bail!(
        "no durability quorum has job {id}; highest observed revision is {}",
        copies
            .iter()
            .map(|copy| copy.job.revision)
            .max()
            .unwrap_or(0)
    )
}

fn validate_commit_proof(
    proof: &CommitProof,
    id: Uuid,
    revision: u64,
    minimum_domains: usize,
    replica_domain: &str,
) -> Result<()> {
    ensure!(
        proof.schema == 2 && proof.job == id && proof.revision == revision,
        "commit proof identity mismatch"
    );
    ensure!(
        proof.required_domains >= minimum_domains && proof.failure_domains.len() == 1,
        "commit proof does not establish the configured quorum"
    );
    ensure!(
        proof.bundle_sha256.len() == 64
            && proof
                .bundle_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "commit proof has an invalid bundle digest"
    );
    ensure!(
        proof.local_receipt.schema == 1
            && proof.local_receipt.job == id
            && proof.local_receipt.revision == revision
            && proof.local_receipt.bundle_sha256 == proof.bundle_sha256
            && proof.local_receipt.required_domains == proof.required_domains,
        "commit proof has an invalid local receipt"
    );
    ensure!(
        proof
            .failure_domains
            .iter()
            .all(|domain| !domain.is_empty() && domain.len() <= 128),
        "commit proof has an invalid failure domain"
    );
    let unique = proof
        .failure_domains
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        unique.len() == proof.failure_domains.len(),
        "commit proof repeats a failure domain"
    );
    ensure!(
        proof
            .failure_domains
            .iter()
            .any(|domain| domain == replica_domain),
        "commit proof omits the recovering failure domain"
    );
    Ok(())
}

fn same_job_state(left: &Job, right: &Job) -> Result<bool> {
    Ok(serde_json::to_vec(left)? == serde_json::to_vec(right)?)
}

fn install_selected(home: &Path, id: Uuid, bundle: &Path, limit: u64) -> Result<PathBuf> {
    let local = home.join("jobs").join(id.to_string());
    let backup_root = home.join("backups").join("jobs");
    fs::create_dir_all(&backup_root)?;
    let backup = backup_root.join(format!("{id}-{}-{}", now(), Uuid::new_v4()));
    let moved = local.exists();
    if moved {
        fs::rename(&local, &backup)?;
        File::open(home.join("jobs"))?.sync_all()?;
        File::open(&backup_root)?.sync_all()?;
    }
    match install_bundle(home, id, bundle, limit) {
        Ok(directory) => Ok(directory),
        Err(error) => {
            if moved {
                let _ = fs::rename(&backup, &local);
                let _ = File::open(home.join("jobs")).and_then(|file| file.sync_all());
            }
            Err(error)
        }
    }
}

/// 旧任务缺少源码摘要时，先验证归档并写入副本 quorum，再发布本地元数据修订。
pub async fn adopt_legacy_job(config: &Config, home: &Path, id: Uuid) -> Result<Job> {
    let directory = home.join("jobs").join(id.to_string());
    let mut job: Job = serde_json::from_slice(&fs::read(directory.join("job.json"))?)?;
    ensure!(job.id == id, "job identity mismatch");
    let source = directory.join("source.tar");
    let limit = config.max_upload_mib * 1048576;
    archive::validate(&source, limit, None)?;
    let actual = archive::sha256_file(&source)?;
    if let Some(expected) = &job.source_sha256 {
        ensure!(
            expected == &actual,
            "existing source digest does not match archive"
        );
        sync_job_state(config, home, &job).await?;
        return Ok(job);
    }
    let backup_root = home.join("backups").join("jobs");
    fs::create_dir_all(&backup_root)?;
    let backup = backup_root.join(format!("{id}-legacy-{}-{}.json", now(), Uuid::new_v4()));
    fs::copy(directory.join("job.json"), &backup)?;
    File::open(&backup)?.sync_all()?;
    File::open(&backup_root)?.sync_all()?;
    job.source_sha256 = Some(actual);
    job.revision = crate::state::reserve_revision(home, id, job.revision)?;
    sync_job_state(config, home, &job).await?;
    crate::config::atomic_write(
        &directory.join("job.json"),
        &serde_json::to_vec_pretty(&job)?,
    )?;
    Ok(job)
}

/// 从显式指定的副本恢复一个本地不存在的任务；已有任务绝不覆盖。
pub async fn restore_from(
    config: &Config,
    home: &Path,
    replica: &Replica,
    id: Uuid,
) -> Result<PathBuf> {
    ensure!(
        config.replica_min_ack == 2,
        "single-replica restore is only valid with quorum 2; use automatic startup recovery for higher quorums"
    );
    let stage = home.join("replica-stage");
    fs::create_dir_all(&stage)?;
    let download = stage.join(format!("restore-{id}-{}.tar", Uuid::new_v4()));
    let limit =
        (config.max_upload_mib + config.max_artifact_mib + config.max_log_mib + 16) * 1048576;
    let result = async {
        let (revisions, _, legacy) = versions(replica, id).await?;
        let revision = revisions.into_iter().max();
        ensure!(
            revision.is_some() || legacy,
            "replica has no restorable version"
        );
        download_version(
            replica,
            id,
            revision,
            &download,
            limit,
            config.replica_min_ack,
        )
        .await?;
        install_bundle(home, id, &download, limit)
    }
    .await;
    let _ = fs::remove_file(download);
    result
}

#[cfg(test)]
mod tests {
    use super::{
        CommitProof, LocalReceipt, ReplicaJob, RestoreCandidates, create_bundle,
        ensure_startup_quorum, install_bundle, restore_candidates, select_quorum, sync_job_state,
    };
    use crate::model::{Job, Phase};
    use anyhow::Result;
    use std::fs;

    fn make_job(home: &std::path::Path) -> Result<Job> {
        let id = uuid::Uuid::new_v4();
        let directory = home.join("jobs").join(id.to_string());
        fs::create_dir_all(&directory)?;
        let source = directory.join("source.tar");
        let mut archive = tar::Builder::new(fs::File::create(&source)?);
        archive.finish()?;
        Ok(Job {
            id,
            revision: 1,
            build: Default::default(),
            phase: Phase::Queued,
            created_at: 1,
            finished_at: None,
            attempts: Vec::new(),
            exit_code: None,
            message: None,
            artifacts: false,
            cancel_requested: false,
            cleanup_confirmed: false,
            queue_deadline: None,
            source_sha256: Some(crate::archive::sha256_file(&source)?),
            owner: None,
        })
    }

    #[test]
    fn bundle_round_trip_preserves_a_valid_job() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source_home = root.path().join("source");
        let destination_home = root.path().join("destination");
        fs::create_dir_all(&source_home)?;
        let job = make_job(&source_home)?;
        let job_dir = source_home.join("jobs").join(job.id.to_string());
        fs::write(job_dir.join("job.json"), serde_json::to_vec(&job)?)?;
        let bundle = root.path().join("bundle.tar");
        let manifest = create_bundle(&job_dir, &bundle, 1048576)?;
        assert_eq!(manifest.job, job.id);
        let restored = install_bundle(&destination_home, job.id, &bundle, 1048576)?;
        assert!(restored.join("job.json").is_file());
        assert!(restored.join("source.tar").is_file());
        Ok(())
    }

    #[tokio::test]
    async fn candidate_state_is_bundled_without_overwriting_the_local_job() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(&home)?;
        let job = make_job(&home)?;
        let job_dir = home.join("jobs").join(job.id.to_string());
        fs::write(job_dir.join("job.json"), serde_json::to_vec(&job)?)?;
        let local_before = fs::read(job_dir.join("job.json"))?;
        let candidate = Job {
            phase: Phase::Interrupted,
            message: Some("candidate only".into()),
            finished_at: Some(2),
            ..job.clone()
        };
        let config = crate::config::Config::default();
        sync_job_state(&config, &home, &candidate).await?;
        assert_eq!(fs::read(job_dir.join("job.json"))?, local_before);
        Ok(())
    }

    fn replica_job(job: Job, replica: &str) -> ReplicaJob {
        let proof = CommitProof {
            schema: 2,
            job: job.id,
            revision: job.revision,
            bundle_sha256: "a".repeat(64),
            required_domains: 2,
            failure_domains: vec![replica.into()],
            local_receipt: LocalReceipt {
                schema: 1,
                job: job.id,
                revision: job.revision,
                bundle_sha256: "a".repeat(64),
                required_domains: 2,
            },
        };
        ReplicaJob {
            replica: replica.into(),
            failure_domain: replica.into(),
            job,
            bundle: std::path::PathBuf::from("not-read-by-selection"),
            proof: Some(proof),
        }
    }

    #[test]
    fn recovery_requires_quorum_and_rejects_conflicting_equal_versions() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let first = replica_job(job.clone(), "first");
        assert!(select_quorum(std::slice::from_ref(&first), job.id, 2, 3, 0).is_err());
        let mut conflicting = job.clone();
        conflicting.message = Some("different state".into());
        let second = replica_job(conflicting, "second");
        assert!(
            select_quorum(&[first.clone(), second], job.id, 1, 2, 0)
                .unwrap_err()
                .to_string()
                .contains("replica conflict")
        );
        let newer = replica_job(
            Job {
                revision: 2,
                ..job.clone()
            },
            "second",
        );
        let third = replica_job(job.clone(), "third");
        let copies = [first, newer, third];
        // quorum 2 的每个有效副本都包含本地确认；更新的单副本已是可恢复提交。
        let selected = select_quorum(&copies, job.id, 1, 2, 2)?;
        assert_eq!(selected.job.revision, 2);
        assert_eq!(selected.replica, "second");
        Ok(())
    }

    #[test]
    fn unreadable_newer_published_revision_cannot_fall_back_to_an_older_quorum() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let first = replica_job(job.clone(), "first");
        let second = replica_job(job.clone(), "second");
        let error = select_quorum(&[first, second], job.id, 1, 2, 2).unwrap_err();
        assert!(error.to_string().contains("refusing fallback"));
        Ok(())
    }

    #[test]
    fn same_revision_with_different_bundle_digests_is_a_conflict() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let first = replica_job(job.clone(), "first");
        let mut second = replica_job(job.clone(), "second");
        if let Some(proof) = &mut second.proof {
            proof.bundle_sha256 = "b".repeat(64);
            proof.local_receipt.bundle_sha256 = "b".repeat(64);
        }
        let error = select_quorum(&[first, second], job.id, 2, 2, 0).unwrap_err();
        assert!(error.to_string().contains("replica conflict"));
        Ok(())
    }

    #[test]
    fn same_revision_with_different_receipts_is_a_conflict() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let first = replica_job(job.clone(), "first");
        let mut second = replica_job(job.clone(), "second");
        if let Some(proof) = &mut second.proof {
            proof.required_domains = 3;
            proof.local_receipt.required_domains = 3;
        }
        let error = select_quorum(&[first, second], job.id, 2, 2, 0).unwrap_err();
        assert!(error.to_string().contains("replica conflict"));
        Ok(())
    }

    #[test]
    fn quorum_three_requires_two_remote_commit_domains() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let mut first = replica_job(job.clone(), "first");
        let mut second = replica_job(job.clone(), "second");
        let mut third = replica_job(job.clone(), "third");
        for copy in [&mut first, &mut second, &mut third] {
            if let Some(proof) = &mut copy.proof {
                proof.required_domains = 3;
                proof.local_receipt.required_domains = 3;
            }
        }
        assert!(select_quorum(&[first.clone(), second.clone()], job.id, 3, 3, 0).is_err());
        let copies = [first, second, third];
        let selected = select_quorum(&copies, job.id, 3, 3, 0)?;
        assert_eq!(selected.replica, "first");
        Ok(())
    }

    #[test]
    fn a_candidate_without_commit_proof_is_not_recoverable() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let mut candidate = replica_job(job.clone(), "prepared-only");
        candidate.proof = None;
        assert!(select_quorum(&[candidate], job.id, 1, 2, 0).is_err());
        let mut legacy = replica_job(
            Job {
                revision: 0,
                ..job.clone()
            },
            "legacy",
        );
        legacy.proof = None;
        assert!(select_quorum(&[legacy], job.id, 1, 2, 0).is_ok());
        Ok(())
    }

    #[test]
    fn commit_proof_must_name_the_recovering_failure_domain() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let copy = replica_job(job.clone(), "lost-domain");
        let mut wrong_domain = copy.clone();
        if let Some(proof) = &mut wrong_domain.proof {
            proof.failure_domains = vec!["wrong-domain".into()];
        }
        assert!(select_quorum(&[wrong_domain], job.id, 1, 2, 0).is_err());
        let mut weaker = copy;
        if let Some(proof) = &mut weaker.proof {
            proof.required_domains = 1;
            proof.local_receipt.required_domains = 1;
        }
        assert!(select_quorum(&[weaker], job.id, 1, 2, 0).is_err());
        Ok(())
    }

    #[test]
    fn commit_proof_must_reference_the_exact_local_receipt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let copy = replica_job(job.clone(), "remote");
        let mut wrong = copy;
        if let Some(proof) = &mut wrong.proof {
            proof.local_receipt.bundle_sha256 = "b".repeat(64);
        }
        let error = select_quorum(&[wrong], job.id, 1, 2, 0).unwrap_err();
        assert!(error.to_string().contains("no durability quorum"));
        Ok(())
    }

    #[test]
    fn quorum_two_remote_receipt_recovers_after_local_state_is_lost() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let copy = replica_job(job.clone(), "surviving-remote");
        let selected = select_quorum(std::slice::from_ref(&copy), job.id, 1, 2, 0)?;
        assert_eq!(selected.proof.as_ref().unwrap().local_receipt.job, job.id);
        Ok(())
    }

    #[test]
    fn startup_requires_the_configured_number_of_distinct_live_domains() -> Result<()> {
        let two = crate::config::Config {
            replica_min_ack: 2,
            ..crate::config::Config::default()
        };
        assert!(ensure_startup_quorum(&two, 1).is_ok());
        assert!(ensure_startup_quorum(&two, 0).is_err());
        let three = crate::config::Config {
            replica_min_ack: 3,
            ..crate::config::Config::default()
        };
        let error = ensure_startup_quorum(&three, 1).unwrap_err();
        assert!(error.to_string().contains("refusing to start"));
        assert!(ensure_startup_quorum(&three, 2).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn unrelated_candidate_only_history_does_not_block_recovery() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let config = crate::config::Config {
            replica_min_ack: 2,
            ..crate::config::Config::default()
        };
        let unreadable = std::collections::BTreeSet::from([uuid::Uuid::new_v4()]);
        let restored = restore_candidates(RestoreCandidates {
            config: &config,
            home: &home,
            stage: root.path(),
            limit: 1048576,
            remote_healthy: 1,
            candidates: &std::collections::BTreeMap::new(),
            commit_marks: &std::collections::BTreeMap::new(),
            unreadable_jobs: &unreadable,
        })
        .await?;
        assert!(restored.is_empty());
        Ok(())
    }

    #[test]
    fn duplicate_replica_copies_do_not_satisfy_quorum() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let job = make_job(&home)?;
        let first = replica_job(job.clone(), "same-host");
        let duplicate = replica_job(job.clone(), "same-host");
        assert!(select_quorum(&[first, duplicate], job.id, 2, 2, 0).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn startup_checks_health_quorum_even_when_local_jobs_exist() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        make_job(&home)?;
        let config = crate::config::Config {
            replica_min_ack: 2,
            ..crate::config::Config::default()
        };
        let candidates = std::collections::BTreeMap::new();
        let error = restore_candidates(RestoreCandidates {
            config: &config,
            home: &home,
            stage: root.path(),
            limit: 1048576,
            remote_healthy: 0,
            candidates: &candidates,
            commit_marks: &std::collections::BTreeMap::new(),
            unreadable_jobs: &std::collections::BTreeSet::new(),
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("refusing to start"));
        Ok(())
    }

    #[test]
    fn restore_refuses_to_overwrite_an_existing_job() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        fs::create_dir_all(home.join("jobs"))?;
        let id = uuid::Uuid::new_v4();
        fs::create_dir(home.join("jobs").join(id.to_string()))?;
        let bundle = root.path().join("missing.tar");
        assert!(install_bundle(&home, id, &bundle, 1048576).is_err());
        Ok(())
    }
}
