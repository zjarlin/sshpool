//! 短期访问凭据：签发、撤销、校验，以及**按主体限制权限**。
//!
//! 主 token 仍是控制面的根凭据；这里的凭据只用于把工作台或一次性脚本接入，
//! 必须能设置到期时间并即时撤销。为了撤销立即生效，校验时读取凭据文件，
//! 不做进程内缓存；文件很小，请求频率也低（默认一次探测 15s）。
//!
//! 权限是显式授予的：不写 `scopes` 的凭据只能读，不能提交、取消或改节点状态。
//! 旧版本签发的凭据没有 `scopes` 字段，按最小权限降级为只读 —— 这是权限收紧，
//! 需要更大权限请重新签发；这里刻意不做「缺字段等于全部权限」的兼容。
//!
//! 失败关闭：凭据文件存在但无法解析时拒绝全部动态凭据，而不是退回「没有凭据」。

use crate::{config, model::now};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const SCHEMA: u32 = 1;
/// 明文 token 只在校验时短暂存在；前缀让运维一眼能看出这是 SSH Pool 凭据。
pub const PREFIX: &str = "spt";
/// 上限 90 天：足够一次迭代或一台借用机器，又不至于变成第二把长期密钥。
pub const MAX_TTL_SECS: u64 = 90 * 86_400;
/// 根 token 在任务属主里写作 `root`；凭据不能用这个名字，否则两者无法区分。
pub const RESERVED_SUBJECT: &str = "root";

/// 一条短期凭据被允许做的事。权限只按白名单授予，不认识的字符串一律拒绝。
///
/// `read` 是任何凭据都有的：没有它连自己的任务列表都看不到，凭据就没有意义。
/// `submit` 提交任务（会占用 Worker），`cancel` 请求停止任务，
/// `admin` 改节点状态、在线核对隔离、查询他人访问审计。
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Read,
    Submit,
    Cancel,
    Admin,
}

impl Scope {
    pub const ALL: [Scope; 4] = [Scope::Read, Scope::Submit, Scope::Cancel, Scope::Admin];
    /// 解析命令行/配置里的一词；大小写不敏感，其余拼写一律拒绝。
    pub fn parse(word: &str) -> Result<Self> {
        match word.trim().to_ascii_lowercase().as_str() {
            "read" => Ok(Self::Read),
            "submit" => Ok(Self::Submit),
            "cancel" => Ok(Self::Cancel),
            "admin" => Ok(Self::Admin),
            _ => {
                anyhow::bail!("unknown scope {word:?}; expected one of read, submit, cancel, admin")
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Submit => "submit",
            Self::Cancel => "cancel",
            Self::Admin => "admin",
        }
    }
}

/// 旧记录缺 `scopes` 时的权限：只读。权限收紧宁可让旧脚本报 403，也不能让它继续写。
pub fn legacy_scopes() -> Vec<Scope> {
    vec![Scope::Read]
}

/// 磁盘上的凭据记录；只保存摘要，明文永远不落盘。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: Uuid,
    /// 审计用的主体名；不参与鉴权判断。
    pub subject: String,
    pub token_sha256: String,
    /// 签发时显式授予的权限；旧记录没有该字段时按 `legacy_scopes()` 降级为只读。
    #[serde(default = "legacy_scopes")]
    pub scopes: Vec<Scope>,
    pub created_at: u64,
    pub expires_at: u64,
    /// 撤销时间一经写入不会清除，避免「撤销后再恢复」被误当成新凭据。
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

impl Credential {
    /// 是否仍然可用；过期与撤销都算失效，二者不互相替代。
    pub fn active(&self, at: u64) -> bool {
        self.revoked_at.is_none() && at < self.expires_at
    }
}

/// 对外展示的凭据摘要：不含明文，也不含可被离线比对的摘要。
///
/// 这里刻意不带 `active`：是否仍可用依赖调用方的时钟，把结论塞进结构体
/// 只会让「过期未撤销」看起来仍然有效。
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub id: Uuid,
    pub subject: String,
    /// 授予的权限，按 `Scope` 的固定顺序排列，便于人读与脚本比较。
    pub scopes: Vec<Scope>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

impl From<&Credential> for Summary {
    fn from(credential: &Credential) -> Self {
        Self {
            id: credential.id,
            subject: credential.subject.clone(),
            scopes: sorted_scopes(&credential.scopes),
            created_at: credential.created_at,
            expires_at: credential.expires_at,
            revoked_at: credential.revoked_at,
        }
    }
}

/// 一次通过的鉴权结果；`id` 与 `expires_at` 供审计使用，不参与判断。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: Uuid,
    pub subject: String,
    /// 该凭据能做的事；`Principal` 用它做授权判断。
    pub scopes: Vec<Scope>,
    pub expires_at: u64,
}

impl Grant {
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Store {
    pub schema: u32,
    pub credentials: Vec<Credential>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            credentials: Vec::new(),
        }
    }
}

pub fn path(home: &Path) -> PathBuf {
    home.join("credentials.json")
}

/// 读取凭据库；文件不存在等于「从未签发过」，主 token 仍然可用。
///
/// 结构校验在这里一次做完：凡是能让 `verify` 做出错误判断的记录都拒绝整个文件。
fn load(home: &Path) -> Result<Store> {
    let path = path(home);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Store::default()),
        Err(error) => return Err(error.into()),
    };
    let store: Store = serde_json::from_slice(&bytes)
        .with_context(|| format!("credential store is unreadable: {}", path.display()))?;
    ensure!(
        store.schema == SCHEMA,
        "unsupported credential store schema {}",
        store.schema
    );
    let mut ids = HashSet::new();
    for credential in &store.credentials {
        ensure!(
            credential.token_sha256.len() == 64
                && credential
                    .token_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "credential store contains an invalid digest"
        );
        validate_subject(&credential.subject)
            .context("credential store contains an invalid subject")?;
        // 权限是白名单枚举，serde 已拒绝未知值；这里拒绝「声明了但没 read」这种
        // 自相矛盾的记录，而不是悄悄补一个权限进去。
        ensure!(
            credential.scopes.contains(&Scope::Read),
            "credential store contains a credential without read access"
        );
        ensure!(
            credential.expires_at > credential.created_at,
            "credential store contains an invalid lifetime"
        );
        if let Some(revoked_at) = credential.revoked_at {
            ensure!(
                revoked_at >= credential.created_at,
                "credential store revokes before it was issued"
            );
        }
        ensure!(
            ids.insert(credential.id),
            "credential store contains a duplicate identifier"
        );
    }
    Ok(store)
}

/// 去重并按固定顺序排列，保证同一组权限的展示与比较稳定。
fn sorted_scopes(scopes: &[Scope]) -> Vec<Scope> {
    let mut values = scopes.to_vec();
    values.sort();
    values.dedup();
    values
}

/// 权限列表的规范形式：`read` 必定存在，其余按固定顺序，空列表按旧记录降级。
fn normalize_scopes(scopes: &[Scope]) -> Vec<Scope> {
    let mut values = sorted_scopes(scopes);
    if values.is_empty() {
        return legacy_scopes();
    }
    if !values.contains(&Scope::Read) {
        values.insert(0, Scope::Read);
    }
    values
}

fn save(home: &Path, store: &Store) -> Result<()> {
    config::atomic_write(&path(home), &serde_json::to_vec_pretty(store)?)
}

/// 独占写锁：签发与撤销都是「读—改—写」，没有锁时两个并发签发会丢一条记录。
///
/// 用独立锁文件而不是锁 `credentials.json`：`atomic_write` 每次都换 inode，
/// 锁旧 inode 等于没锁。
struct WriteLock(fs::File);

impl WriteLock {
    fn acquire(home: &Path) -> Result<Self> {
        use fs2::FileExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(home.join("credentials.lock"))?;
        // 等价于阻塞式 `lock_exclusive`，但失败时给出可诊断的错误而不是 panic。
        file.lock_exclusive()
            .context("cannot lock the credential store for writing")?;
        Ok(Self(file))
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

fn digest(token: &str) -> String {
    let bytes = Sha256::digest(token.as_bytes());
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 恒时比较摘要；不能用 `==` 提前返回，否则可被用来枚举凭据。
fn digest_matches(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn validate_subject(subject: &str) -> Result<()> {
    ensure!(
        !subject.trim().is_empty()
            && subject.len() <= 128
            && !subject.chars().any(char::is_control),
        "subject must be 1..128 printable characters"
    );
    // `root` 是根 token 的任务属主名。允许凭据占用它，等于让一份借出的只读凭据
    // 被当成运维提交的任务的所有者，所以这里是硬冲突而不是命名建议。
    ensure!(
        subject != RESERVED_SUBJECT,
        "subject {RESERVED_SUBJECT:?} is reserved for the root token; choose another name"
    );
    Ok(())
}

/// 签发一次性凭据；明文只通过返回值交给调用方，绝不写回磁盘。
pub fn issue(
    home: &Path,
    subject: &str,
    scopes: &[Scope],
    ttl_secs: u64,
    issued_at: u64,
) -> Result<(Summary, String)> {
    validate_subject(subject)?;
    ensure!(
        !scopes.is_empty(),
        "a credential needs at least one scope; pass read explicitly"
    );
    ensure!(ttl_secs > 0, "credential lifetime must be positive");
    ensure!(
        ttl_secs <= MAX_TTL_SECS,
        "credential lifetime must not exceed 90 days"
    );
    let _lock = WriteLock::acquire(home)?;
    let mut store = load(home)?;
    let id = Uuid::new_v4();
    // 两个 UUIDv4 拼接成 256 位随机量：不依赖系统熵源之外的任何东西，也不引用额外 crate。
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let token = format!("{PREFIX}_{}_{secret}", id.simple());
    let credential = Credential {
        id,
        subject: subject.to_string(),
        token_sha256: digest(&token),
        scopes: normalize_scopes(scopes),
        created_at: issued_at,
        expires_at: issued_at + ttl_secs,
        revoked_at: None,
    };
    store.credentials.push(credential.clone());
    save(home, &store)?;
    Ok((Summary::from(&credential), token))
}

/// 撤销一条凭据；重复撤销保留最早的撤销时间，因此可以安全重试。
pub fn revoke(home: &Path, id: Uuid, revoked_at: u64) -> Result<Summary> {
    let _lock = WriteLock::acquire(home)?;
    let mut store = load(home)?;
    let credential = store
        .credentials
        .iter_mut()
        .find(|credential| credential.id == id)
        .with_context(|| format!("unknown credential {id}"))?;
    ensure!(
        revoked_at >= credential.created_at,
        "a credential cannot be revoked before it was issued"
    );
    credential.revoked_at.get_or_insert(revoked_at);
    let summary = Summary::from(&*credential);
    save(home, &store)?;
    Ok(summary)
}

/// 按标识查找；用于 `issue` 之后的核对与 `revoke` 的友好报错。
pub fn find(home: &Path, id: Uuid) -> Result<Option<Summary>> {
    Ok(load(home)?
        .credentials
        .iter()
        .find(|credential| credential.id == id)
        .map(Summary::from))
}

/// 列出全部凭据（不含明文和摘要），供运维核对到期与撤销状态。
pub fn list(home: &Path) -> Result<Vec<Credential>> {
    Ok(load(home)?.credentials)
}

/// 校验动态凭据；返回主体信息。主 token 由调用方单独处理。
///
/// 先看前缀再看存储：主 token 和任意伪造串都不会触发磁盘读取。
/// 凭据文件损坏时返回错误，让调用方拒绝请求，而不是当作「没有动态凭据」放行。
pub fn verify(home: &Path, token: &str, at: u64) -> Result<Option<Grant>> {
    let prefix = format!("{PREFIX}_");
    let Some(rest) = token.strip_prefix(&prefix) else {
        return Ok(None);
    };
    // 解析失败只说明这不是本模块签发的 token，不泄露存储内容。
    let Some((id, secret)) = rest.split_once('_') else {
        return Ok(None);
    };
    if secret.len() != 64
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Ok(None);
    }
    let Ok(id) = Uuid::parse_str(id) else {
        return Ok(None);
    };
    let store = load(home)?;
    let Some(credential) = store
        .credentials
        .iter()
        .find(|credential| credential.id == id)
    else {
        return Ok(None);
    };
    // 先比较摘要再看状态，避免通过响应时间区分「标识不存在」与「摘要不匹配」。
    if !digest_matches(&credential.token_sha256, &digest(token)) {
        return Ok(None);
    }
    if !credential.active(at) {
        return Ok(None);
    }
    Ok(Some(Grant {
        id: credential.id,
        subject: credential.subject.clone(),
        scopes: sorted_scopes(&credential.scopes),
        expires_at: credential.expires_at,
    }))
}

/// 清理「已经过期且已撤销」的记录；`apply` 之前只统计。
///
/// 只删这两项同时成立的记录：仍有效的凭据可以继续用，撤销后未过期的凭据
/// 还要继续挡住旧 token，提前删除会让撤销失效。
pub fn prune(home: &Path, at: u64, apply: bool) -> Result<Vec<Summary>> {
    let _lock = WriteLock::acquire(home)?;
    let mut store = load(home)?;
    let mut removed = Vec::new();
    store.credentials.retain(|credential| {
        let stale = at >= credential.expires_at && credential.revoked_at.is_some();
        if stale {
            removed.push(Summary::from(credential));
        }
        !stale
    });
    if apply && !removed.is_empty() {
        save(home, &store)?;
    }
    Ok(removed)
}

/// 供测试与报告使用的当前时间。
pub fn timestamp() -> u64 {
    now()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp home")
    }

    #[test]
    fn issued_tokens_verify_and_never_store_the_secret() {
        let root = home();
        let (summary, token) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        assert_eq!(summary.subject, "workbench");
        assert_eq!(summary.created_at, 1_000);
        assert_eq!(summary.expires_at, 4_600);
        assert!(token.starts_with("spt_"));
        let stored = fs::read_to_string(path(root.path())).unwrap();
        assert!(!stored.contains(&token));
        let secret = token.rsplit('_').next().unwrap();
        assert!(!stored.contains(secret));
        let grant = verify(root.path(), &token, 1_001).unwrap().unwrap();
        assert_eq!(grant.subject, "workbench");
        assert_eq!(grant.id, summary.id);
        // 到期的瞬间就拒绝（半开区间），不留 1 秒的灰区。
        assert_eq!(verify(root.path(), &token, 4_599).unwrap().unwrap(), grant);
        assert_eq!(verify(root.path(), &token, 4_600).unwrap(), None);
    }

    #[test]
    fn the_root_subject_name_cannot_be_issued_or_loaded() {
        let root = home();
        let error = issue(root.path(), RESERVED_SUBJECT, &Scope::ALL, 3600, 1_000).unwrap_err();
        assert!(
            format!("{error:#}").contains("reserved"),
            "unexpected error: {error:#}"
        );
        // 手写进文件也不行：加载时同样拒绝整个库（fail-closed）。
        let (_, token) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        let mut store: serde_json::Value =
            serde_json::from_slice(&fs::read(path(root.path())).unwrap()).unwrap();
        store["credentials"][0]["subject"] = serde_json::json!(RESERVED_SUBJECT);
        fs::write(
            path(root.path()),
            serde_json::to_vec_pretty(&store).unwrap(),
        )
        .unwrap();
        assert!(load(root.path()).is_err());
        assert!(verify(root.path(), &token, 1_000).is_err());
    }

    #[test]
    fn jobs_of_the_same_subject_share_the_same_identity() {
        // 同一主体签两次（例如例行轮换）视为同一个人：任务归属按主体名比较，
        // 不按凭据 id，否则换一把 token 就看不到自己昨天提交的任务。
        let root = home();
        let (first, _) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        let (second, _) = issue(root.path(), "workbench", &Scope::ALL, 3600, 2_000).unwrap();
        assert_ne!(first.id, second.id);
        assert_eq!(first.subject, second.subject);
    }

    #[test]
    fn revoke_takes_effect_immediately_and_is_idempotent() {
        let root = home();
        let (summary, token) = issue(root.path(), "laptop", &Scope::ALL, 3600, 1_000).unwrap();
        assert!(verify(root.path(), &token, 1_000).unwrap().is_some());
        let revoked = revoke(root.path(), summary.id, 1_100).unwrap();
        assert_eq!(revoked.revoked_at, Some(1_100));
        assert!(!list(root.path()).unwrap()[0].active(1_100));
        assert!(verify(root.path(), &token, 1_100).unwrap().is_none());
        // 重复撤销不重写时间，也不产生第二条记录。
        let again = revoke(root.path(), summary.id, 9_999).unwrap();
        assert_eq!(again.revoked_at, Some(1_100));
        assert_eq!(list(root.path()).unwrap().len(), 1);
    }

    #[test]
    fn foreign_and_forged_tokens_do_not_touch_the_store() {
        let root = home();
        let (_summary, token) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        // 主 token 与任意伪造串都返回 None，绝不返回错误。
        assert_eq!(verify(root.path(), "some-root-token", 1_000).unwrap(), None);
        assert_eq!(
            verify(root.path(), "spt_not-a-uuid_dead", 1_000).unwrap(),
            None
        );
        assert_eq!(verify(root.path(), "spt_", 1_000).unwrap(), None);
        assert_eq!(
            verify(root.path(), &token.replace("spt_", "spx_"), 1_000).unwrap(),
            None
        );
        // 同标识、不同 secret 必须拒绝。
        let forged = format!(
            "spt_{}_{}",
            token.split('_').nth(1).unwrap(),
            "0".repeat(64)
        );
        assert_eq!(verify(root.path(), &forged, 1_000).unwrap(), None);
    }

    #[test]
    fn a_corrupt_store_fails_closed() {
        let root = home();
        let (_, token) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        let original = fs::read_to_string(path(root.path())).unwrap();
        for broken in [
            "not json".to_string(),
            original.replace("\"schema\": 1", "\"schema\": 2"),
            original.replace("\"schema\": 1", "\"schema\": 1, \"extra\": 1"),
            original.replace("\"subject\": \"workbench\"", "\"subject\": \"\""),
            // 摘要长度不对，说明文件被截断或手工改坏。
            original.replace(&list(root.path()).unwrap()[0].token_sha256[..8], "zzzzzzzz"),
        ] {
            assert_ne!(broken, original, "each mutation must change the file");
            fs::write(path(root.path()), broken).unwrap();
            // 用一把真凭据验证：它本来能过，文件坏掉后必须报错而不是返回 None 混过去。
            assert!(
                verify(root.path(), &token, 1_000).is_err(),
                "corrupt store must not be treated as empty"
            );
            assert!(list(root.path()).is_err());
        }
        fs::write(path(root.path()), original).unwrap();
        assert!(list(root.path()).is_ok());
    }

    #[test]
    fn duplicate_identifiers_and_bad_lifetimes_are_rejected() {
        let root = home();
        let (_summary, _token) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        let original: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path(root.path())).unwrap()).unwrap();
        let mut duplicated = original.clone();
        let first = duplicated["credentials"][0].clone();
        duplicated["credentials"]
            .as_array_mut()
            .unwrap()
            .push(first);
        fs::write(path(root.path()), serde_json::to_vec(&duplicated).unwrap()).unwrap();
        assert!(list(root.path()).is_err());

        let mut bad_lifetime = original.clone();
        bad_lifetime["credentials"][0]["expires_at"] = serde_json::json!(500);
        fs::write(
            path(root.path()),
            serde_json::to_vec(&bad_lifetime).unwrap(),
        )
        .unwrap();
        assert!(list(root.path()).is_err());

        let mut early_revoke = original.clone();
        early_revoke["credentials"][0]["revoked_at"] = serde_json::json!(10);
        fs::write(
            path(root.path()),
            serde_json::to_vec(&early_revoke).unwrap(),
        )
        .unwrap();
        assert!(list(root.path()).is_err());
    }

    #[test]
    fn issue_bounds_and_subject_validation() {
        let root = home();
        for ttl in [0, MAX_TTL_SECS + 1] {
            assert!(issue(root.path(), "workbench", &Scope::ALL, ttl, 1_000).is_err());
        }
        for subject in ["", "   ", &"x".repeat(129), "a\u{7}b"] {
            assert!(issue(root.path(), subject, &Scope::ALL, 60, 1_000).is_err());
        }
        assert!(!path(root.path()).exists(), "validation precedes any write");
        issue(
            root.path(),
            &"x".repeat(128),
            &Scope::ALL,
            MAX_TTL_SECS,
            1_000,
        )
        .unwrap();
    }

    #[test]
    fn scopes_are_whitelisted_normalized_and_read_is_mandatory() {
        // 解析只认四个词，大小写不敏感，其余（含空串与近义词）一律拒绝。
        assert_eq!(Scope::parse(" READ ").unwrap(), Scope::Read);
        for word in ["root", "write", "readonly", ""] {
            assert!(Scope::parse(word).is_err(), "{word:?} must not parse");
        }
        // 空权限列表没有意义；`admin` 会自动补上必需的 `read` 并去重排序。
        let root = home();
        assert!(issue(root.path(), "no-scopes", &[], 60, 1_000).is_err());
        let (summary, _) = issue(
            root.path(),
            "operator",
            &[Scope::Admin, Scope::Read, Scope::Admin],
            60,
            1_000,
        )
        .unwrap();
        assert_eq!(summary.scopes, vec![Scope::Read, Scope::Admin]);
        // 缺 `read` 的记录不是「只写凭据」，而是自相矛盾的坏记录：整库拒绝加载。
        let mut store: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path(root.path())).unwrap()).unwrap();
        store["credentials"][0]["scopes"] = serde_json::json!(["admin"]);
        fs::write(path(root.path()), serde_json::to_vec(&store).unwrap()).unwrap();
        assert!(list(root.path()).is_err());
    }

    #[test]
    fn prune_only_drops_credentials_that_expired_after_revocation() {
        let root = home();
        let (expired, _) = issue(root.path(), "expired", &Scope::ALL, 60, 1_000).unwrap();
        let (live, _) = issue(root.path(), "live", &Scope::ALL, 3_600, 1_000).unwrap();
        let (never, _) = issue(root.path(), "never-revoked", &Scope::ALL, 60, 1_000).unwrap();
        revoke(root.path(), expired.id, 1_010).unwrap();
        revoke(root.path(), live.id, 1_010).unwrap();
        let before = fs::read(path(root.path())).unwrap();

        let planned = prune(root.path(), 1_100, false).unwrap();
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].id, expired.id);
        assert_eq!(
            fs::read(path(root.path())).unwrap(),
            before,
            "dry run must not write"
        );
        assert_eq!(list(root.path()).unwrap().len(), 3);

        let removed = prune(root.path(), 1_100, true).unwrap();
        assert_eq!(removed.len(), 1);
        let remaining = list(root.path()).unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(
            remaining.iter().any(|c| c.id == live.id),
            "revoked but live stays"
        );
        assert!(
            remaining.iter().any(|c| c.id == never.id),
            "expired but not revoked stays"
        );
        // 再跑一次是空操作，不重写文件。
        let after = fs::read(path(root.path())).unwrap();
        assert!(prune(root.path(), 1_100, true).unwrap().is_empty());
        assert_eq!(fs::read(path(root.path())).unwrap(), after);
    }

    /// 并发签发不能丢记录：没有写锁时两个 `issue` 各自读到同一份旧文件，
    /// 后写的会覆盖前一条（这是真实的丢凭据竞态，不是理论问题）。
    #[test]
    fn concurrent_issuance_does_not_lose_records() {
        let root = home();
        let root = std::sync::Arc::new(root.path().to_path_buf());
        let handles = (0..8)
            .map(|index| {
                let root = root.clone();
                std::thread::spawn(move || {
                    issue(&root, &format!("subject-{index}"), &Scope::ALL, 600, 1_000)
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle
                .join()
                .expect("thread panicked")
                .expect("issue failed");
        }
        assert_eq!(list(&root).unwrap().len(), 8);
    }

    #[test]
    fn summaries_never_carry_the_digest() {
        let root = home();
        let (summary, _) = issue(root.path(), "workbench", &Scope::ALL, 3600, 1_000).unwrap();
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("token_sha256"));
        assert!(!json.contains("sha256"));
    }
}
