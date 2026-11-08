#!/usr/bin/env python3
"""在全新 Docker 资源中验收真实 sub2api 的停写迁移、入口切换与反向恢复。"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid


APP_IMAGE = "zjarlin/sub2api@sha256:4915bd250efa7c7c78b4a733c828330234a84438d937d0e098ce41747a8474f4"
IMAGES = {"app": APP_IMAGE, "pg": "postgres:15-alpine", "redis": "redis:8-alpine", "edge": "caddy:2"}
LABEL = "io.sshpool.rehearsal"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_snapshot(directory):
    """只认可固定文件集合；任何摘要不符均在创建恢复实例前失败。"""
    manifest = json.loads((directory / "manifest.json").read_text())
    require(set(manifest) == {"postgres.dump", "redis.rdb", "app.tar"}, "unexpected snapshot files")
    for name, digest in manifest.items():
        file = directory / name
        require(file.is_file() and not file.is_symlink(), f"snapshot file missing: {name}")
        require(sha256(file) == digest, f"snapshot checksum mismatch: {name}")
    return manifest


def file_manifest(archive):
    """比较配置卷的文件内容与权限；不把 tar 头的时间戳当作业务变化。"""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source:
            if member.isdir():
                continue
            require(member.isfile(), "configuration archive has an unsupported entry")
            name = str(Path(member.name))
            require(name not in files, "configuration archive has a duplicate path")
            with source.extractfile(member) as content:
                files[name] = {"sha256": hashlib.sha256(content.read()).hexdigest(), "mode": member.mode}
    require(files, "configuration archive is empty")
    return files


def comparable_print(observation, at_ms):
    """按同一截止时刻比较；只允许已到期键消失，不忽略永久键或未到期会话。"""
    keys = []
    databases = []
    for line in observation["redis"].splitlines():
        fields = line.split("|")
        require(len(fields) == 5, "invalid Redis fingerprint")
        if fields[1] == "dbsize":
            databases.append(fields[0])
            continue
        require(fields[4].startswith("expires_at_ms="), "exact Redis expiry missing")
        expiry = int(fields[4].removeprefix("expires_at_ms="))
        require(expiry >= -1, "invalid Redis expiry")
        if expiry == -1 or expiry > at_ms:
            keys.append(line)
    return observation["postgres"], sorted(databases), sorted(keys)


class Rehearsal:
    """所有资源名都由新 UUID 派生；不接受现有实例、业务目录或凭据作为输入。"""

    def __init__(self, output):
        self.output = output
        output.mkdir(parents=True, exist_ok=False)
        os.chmod(output, 0o700)
        self.prefix = f"sshpool-app-mig-{uuid.uuid4()}"
        self.stage = Path(tempfile.mkdtemp(prefix=self.prefix + "-"))
        self.resources = {"container": [], "volume": [], "network": []}
        self.password = secrets.token_hex(24)
        self.jwt = secrets.token_hex(32)
        self.token = None
        self.refresh = None
        self.url = None
        self.active = None
        self.report = {"schema": 1, "image": APP_IMAGE, "checks": {}, "transfers": [], "frozen_observations": [], "steps": []}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def docker(self, *args, stdin=None, ok=True, seconds=180):
        # 统一执行入口不打印命令参数：其中可能包含本次生成的演练凭据。
        result = subprocess.run(["docker", *args], input=stdin, capture_output=True, timeout=seconds)
        if ok and result.returncode:
            message = result.stderr.decode(errors="replace").replace(self.password, "<demo-secret>")
            raise RuntimeError(f"docker {args[0]} failed: {message[-2500:]}")
        return result

    def name(self, suffix):
        return f"{self.prefix}-{suffix}"

    def record(self, step):
        entry = {"step": step, "at": int(time.time())}
        self.report["steps"].append(entry)
        with (self.output / "steps.jsonl").open("a") as sink:
            sink.write(json.dumps(entry) + "\n")
            sink.flush()
            os.fsync(sink.fileno())
        print(step, flush=True)

    def check(self, name, condition):
        self.report["checks"][name] = bool(condition)
        require(condition, f"check failed: {name}")

    def create_resource(self, kind, suffix, *args):
        name = self.name(suffix)
        self.resources[kind].append(name)
        self.docker(kind, "create", "--label", f"{LABEL}={self.prefix}", *args, name)
        return name

    def container(self, suffix, image, *args):
        name = self.name(suffix)
        self.resources["container"].append(name)
        self.docker("create", "--name", name, "--label", f"{LABEL}={self.prefix}",
                    "--memory", "768m", "--cpus", "1", "--pids-limit", "256", *args, image)
        return name

    def run_command_container(self, suffix, image, args, command):
        name = self.name(suffix)
        self.resources["container"].append(name)
        self.docker("run", "--name", name, "--label", f"{LABEL}={self.prefix}",
                    "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64", *args, image, *command)

    def sql(self, side, sql, user="postgres", ok=True):
        return self.docker("exec", "-i", self.name(f"{side}-pg"), "psql", "-X", "-qAt",
                           "-v", "ON_ERROR_STOP=1", "-U", user, "-d", "demo",
                           stdin=sql.encode(), ok=ok)

    def redis(self, side, *args):
        result = self.docker("exec", self.name(f"{side}-redis"), "redis-cli", "--raw", *args)
        text = result.stdout.decode().strip()
        require(not text.startswith(("ERR ", "NOAUTH ", "NOREPLICAS ")), "Redis command rejected")
        return text

    def wait(self, description, probe, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if probe():
                    return
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                # 只在启动探测中容许尚未监听；正式业务请求不自动重试。
                pass
            time.sleep(1)
        raise RuntimeError(f"timed out waiting for {description}")

    def create_side(self, side):
        network = self.create_resource("network", side, "--internal")
        for kind in ("pg", "redis", "app"):
            self.create_resource("volume", f"{side}-{kind}")
        pg = self.container(f"{side}-pg", IMAGES["pg"], "--network", network,
                            "--network-alias", "db", "-e", f"POSTGRES_PASSWORD={self.password}",
                            "-e", "POSTGRES_DB=demo", "-v", f"{self.name(side + '-pg')}:/var/lib/postgresql/data")
        redis = self.container(f"{side}-redis", IMAGES["redis"], "--network", network,
                               "--network-alias", "redis", "-v", f"{self.name(side + '-redis')}:/data")
        self.docker("start", pg, redis)
        # 初始化阶段的临时实例只监听 Unix socket；等 TCP 就绪才能确认建库已完成。
        self.wait("PostgreSQL", lambda: self.docker("exec", pg, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "demo", ok=False).returncode == 0)
        self.sql(side, f"CREATE ROLE demo_app LOGIN PASSWORD '{self.password}'; ALTER DATABASE demo OWNER TO demo_app;")
        self.check(f"{side}_database_identity", self.sql(side, "SELECT current_database(), current_user;", "demo_app").stdout.strip() == b"demo|demo_app")

    def start_app(self, side):
        for name in self.resources["container"]:
            if name.endswith("-app"):
                running = self.docker("inspect", "--format", "{{.State.Running}}", name).stdout.strip()
                require(running == b"false", "another application writer is still running")
        # 地址在各自的独立网络内解析，原配置卷无需修改连接串。
        args = ["--network", self.name(side), "--network-alias", f"app-{side}",
                "-v", f"{self.name(side + '-app')}:/app/data"]
        env = {"AUTO_SETUP": "true", "DATABASE_HOST": "db", "DATABASE_DBNAME": "demo",
               "DATABASE_USER": "demo_app", "DATABASE_PASSWORD": self.password, "DATABASE_SSLMODE": "disable",
               "REDIS_HOST": "redis", "ADMIN_EMAIL": "demo@example.invalid", "ADMIN_PASSWORD": self.password,
               "JWT_SECRET": self.jwt, "TOTP_ENCRYPTION_KEY": self.jwt, "SERVER_MODE": "debug",
               "DATABASE_MAX_OPEN_CONNS": "5", "DATABASE_MAX_IDLE_CONNS": "2",
               "REDIS_POOL_SIZE": "10", "REDIS_MIN_IDLE_CONNS": "1"}
        for key, value in env.items():
            args.extend(["-e", f"{key}={value}"])
        app = self.container(f"{side}-app", APP_IMAGE, *args)
        self.docker("start", app)
        def ready():
            state = json.loads(self.docker("inspect", "--format", "{{json .State}}", app).stdout)
            require(state["Running"], f"{side} application exited with code {state['ExitCode']}")
            return self.docker("exec", app, "wget", "-qO-", "http://127.0.0.1:8080/health", ok=False).returncode == 0
        self.wait("sub2api HTTP health", ready, 180)

    def create_edge(self):
        # Docker 29 不为 internal 网络发布端口；只有入口连接独立桥接网，且只绑定回环。
        network = self.create_resource("network", "entry")
        edge = self.container("edge", IMAGES["edge"], "--network", network, "-p", "127.0.0.1::8080")
        self.docker("network", "connect", self.name("a"), edge)
        self.write_edge(None)
        self.docker("start", edge)
        port = self.docker("port", edge, "8080/tcp").stdout.decode().strip().rsplit(":", 1)[1]
        self.url = f"http://127.0.0.1:{port}"
        self.wait("maintenance endpoint", lambda: self.request("GET", "/health", expected=503)[0] == 503)

    def write_edge(self, side):
        if side is None:
            handler = 'respond "migration maintenance" 503'
        else:
            handler = f"header X-Rehearsal-Side {side}\nreverse_proxy app-{side}:8080"
        config = self.stage / "Caddyfile"
        config.write_text("{\n admin 127.0.0.1:2019\n auto_https off\n}\n:8080 {\n" + handler + "\n}\n")
        self.docker("cp", str(config), f"{self.name('edge')}:/etc/caddy/Caddyfile")

    def route(self, side):
        self.write_edge(side)
        self.docker("exec", self.name("edge"), "caddy", "reload", "--config", "/etc/caddy/Caddyfile")
        self.active = side
        self.request("GET", "/health", expected=200 if side else 503)
        self.record("route-" + (side or "maintenance"))

    def request(self, method, path, body=None, expected=200, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth and self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            response = self.http.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            require(response.status == expected, f"{method} {path}: expected {expected}, got {response.status}")
            if self.active:
                require(response.headers.get("X-Rehearsal-Side") == self.active, "request reached the wrong side")
        if expected == 503 or path == "/health":
            return expected, None
        result = json.loads(raw)
        if expected >= 400:
            return expected, result
        require(result.get("code") == 0, f"application rejected {method} {path}")
        return expected, result["data"]

    def login(self):
        _, data = self.request("POST", "/api/v1/auth/login", {"email": "demo@example.invalid", "password": self.password}, auth=False)
        self.token = data["access_token"]
        self.refresh = data["refresh_token"]
        require(bool(self.refresh), "login did not create a persistent refresh session")
        self.user = data["user"]["id"]
        return data["user"]["balance"]

    def profile(self):
        return self.request("GET", "/api/v1/user/profile")[1]

    def renew_session(self, label):
        self.check(label + "_old_access_token_valid", self.profile()["id"] == self.user)
        _, data = self.request("POST", "/api/v1/auth/refresh", {"refresh_token": self.refresh}, auth=False)
        self.token = data["access_token"]
        self.refresh = data["refresh_token"]
        self.check(label + "_refresh_session_survived", bool(self.token and self.refresh))

    def charge(self, code, amount, replay=False):
        # 只把兑换码作为演练种子；余额更新、消费记录和去重均交给真实用户 API。
        if not replay:
            self.sql(self.active, f"INSERT INTO redeem_codes(code,type,value) VALUES ('{code}','balance',{amount});")
        code_id = int(self.sql(self.active, f"SELECT id FROM redeem_codes WHERE code='{code}';").stdout.strip())
        _, data = self.request("POST", "/api/v1/redeem", {"code": code}, expected=409 if replay else 200)
        if replay:
            require(data.get("reason") == "REDEEM_CODE_USED" or data.get("code") == "REDEEM_CODE_USED",
                    "duplicate credit was rejected for an unexpected reason")
        else:
            require(data["id"] == code_id and data["status"] == "used", "credit was not consumed")
        return code_id

    def stop_and_fence(self, side):
        require(self.active is None, "traffic must enter maintenance before fencing")
        self.docker("stop", "--time", "45", self.name(f"{side}-app"), seconds=60)
        state = json.loads(self.docker("inspect", "--format", "{{json .State}}", self.name(f"{side}-app")).stdout)
        self.check(side + "_app_stopped_cleanly", not state["Running"] and state["ExitCode"] == 0)
        self.enqueue_invalidation(side, "demo-queue-" + side)
        self.sql(side, "ALTER SYSTEM SET default_transaction_read_only=on; SELECT pg_reload_conf();")
        self.wait("PostgreSQL write fence", lambda: self.sql(side, "SHOW transaction_read_only;", "demo_app").stdout.strip() == b"on")
        denied = self.sql(side, "CREATE TABLE must_not_exist(id int);", "demo_app", ok=False)
        self.check(side + "_sql_write_rejected", denied.returncode != 0 and b"read-only" in denied.stderr)
        self.redis(side, "CONFIG", "SET", "min-replicas-to-write", "1")
        denied = self.docker("exec", self.name(f"{side}-redis"), "redis-cli", "SET", "must-not-exist", "x")
        self.check(side + "_redis_write_rejected", b"NOREPLICAS" in denied.stdout)
        self.record(side + "-stopped-and-fenced")

    def snapshot(self, side):
        directory = self.output / (side + "-snapshot")
        directory.mkdir()
        # 管理连接只用于只读备份；应用已停且两个数据引擎都验证拒写。
        dump = self.docker("exec", self.name(side + "-pg"), "pg_dump", "-U", "demo_app", "-d", "demo", "-Fc").stdout
        (directory / "postgres.dump").write_bytes(dump)
        self.redis(side, "SAVE")
        self.docker("cp", self.name(side + "-redis") + ":/data/dump.rdb", str(directory / "redis.rdb"))
        data = self.docker("cp", self.name(side + "-app") + ":/app/data/.", "-").stdout
        (directory / "app.tar").write_bytes(data)
        manifest = {name: sha256(directory / name) for name in ("postgres.dump", "redis.rdb", "app.tar")}
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        verify_snapshot(directory)
        self.record(side + "-snapshot-verified")
        return directory

    def frozen_print(self, side):
        pg = self.sql(side, (self.output / "fingerprint.sql").read_text(), "demo_app").stdout.decode()
        lua = (self.output / "fingerprint.lua").read_bytes()
        # EVAL 的脚本文本作为一个参数，输出只有摘要，没有键值明文。
        redis = self.redis(side, "EVAL", lua.decode(), "0", "0")
        return {"postgres": pg, "redis": redis}

    def verify_redis_fingerprint(self):
        """用真实 Redis 固定集合无序、嵌套 stream 与二进制字段边界的回归。"""
        container = self.container("fingerprint-redis", IMAGES["redis"], "--network", "none")
        self.docker("start", container)
        self.wait("fingerprint Redis", lambda: self.docker("exec", container, "redis-cli", "PING", ok=False).stdout.strip() == b"PONG")
        seed = r"""
redis.call('HSET', 'hash', 'a', '1', 'b', '2', 'c', '3')
redis.call('SADD', 'set', 'a', 'b', 'c', 'd')
redis.call('XADD', 'stream', '1-0', 'field', 'value')
redis.call('RPUSH', 'binary-left', 'a\0b', 'c')
redis.call('RPUSH', 'binary-right', 'a', 'b\0c')
return 'ok'
"""
        self.redis("fingerprint", "EVAL", seed, "0")
        script = (self.output / "fingerprint.lua").read_text()
        before = self.redis("fingerprint", "EVAL", script, "0", "0")
        self.redis("fingerprint", "EVAL", "redis.call('DEL','hash','set'); redis.call('HSET','hash','c','3','b','2','a','1'); redis.call('SADD','set','d','c','b','a'); return 'ok'", "0")
        after = self.redis("fingerprint", "EVAL", script, "0", "0")
        self.check("redis_unordered_values_and_stream_stable", before == after)
        values = {line.split("|")[2]: line.split("|")[3] for line in after.splitlines() if "|dbsize|" not in line}
        left = values[hashlib.sha1(b"binary-left").hexdigest()]
        right = values[hashlib.sha1(b"binary-right").hexdigest()]
        self.check("redis_binary_boundaries_distinguished", left != right)
        self.docker("stop", container)

    def restore(self, side, directory):
        manifest = verify_snapshot(directory)
        self.create_side(side)
        self.docker("exec", "-i", self.name(side + "-pg"), "pg_restore", "-U", "demo_app", "-d", "demo",
                    "--no-owner", "--no-acl", "--exit-on-error", stdin=(directory / "postgres.dump").read_bytes())
        self.docker("stop", self.name(side + "-redis"))
        self.docker("cp", str(directory / "redis.rdb"), self.name(side + "-redis") + ":/data/dump.rdb")
        self.docker("start", self.name(side + "-redis"))
        self.wait("restored Redis", lambda: self.docker("exec", self.name(side + "-redis"), "redis-cli", "PING", ok=False).stdout.strip() == b"PONG")
        self.run_command_container(side + "-restore-files", "alpine:3.22",
                                   ["--network", "none", "-i", "-v", f"{self.name(side + '-app')}:/restore"], ["true"])
        self.docker("cp", "-", self.name(side + "-restore-files") + ":/restore", stdin=(directory / "app.tar").read_bytes())
        restored_files = self.docker("cp", self.name(side + "-restore-files") + ":/restore/.", "-").stdout
        self.check(side + "_configuration_files_restored", file_manifest(restored_files) == file_manifest((directory / "app.tar").read_bytes()))
        self.check(side + "_backup_unchanged", verify_snapshot(directory) == manifest)
        self.record(side + "-restored")

    def enqueue_invalidation(self, side, marker):
        # 用应用自带的事务入队函数制造停机窗口中的未消费事件。
        self.sql(side, "SELECT enqueue_auth_cache_invalidation('" + marker + "');")
        cache_key = "apikey:auth:" + hashlib.sha256(marker.encode()).hexdigest()
        self.redis(side, "SET", cache_key, "stale-demo-value")
        pending = self.sql(side, "SELECT count(*) FROM auth_cache_invalidation_outbox WHERE cache_key=encode(sha256(convert_to('" + marker + "','UTF8')),'hex');").stdout.strip()
        self.check(side + "_queue_pending", pending == b"1")

    def wait_queue(self, side, marker):
        self.wait("restored application outbox worker", lambda: self.sql(side,
            "SELECT count(*) FROM auth_cache_invalidation_outbox WHERE cache_key=encode(sha256(convert_to('" + marker + "','UTF8')),'hex');").stdout.strip() == b"0", 90)
        self.check(side + "_queue_consumed", True)
        cache_key = "apikey:auth:" + hashlib.sha256(marker.encode()).hexdigest()
        self.check(side + "_stale_cache_invalidated", self.redis(side, "EXISTS", cache_key) == "0")

    def compare(self, source, target, before, after, label):
        at_ms = time.time_ns() // 1_000_000
        self.report["transfers"].append({"from": source, "to": target, "before": before, "after": after, "compared_at_ms": at_ms})
        self.check(label, comparable_print(before, at_ms) == comparable_print(after, at_ms))

    def check_frozen(self, side, before):
        after = self.frozen_print(side)
        at_ms = time.time_ns() // 1_000_000
        self.report["frozen_observations"].append({"from": side, "to": side, "before": before, "after": after, "compared_at_ms": at_ms})
        self.check(side + "_stayed_frozen", comparable_print(before, at_ms) == comparable_print(after, at_ms))

    def execute(self, sql_path, lua_path):
        for image in {*IMAGES.values(), "alpine:3.22"}:
            self.docker("image", "inspect", image)
        shutil.copyfile(sql_path, self.output / "fingerprint.sql")
        shutil.copyfile(lua_path, self.output / "fingerprint.lua")
        self.record("images-available")
        self.verify_redis_fingerprint()
        self.create_side("a")
        self.start_app("a")
        self.create_edge()
        self.route("a")
        initial_balance = self.login()
        first_id = self.charge("sshpool-demo-first", 10)
        self.check("initial_credit_applied", self.profile()["balance"] == initial_balance + 10)
        self.route(None)
        self.stop_and_fence("a")
        forward = self.snapshot("a")
        before = self.frozen_print("a")
        self.restore("b", forward)
        restored = self.frozen_print("b")
        self.compare("a", "b", before, restored, "forward_fingerprints_equal")
        self.docker("network", "connect", self.name("b"), self.name("edge"))
        self.start_app("b")
        self.route("b")
        self.renew_session("b")
        self.check("b_fresh_login", self.login() == initial_balance + 10)
        self.check("forward_credit_not_duplicated", self.charge("sshpool-demo-first", 10, replay=True) == first_id and self.profile()["balance"] == initial_balance + 10)
        second_id = self.charge("sshpool-demo-second", 7)
        self.check("b_new_credit_and_sequence", second_id > first_id and self.profile()["balance"] == initial_balance + 17)
        self.wait_queue("b", "demo-queue-a")
        self.check_frozen("a", before)
        self.route(None)
        self.stop_and_fence("b")
        reverse = self.snapshot("b")
        before_return = self.frozen_print("b")
        self.restore("return", reverse)
        restored_return = self.frozen_print("return")
        self.compare("b", "return", before_return, restored_return, "reverse_fingerprints_equal")
        self.docker("network", "connect", self.name("return"), self.name("edge"))
        self.start_app("return")
        self.route("return")
        self.renew_session("return")
        self.check("return_fresh_login", self.login() == initial_balance + 17)
        self.check("b_credit_survived_switchback", self.charge("sshpool-demo-second", 7, replay=True) == second_id and self.profile()["balance"] == initial_balance + 17)
        third_id = self.charge("sshpool-demo-third", 3)
        self.check("return_credit_and_sequence", third_id > second_id and self.profile()["balance"] == initial_balance + 20)
        self.wait_queue("return", "demo-queue-b")
        self.check_frozen("b", before_return)
        self.check("both_backups_retained", bool(verify_snapshot(forward) and verify_snapshot(reverse)))
        self.report["billing_ids"] = [first_id, second_id, third_id]
        self.report["final_balance_delta"] = 20
        self.record("switchback-verified")

    def cleanup(self):
        # 只删除本次新建且标签匹配的资源；任何失败都使演练失败。
        errors = []
        for kind, names in self.resources.items():
            for name in reversed(names):
                result = self.docker(kind, "inspect", name, ok=False)
                if result.returncode:
                    continue
                info = json.loads(result.stdout)[0]
                labels = info.get("Config", info).get("Labels") or {}
                if labels.get(LABEL) != self.prefix:
                    errors.append(f"refusing cleanup of unowned {kind} {name}")
                    continue
                flags = ["-f"] if kind == "container" else []
                result = self.docker(kind, "rm", *flags, name, ok=False)
                if result.returncode:
                    errors.append(f"could not remove {kind} {name}")
        shutil.rmtree(self.stage)
        for kind in ("container", "volume", "network"):
            flags = ["-a"] if kind == "container" else []
            remaining = self.docker(kind, "ls", "-q", *flags, "--filter", f"label={LABEL}={self.prefix}").stdout.strip()
            if remaining:
                errors.append(f"{kind} resources remain after cleanup")
        self.report["cleanup_errors"] = errors
        self.check("resources_removed", not errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--postgres-fingerprint", required=True, type=Path)
    parser.add_argument("--redis-fingerprint", required=True, type=Path)
    args = parser.parse_args()
    rehearsal = Rehearsal(args.output)
    try:
        rehearsal.execute(args.postgres_fingerprint, args.redis_fingerprint)
    except Exception as error:
        rehearsal.report["failure"] = str(error).replace(rehearsal.password, "<demo-secret>")
        raise
    finally:
        try:
            rehearsal.cleanup()
        finally:
            (args.output / "report.json").write_text(json.dumps(rehearsal.report, indent=2) + "\n")


if __name__ == "__main__":
    main()
