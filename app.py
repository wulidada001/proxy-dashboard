from flask import Flask, jsonify
import subprocess
import time
import requests
import threading
from datetime import datetime
import json
import re
from collections import defaultdict
from pathlib import Path

app = Flask(__name__)

# ---------- 基础配置 ----------
# 生成 254 个代理配置：30000-30253 对应 31.58.239.1-31.58.239.254
PROXIES = [
    {"port": port, "ip": f"31.58.239.{port - 29999}"}
    for port in range(30000, 30254)
]

CHECK_INTERVAL_SECONDS = 60  # 后台健康检查间隔

# 全局缓存
RESULTS = {}
LAST_UPDATE_TS = 0
USER_SUMMARY = {}
USERS_CONFIG_MTIME = 0

LOG_DIR = Path("/var/log/3proxy")
LOG_PREFIX = "3proxy.log."


def get_today_log_path() -> Path | None:
    """返回今天的 3proxy 日志路径，如 /var/log/3proxy/3proxy.log.2025.11.22"""
    today = datetime.now().strftime("%Y.%m.%d")
    p = LOG_DIR / f"{LOG_PREFIX}{today}"
    if p.exists():
        return p
    # 回退：尝试不带日期的文件
    p2 = LOG_DIR / "3proxy.log"
    return p2 if p2.exists() else None


def load_log_hits():
    """
    从 3proxy 日志里粗略统计：
    - 每个 userN（=端口）今天的请求次数
    返回：hits_by_port, hits_by_user
    """
    hits_by_port = defaultdict(int)
    hits_by_user = defaultdict(int)

    log_path = get_today_log_path()
    if not log_path:
        return hits_by_port, hits_by_user

    user_re = re.compile(r"\buser(\d+)\b")

    try:
        with log_path.open("r", errors="ignore") as f:
            for line in f:
                m = user_re.search(line)
                if not m:
                    continue
                idx = int(m.group(1))
                port = 29999 + idx
                hits_by_port[port] += 1
                hits_by_user[idx] += 1
    except Exception:
        # 日志打不开就算了，保持 0
        pass

    return hits_by_port, hits_by_user


def get_conn_count(port: int) -> int:
    """
    用 ss 统计当前到某个端口的 TCP 连接数
    """
    try:
        out = subprocess.check_output(
            ["ss", "-nt", "sport", f"=:{port}"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        lines = [l for l in out.strip().splitlines() if l.strip()]
        if not lines:
            return 0
        # 第一行是标题，从第二行开始是真实连接
        return max(len(lines) - 1, 0)
    except Exception:
        return 0


def load_user_map():
    """
    从 users.json 读取用户与端口的绑定关系
    格式示例:
    [
      {"name": "项目A", "ports": [30000,30001,30002]},
      {"name": "客户B", "ports": [30003,30004]}
    ]
    返回:
      port_to_user: {30000: "项目A", ...}
      user_meta: {"项目A": {"name": "...", "ports":[...], ...}, ...}
    """
    global USERS_CONFIG_MTIME

    cfg_path = Path(__file__).with_name("users.json")
    port_to_user: dict[int, str] = {}
    user_meta: dict[str, dict] = {}

    if not cfg_path.exists():
        return port_to_user, user_meta

    try:
        stat = cfg_path.stat()
        mtime = stat.st_mtime
    except Exception:
        return port_to_user, user_meta

    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return port_to_user, user_meta

    for u in data:
        name = u.get("name")
        if not name:
            continue
        ports = u.get("ports", [])
        ports_clean = []
        for p in ports:
            try:
                p_int = int(p)
            except Exception:
                continue
            ports_clean.append(p_int)
            port_to_user[p_int] = name
        user_meta[name] = {
            "name": name,
            "ports": sorted(list(set(ports_clean))),
            "reqs_today": 0,
            "online_ports": 0,
            "total_ports": len(set(ports_clean)),
        }

    USERS_CONFIG_MTIME = mtime
    return port_to_user, user_meta


def check_single_proxy(port: int, ip: str, last_ok_ts: float | None = None, reqs_today: int = 0):
    """
    通过 ipinfo.io 测试代理：
    - 成功：online=True, delay_ms, real_ip, last_ok_ts
    - 失败：online=False, 其它为 None（保留 last_ok_ts 方便显示历史）
    """
    user_index = port - 29999
    proxy_auth = f"user{user_index}:pass{user_index}"
    proxy_url = f"http://{proxy_auth}@127.0.0.1:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}
    now = time.time()
    try:
        start = time.time()
        r = requests.get("https://ipinfo.io/ip", proxies=proxies, timeout=3)
        delay_ms = int((time.time() - start) * 1000)
        real_ip = r.text.strip()
        ok = True
        last_ok_ts = now
    except Exception:
        ok = False
        delay_ms = None
        real_ip = None

    conn_count = get_conn_count(port)

    item = {
        "port": port,
        "expected_ip": ip,
        "real_ip": real_ip,
        "delay_ms": delay_ms,
        "online": ok,
        "conn_count": conn_count,
        "last_ok_ts": last_ok_ts,
        "last_ok": (
            datetime.fromtimestamp(last_ok_ts).strftime("%Y-%m-%d %H:%M:%S")
            if last_ok_ts
            else None
        ),
        "reqs_today": reqs_today,
    }

    # 简单盗用检测：出口 IP 和预期不一致
    item["ip_mismatch"] = bool(real_ip and real_ip != ip)

    return item


def background_worker():
    """
    后台线程：循环检查全部 254 个代理，结果写入 RESULTS 和 USER_SUMMARY
    """
    global RESULTS, LAST_UPDATE_TS, USER_SUMMARY
    while True:
        new_results: dict[int, dict] = {}
        old_results = RESULTS.copy()

        # 1) 从日志加载今天的请求次数
        hits_by_port, hits_by_user = load_log_hits()

        # 2) 加载用户映射
        port_to_user, user_meta = load_user_map()

        # 3) 逐个检查代理
        for cfg in PROXIES:
            port = cfg["port"]
            ip = cfg["ip"]
            old = old_results.get(port, {})
            last_ok_ts = old.get("last_ok_ts")
            reqs_today = hits_by_port.get(port, 0)

            item = check_single_proxy(port, ip, last_ok_ts=last_ok_ts, reqs_today=reqs_today)
            # 绑定 user 名称
            user_name = port_to_user.get(port)
            item["user"] = user_name
            new_results[port] = item

            # 聚合到用户统计
            if user_name:
                u = user_meta.setdefault(
                    user_name,
                    {"name": user_name, "ports": [], "reqs_today": 0, "online_ports": 0, "total_ports": 0},
                )
                if port not in u["ports"]:
                    u["ports"].append(port)
                u["reqs_today"] += reqs_today
                if item["online"]:
                    u["online_ports"] += 1

        # 补齐 total_ports
        for u in user_meta.values():
            if not u.get("total_ports"):
                u["total_ports"] = len(u.get("ports", []))
            u["ports"] = sorted(u.get("ports", []))

        RESULTS = new_results
        USER_SUMMARY = user_meta
        LAST_UPDATE_TS = time.time()

        time.sleep(CHECK_INTERVAL_SECONDS)


@app.route("/api/status")
def api_status():
    """
    返回所有代理状态 + 汇总（给前端用）
    """
    global RESULTS, LAST_UPDATE_TS, USER_SUMMARY
    if not RESULTS:
        # 首次访问时临时做一轮快速检查，避免空白
        hits_by_port, _ = load_log_hits()
        temp_results = {}
        for cfg in PROXIES:
            port = cfg["port"]
            ip = cfg["ip"]
            reqs_today = hits_by_port.get(port, 0)
            item = check_single_proxy(port, ip, last_ok_ts=None, reqs_today=reqs_today)
            temp_results[port] = item
        RESULTS = temp_results
        LAST_UPDATE_TS = time.time()

    data = list(sorted(RESULTS.values(), key=lambda x: x["port"]))
    summary = {
        "total": len(data),
        "online": sum(1 for d in data if d["online"]),
        "offline": sum(1 for d in data if not d["online"]),
        "mismatch": sum(1 for d in data if d.get("ip_mismatch")),
        "total_reqs_today": sum(d.get("reqs_today", 0) for d in data),
        "last_update": datetime.fromtimestamp(LAST_UPDATE_TS).strftime("%Y-%m-%d %H:%M:%S")
        if LAST_UPDATE_TS
        else None,
    }

    # 用户汇总（如果没有配置 users.json，则为空）
    users_list = []
    for u in USER_SUMMARY.values():
        users_list.append(
            {
                "name": u["name"],
                "ports": u.get("ports", []),
                "total_ports": u.get("total_ports", len(u.get("ports", []))),
                "online_ports": u.get("online_ports", 0),
                "reqs_today": u.get("reqs_today", 0),
            }
        )

    return jsonify({"summary": summary, "proxies": data, "users": users_list})


@app.route("/")
def index():
    """
    简单前端页面：表格 + 图表 + 用户汇总
    """
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Proxy Dashboard</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; margin: 20px; background: #f5f5f5; }
h2 { margin-bottom: 5px; }
small { color: #666; }
table { border-collapse: collapse; width: 100%; margin-top: 15px; background: #fff; }
th, td { border: 1px solid #ddd; padding: 6px 4px; text-align: center; font-size: 12px; }
th { background: #fafafa; }
.ok { background: #e7f9e7; }
.bad { background: #fde4e4; }
.warn { background: #fff7d6; }
.mono { font-family: monospace; }
#charts { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }
.chart-box { background:#fff; padding:10px; border:1px solid #ddd; border-radius:4px; flex:1 1 300px; }
#user-box { background:#fff; padding:10px; border:1px solid #ddd; border-radius:4px; margin-top:20px; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <h2>Proxy Dashboard</h2>
  <small>每 60 秒后端刷新一次健康状态 · 实时请求数来自 3proxy 日志</small>
  <div id="summary" style="margin-top:10px; font-size:13px;"></div>

  <table>
    <thead>
      <tr>
        <th>Port</th>
        <th>状态</th>
        <th>出口 IP (real / expected)</th>
        <th>延迟 (ms)</th>
        <th>当前连接数</th>
        <th>今日请求数</th>
        <th>绑定用户</th>
        <th>最近成功时间</th>
      </tr>
    </thead>
    <tbody id="tbody">
      <!-- JS 动态填充 -->
    </tbody>
  </table>

  <div id="charts">
    <div class="chart-box">
      <h4 style="margin:5px 0;">在线 / 离线 / IP 异常 统计</h4>
      <canvas id="onlineChart" height="180"></canvas>
    </div>
    <div class="chart-box">
      <h4 style="margin:5px 0;">前 20 个端口延迟</h4>
      <canvas id="latencyChart" height="180"></canvas>
    </div>
  </div>

  <div id="user-box">
    <h4 style="margin:5px 0;">按业务用户统计（来自 users.json）</h4>
    <table style="width:100%; margin-top:5px;">
      <thead>
        <tr>
          <th>用户名称</th>
          <th>绑定端口数量</th>
          <th>在线端口数量</th>
          <th>今日请求数</th>
          <th>端口列表</th>
        </tr>
      </thead>
      <tbody id="user-tbody"></tbody>
    </table>
  </div>

<script>
let onlineChart = null;
let latencyChart = null;

function cls(row) {
  if (!row.online) return "bad";
  if (row.ip_mismatch) return "warn";
  return "ok";
}

function formatPorts(ports) {
  if (!ports || ports.length === 0) return "-";
  if (ports.length <= 10) return ports.join(", ");
  return ports.slice(0, 10).join(", ") + " ... (" + ports.length + " ports)";
}

async function refresh() {
  try {
    const resp = await fetch('/api/status');
    const data = await resp.json();
    const summary = data.summary || {};
    const list = data.proxies || [];
    const users = data.users || [];

    // summary
    const sumDiv = document.getElementById('summary');
    sumDiv.innerText =
      `总数：${summary.total || 0} · 在线：${summary.online || 0} · 离线：${summary.offline || 0} · IP 异常：${summary.mismatch || 0} · 今日请求数：${summary.total_reqs_today || 0} · 最近更新：${summary.last_update || '-'}`;

    // 代理表格
    const tbody = document.getElementById('tbody');
    tbody.innerHTML = list.map(p => {
      const clsName = cls(p);
      const real = p.real_ip || '-';
      const exp = p.expected_ip || '-';
      const delay = (p.delay_ms !== null && p.delay_ms !== undefined) ? p.delay_ms : '-';
      const conn = (p.conn_count !== null && p.conn_count !== undefined) ? p.conn_count : 0;
      const reqs = (p.reqs_today !== null && p.reqs_today !== undefined) ? p.reqs_today : 0;
      const user = p.user || '-';
      const last = p.last_ok || '-';
      return `<tr class="${clsName}">
        <td class="mono">${p.port}</td>
        <td>${p.online ? '在线' : '离线'}</td>
        <td class="mono">${real} / ${exp}</td>
        <td>${delay}</td>
        <td>${conn}</td>
        <td>${reqs}</td>
        <td>${user}</td>
        <td>${last}</td>
      </tr>`;
    }).join('');

    // 用户表格
    const userBody = document.getElementById('user-tbody');
    userBody.innerHTML = users.map(u => {
      return `<tr>
        <td>${u.name}</td>
        <td>${u.total_ports}</td>
        <td>${u.online_ports}</td>
        <td>${u.reqs_today}</td>
        <td class="mono">${formatPorts(u.ports)}</td>
      </tr>`;
    }).join('');

    // 饼图数据
    const online = summary.online || 0;
    const offline = summary.offline || 0;
    const mismatch = summary.mismatch || 0;

    const onlineCtx = document.getElementById('onlineChart').getContext('2d');
    const latencyCtx = document.getElementById('latencyChart').getContext('2d');

    if (onlineChart) onlineChart.destroy();
    if (latencyChart) latencyChart.destroy();

    onlineChart = new Chart(onlineCtx, {
      type: 'pie',
      data: {
        labels: ['在线', '离线', 'IP 异常'],
        datasets: [{
          data: [online, offline, mismatch]
        }]
      }
    });

    // 延迟图：选前 20 个端口
    const top = list
      .filter(p => p.delay_ms !== null && p.delay_ms !== undefined)
      .sort((a, b) => a.port - b.port)
      .slice(0, 20);

    latencyChart = new Chart(latencyCtx, {
      type: 'bar',
      data: {
        labels: top.map(p => p.port),
        datasets: [{
          label: '延迟(ms)',
          data: top.map(p => p.delay_ms || 0)
        }]
      },
      options: {
        scales: {
          x: { title: { display: true, text: '端口' } },
          y: { title: { display: true, text: '延迟(ms)' }, beginAtZero: true }
        }
      }
    });

  } catch (e) {
    console.error(e);
    document.getElementById('summary').innerText = '加载失败：' + e;
  }
}

setInterval(refresh, 10000);
refresh();
</script>

</body>
</html>
"""


def start_background_thread():
    t = threading.Thread(target=background_worker, daemon=True)
    t.start()


if __name__ == "__main__":
    start_background_thread()
    app.run(host="0.0.0.0", port=5000)
