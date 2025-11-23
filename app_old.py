from flask import Flask, jsonify
import subprocess
import time
import requests
import threading
from datetime import datetime

app = Flask(__name__)

# 生成 254 个代理配置：30000-30253 对应 31.58.239.1-31.58.239.254
PROXIES = [
    {"port": port, "ip": f"31.58.239.{port - 29999}"}
    for port in range(30000, 30254)
]

# 全局缓存：后台线程会定时刷新
RESULTS = {}
LAST_UPDATE_TS = 0

CHECK_INTERVAL_SECONDS = 60  # 后台健康检查间隔（秒）


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


def check_single_proxy(port: int, ip: str, last_ok_ts: float | None = None):
    """
    通过 ipinfo.io 测试代理：
    - 成功：返回 online=True, delay_ms, real_ip, last_ok_ts
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
    }

    # 简单盗用检测：出口 IP 和预期不一致
    item["ip_mismatch"] = bool(real_ip and real_ip != ip)

    return item


def background_worker():
    """
    后台线程：循环检查全部 254 个代理，结果写入 RESULTS
    """
    global RESULTS, LAST_UPDATE_TS
    while True:
        new_results = {}
        old_results = RESULTS.copy()
        for cfg in PROXIES:
            port = cfg["port"]
            ip = cfg["ip"]
            old = old_results.get(port, {})
            last_ok_ts = old.get("last_ok_ts")
            item = check_single_proxy(port, ip, last_ok_ts=last_ok_ts)
            new_results[port] = item
        RESULTS = new_results
        LAST_UPDATE_TS = time.time()
        time.sleep(CHECK_INTERVAL_SECONDS)


@app.route("/api/status")
def api_status():
    """
    返回所有代理状态（给前端用）
    """
    global RESULTS, LAST_UPDATE_TS
    if not RESULTS:
        temp_results = {}
        for cfg in PROXIES:
            port = cfg["port"]
            ip = cfg["ip"]
            item = check_single_proxy(port, ip)
            temp_results[port] = item
        RESULTS = temp_results
        LAST_UPDATE_TS = time.time()

    data = list(sorted(RESULTS.values(), key=lambda x: x["port"]))
    summary = {
        "total": len(data),
        "online": sum(1 for d in data if d["online"]),
        "offline": sum(1 for d in data if not d["online"]),
        "mismatch": sum(1 for d in data if d.get("ip_mismatch")),
        "last_update": datetime.fromtimestamp(LAST_UPDATE_TS).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        if LAST_UPDATE_TS
        else None,
    }
    return jsonify({"summary": summary, "proxies": data})


@app.route("/")
def index():
    """
    简单前端页面：表格 + 图表
    """
    return """
<!DOCTYPE html>
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
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <h2>Proxy Dashboard</h2>
  <small>每 10 秒刷新一次健康状态 · 数据来源：ipinfo.io + 本机 ss</small>
  <div id="summary" style="margin-top:10px; font-size:13px;"></div>

  <table>
    <thead>
      <tr>
        <th>Port</th>
        <th>状态</th>
        <th>出口 IP (real / expected)</th>
        <th>延迟 (ms)</th>
        <th>当前连接数</th>
        <th>最近成功时间</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>

  <div id="charts">
    <div class="chart-box">
      <h4 style="margin:5px 0;">在线 / 离线 统计</h4>
      <canvas id="onlineChart" height="180"></canvas>
    </div>
    <div class="chart-box">
      <h4 style="margin:5px 0;">前 20 个端口延迟</h4>
      <canvas id="latencyChart" height="180"></canvas>
    </div>
  </div>

  <script>
  async function refresh() {
      const res = await fetch('/api/status');
      const data = await res.json();

      document.getElementById('summary').innerHTML =
          `总数：${data.summary.total} · 在线：${data.summary.online} · 离线：${data.summary.offline} · IP 异常：${data.summary.mismatch} · 最近更新：${data.summary.last_update}`;

      const tbody = document.getElementById('tbody');
      tbody.innerHTML = '';

      data.proxies.forEach(p=>{
          let cls = p.online ? 'ok' : 'bad';
          if (p.ip_mismatch) cls = 'warn';
          tbody.innerHTML += `
            <tr class="${cls}">
              <td>${p.port}</td>
              <td>${p.online?'在线':'离线'}</td>
              <td>${p.real_ip || '-'} / ${p.expected_ip}</td>
              <td>${p.delay_ms || '-'}</td>
              <td>${p.conn_count}</td>
              <td>${p.last_ok || '-'}</td>
            </tr>
          `;
      });

      // 在线/离线饼图
      updateOnlineChart(data.summary.online, data.summary.offline);

      // 延迟前 20
      const top20 = data.proxies.slice(0,20);
      updateLatencyChart(
        top20.map(x=>x.port),
        top20.map(x=>x.delay_ms || 0)
      );
  }

  let onlineChart, latencyChart;

  function updateOnlineChart(online, offline) {
      const ctx = document.getElementById('onlineChart').getContext('2d');
      if (onlineChart) onlineChart.destroy();
      onlineChart = new Chart(ctx, {
          type: 'pie',
          data: {
              labels: ['在线', '离线'],
              datasets: [{
                  data: [online, offline]
              }]
          }
      });
  }

  function updateLatencyChart(ports, delays) {
      const ctx = document.getElementById('latencyChart').getContext('2d');
      if (latencyChart) latencyChart.destroy();
      latencyChart = new Chart(ctx, {
          type: 'bar',
          data: {
              labels: ports,
              datasets: [{
                  label: '延迟(ms)',
                  data: delays
              }]
          }
      });
  }

  setInterval(refresh, 10000);
  refresh();
  </script>
</body>
</html>
    """


def start_background():
    t = threading.Thread(target=background_worker, daemon=True)
    t.start()


if __name__ == "__main__":
    start_background()
    app.run(host="0.0.0.0", port=5000)
