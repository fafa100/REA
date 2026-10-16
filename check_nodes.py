#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate SSTP 节点检测流水线 —— 高容错入口
=========================================
直接复用 vpngate.py 里的解析/筛选/渲染能力, 只重写「容易全链路崩掉」的三段:

  1. 数据源获取   : 官方 CSV(http/https 双协议) -> GitHub 预解析镜像(可多个) -> 逐个尝试,
                    任意一个成功即可继续, 全挂才判定失败。
  2. 检测服务     : 支持多个 Cloudflare Worker 端点, 运行前先做存活性探测, 逐个回退;
                    Worker 全部不可用时自动降级为「runner 本地 TCP 直连探测」,
                    (结果标记 probe=local-tcp, data.json 里 degraded=true), 不再整条流水线 exit 1。
  3. 结果产出     : 只要有节点数据就一定写出 public/*, 保证 GitHub Pages 每次都能更新。

环境变量:
  CHECK_WORKERS        逗号分隔的 Worker 端点列表(优先级按书写顺序, 第一个存活的胜出)
  CHECK_WORKER         兼容旧参数(单个端点)
  CHECK_CONCURRENCY    检测并发 (默认 32)
  CHECK_TIMEOUT        单个 Worker 请求超时秒 (默认 60)
  LOCAL_PROBE          Worker 全挂时是否降级为本地 TCP 探测 (默认 1)
  LOCAL_PROBE_TIMEOUT  本地 TCP 探测超时秒 (默认 8)
  LOCAL_PROBE_WORKERS  本地 TCP 探测并发 (默认 96)
  VPNGATE_SOURCES      逗号分隔的官方 CSV 源
  VPNGATE_MIRRORS      逗号分隔的镜像 JSON 源
  MAX_CHECK_NODES      限制检测节点数 (0=不限, 本地调试用)
  HTTP_TIMEOUT         拉取数据源超时 (默认 60)
  STRICT               设为 1 时恢复"严格模式": Worker 全挂不再降级, 直接判定失败退出 1
"""

import json
import os
import socket
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

import requests

import vpngate as V

# 控制台编码兜底 (Windows GBK 控制台也不崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "60"))
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
STRICT = os.environ.get("STRICT", "0") == "1"
LOCAL_PROBE = os.environ.get("LOCAL_PROBE", "1") == "1"
LOCAL_PROBE_TIMEOUT = float(os.environ.get("LOCAL_PROBE_TIMEOUT", "8"))
LOCAL_PROBE_WORKERS = max(1, int(os.environ.get("LOCAL_PROBE_WORKERS", "96")))

# 与原脚本保持一致的运行参数
V.CHECK_TIMEOUT = CHECK_TIMEOUT
V.CONCURRENCY = CONCURRENCY
V.MAX_CHECK_NODES = MAX_CHECK_NODES
V.HTTP_TIMEOUT = HTTP_TIMEOUT

UA = {"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"}


def fatal(msg, code=1):
    V.log("FATAL", "[失败] " + msg)
    sys.exit(code)


# ---------------------------------------------------------------------------
# 第 1 步: 数据源 (官方 CSV -> 镜像 JSON, 多源回退)
# ---------------------------------------------------------------------------
def _csv_sources():
    srcs = [u.strip() for u in os.environ.get(
        "VPNGATE_SOURCES",
        ",".join([V.VPNGATE_API, "https://www.vpngate.net/api/iphone/"]),
    ).split(",") if u.strip()]
    out = []
    for u in srcs:
        if u not in out:
            out.append(u)
    return out


def _mirror_sources():
    mirrors = [u.strip() for u in os.environ.get(
        "VPNGATE_MIRRORS", V.VPNGATE_MIRROR).split(",") if u.strip()]
    out = []
    for u in mirrors:
        if u not in out:
            out.append(u)
    return out


def fetch_rows(session):
    """返回 (rows, source)。任意一个数据源成功即可; 全部失败返回 (None, None)。"""
    for url in _csv_sources():
        try:
            V.log("数据源", f"拉取官方 CSV: {url}")
            resp = session.get(url, timeout=HTTP_TIMEOUT, headers=UA)
            if resp.status_code != 200:
                V.log("数据源", f"  -> HTTP {resp.status_code}")
                continue
            rows = V.parse_csv(resp.text)
            if rows:
                V.log("数据源", f"  -> 成功, {len(rows)} 行")
                return rows, url
            V.log("数据源", "  -> 返回 0 行, 换下一个源")
        except Exception as exc:
            V.log("数据源", f"  -> 异常 {type(exc).__name__}: {exc}")

    for url in _mirror_sources():
        try:
            V.log("数据源", f"拉取镜像 JSON: {url}")
            resp = session.get(url, timeout=HTTP_TIMEOUT, headers=UA)
            if resp.status_code != 200:
                V.log("数据源", f"  -> HTTP {resp.status_code}")
                continue
            rows = V.parse_mirror_json(resp.json())
            if rows:
                V.log("数据源", f"  -> 成功, {len(rows)} 行")
                return rows, url
            V.log("数据源", "  -> 返回 0 行, 换下一个源")
        except Exception as exc:
            V.log("数据源", f"  -> 异常 {type(exc).__name__}: {exc}")

    return None, None


# ---------------------------------------------------------------------------
# 第 2 步: 检测服务 (多 Worker 探测 + 回退)
# ---------------------------------------------------------------------------
def _worker_list():
    raw = os.environ.get("CHECK_WORKERS") or os.environ.get("CHECK_WORKER") or V.WORKER_CHECK_URL
    out = []
    for u in raw.split(","):
        u = u.strip()
        if u and u not in out:
            out.append(u)
    return out


def probe_worker(session, url):
    """判断某个 Worker 端点是否存活 (<500 一律视为服务在线)。"""
    try:
        r = session.get(url + quote("127.0.0.1:1", safe=""), timeout=min(CHECK_TIMEOUT, 20), headers=UA)
        if r.status_code < 500:
            return True, f"HTTP {r.status_code}"
        return False, f"HTTP {r.status_code}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def pick_worker(session):
    """按优先级返回第一个存活的 Worker; 全挂返回 None。"""
    for url in _worker_list():
        ok, why = probe_worker(session, url)
        if ok:
            V.log("检测服务", f"端点可用: {url}  ({why})")
            return url
        V.log("检测服务", f"端点不可用: {url}  ({why})")
    return None


def run_worker_check(nodes, session, worker):
    """用指定 Worker 跑一轮并发检测。"""
    V.WORKER_CHECK_URL = worker
    results = V.check_all(nodes, session)
    ok = [r for r in results if r.get("success")]
    for r in results:
        r["probe"] = "worker"
    return results, len(ok)


# ---------------------------------------------------------------------------
# 第 3 步: 降级 —— runner 本地 TCP 直连探测
# ---------------------------------------------------------------------------
def _tcp_one(node):
    out = dict(node)
    out.update({
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{node['host']}:{node['port']}",
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "exit": None,
        "residential": V.classify_network(node["host"], None, None),
        "probe": "local-tcp",
        "worker_error": False,
    })
    t0 = time.time()
    try:
        with socket.create_connection((node["host"], node["port"]), timeout=LOCAL_PROBE_TIMEOUT):
            out["success"] = True
            out["status"] = "success"
            out["latency_ms"] = int((time.time() - t0) * 1000)
            out["error"] = None
    except Exception as exc:
        out["success"] = False
        out["status"] = "failed"
        out["latency_ms"] = None
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def local_tcp_check(nodes):
    results = []
    with ThreadPoolExecutor(max_workers=LOCAL_PROBE_WORKERS) as pool:
        futs = [pool.submit(_tcp_one, n) for n in nodes]
        for fut in as_completed(futs):
            results.append(fut.result())
    return results


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()

    # 1) 数据源
    rows, source = fetch_rows(session)
    if not rows:
        fatal("所有数据源均不可用 (官方 CSV + 全部镜像), 本次不产出结果")

    # 2) SSTP 筛选 + 去重
    nodes = V.dedupe(V.to_sstp_nodes(rows))
    if not nodes:
        fatal(f"从 {len(rows)} 行原始数据中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化")
    if MAX_CHECK_NODES > 0:
        nodes = nodes[:MAX_CHECK_NODES]
    V.log("节点", f"原始 {len(rows)} 行 -> SSTP 候选(去重后) {len(nodes)} 个")

    # 3) 检测
    results = []
    worker = pick_worker(session)
    worker_errors = 0

    if worker:
        results, okc = run_worker_check(nodes, session, worker)
        worker_errors = len([r for r in results if r.get("worker_error")])
        V.log("检测服务", f"Worker 检测完成: 成功 {okc} / 共 {len(results)} "
                         f"(请求级异常 {worker_errors})")

        # Worker 中途暴毙 (一个成功都没有且全部请求级异常) -> 换下一个端点重试
        if okc == 0 and worker_errors == len(results):
            others = [u for u in _worker_list() if u != worker]
            for alt in others:
                V.log("检测服务", f"首个端点异常率高, 切换备用端点: {alt}")
                ok2, why2 = probe_worker(session, alt)
                if not ok2:
                    V.log("检测服务", f"  -> 不可用 ({why2})")
                    continue
                res2, okc2 = run_worker_check(nodes, session, alt)
                V.log("检测服务", f"  -> 重试结果: 成功 {okc2} / 共 {len(res2)}")
                if okc2 > 0 or len([r for r in res2 if r.get("worker_error")]) < len(res2):
                    worker, results = alt, res2
                    break

    # 4) 降级: Worker 全不可用 -> runner 本地 TCP 直连
    degraded = False
    if not results or (len([r for r in results if r.get("success")]) == 0
                       and len([r for r in results if r.get("worker_error")]) == len(results)):
        if not LOCAL_PROBE or STRICT:
            fatal("检测服务全部不可用且未开启本地降级 (LOCAL_PROBE=1 可降级继续), "
                  "按严格模式判定本次运行失败")
        V.log("检测服务", "Worker 全部不可用 -> 降级为 runner 本地 TCP 直连探测")
        worker = None
        results = local_tcp_check(nodes)
        degraded = True

    success = [r for r in results if r.get("success")]
    V.log("结果", f"可用节点 {len(success)} / 检测 {len(results)}"
                 + ("  (降级模式: 本地 TCP 探测)" if degraded else ""))

    # 5) 产出 + 写盘
    data = V.build_outputs(results, len(rows), len(nodes), source)
    data["worker"] = worker
    data["degraded"] = degraded
    if not degraded and worker:
        data["probe"] = "worker"
    else:
        data["probe"] = "local-tcp" if degraded else "none"
    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    paths = V.write_outputs(data)
    for p in paths:
        V.log("产出", os.path.relpath(p, V.REPO_DIR))
    V.log("产出", "完成 (GitHub Pages 由 workflow 部署)")

    # 结果摘要, 便于在 Actions 日志里一眼看清
    V.log("摘要", json.dumps(data["stats"], ensure_ascii=False))
    if degraded:
        V.log("提醒", "本次为降级模式: Worker 不可用, 页面数据来自 runner 本地 TCP 探测, "
                     "可用于初筛但不等同于 Worker 的实际转发验证")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        traceback.print_exc()
        fatal(f"程序异常: {type(exc).__name__}: {exc}")
