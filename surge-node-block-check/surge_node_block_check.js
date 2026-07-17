/**
 * Surge 节点阻断检测（信息面板版）
 *
 * 支持：
 * 1. 作为 [Panel] 动态信息面板显示检测结果；
 * 2. 在脚本列表手动运行时发送通知；
 * 3. argument 可填写策略组名称，也可填写具体节点名称。
 */

const CFG = {
  defaultTarget: "Proxy",
  ipApi: "https://api64.ipify.org?format=json",
  checkHost: "https://check-host.net",
  requestTimeout: 8,
  remoteNodes: 6,
  pollDelay: 3200,
  maxPolls: 3,
  maxDepth: 8,
};

let finished = false;

(async function main() {
  const panelMode = isPanelRun();
  const target = getArgument() || CFG.defaultTarget;
  if (!target) throw new Error("请在模块参数中填写策略组名称");

  const resolved = await resolvePolicy(target);
  const policy = resolved.policy;

  const detailResult = await surgeAPI(
    "GET",
    `/v1/policies/detail?policy_name=${encodeURIComponent(policy)}`
  );
  const detail = detailResult.ok ? detailResult.data : null;
  const endpoint = findEndpoint(detail);
  const protocol = findProtocol(detail);
  const udpLike = /(hysteria|tuic|wireguard|quic|udp)/i.test(protocol || "");

  const results = await Promise.all([
    checkExit(policy),
    checkExit("DIRECT"),
    endpoint && !udpLike
      ? checkRemote(endpoint.host, endpoint.port)
      : Promise.resolve({
          known: false,
          reason: udpLike
            ? "UDP/QUIC 节点不适用 TCP 远端探测"
            : "未能读取节点入口地址",
          items: [],
        }),
  ]);

  const node = results[0];
  const direct = results[1];
  const remote = results[2];
  const conclusion = diagnose(node, direct, remote);
  const displayName = policy || target;
  const report = buildReport({
    target,
    displayName,
    resolved,
    protocol,
    endpoint,
    node,
    direct,
    remote,
    conclusion,
  });

  if (panelMode) {
    finish({
      title: `${conclusion.panelPrefix} ${displayName}`,
      content: report.panelContent,
      icon: conclusion.icon,
      "icon-color": conclusion.color,
    });
    return;
  }

  const options = remote.url
    ? { action: "open-url", url: remote.url, sound: false }
    : undefined;

  $notification.post(
    "节点阻断检测",
    target === policy ? policy : `${target} → ${policy}`,
    report.fullContent,
    options
  );
  console.log(`[节点阻断检测]\n${report.fullContent}`);
  finish();
})().catch(function onError(error) {
  const message = errorText(error) || "未知错误";
  if (isPanelRun()) {
    finish({
      title: "节点阻断检测失败",
      content: `${message}\n点击右侧刷新按钮重试`,
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#FF3B30",
    });
    return;
  }

  $notification.post("节点阻断检测", "执行失败", message);
  console.log(`[节点阻断检测] ${message}`);
  finish();
});

function isPanelRun() {
  try {
    return (
      typeof $input !== "undefined" &&
      $input &&
      String($input.purpose || "") === "panel"
    );
  } catch (_) {
    return false;
  }
}

function getArgument() {
  try {
    if (typeof $intent !== "undefined" && $intent && $intent.parameter) {
      return normalizeArgument($intent.parameter);
    }
  } catch (_) {}

  try {
    if (typeof $argument !== "undefined" && $argument != null) {
      return normalizeArgument($argument);
    }
  } catch (_) {}

  return "";
}

function normalizeArgument(value) {
  const text = String(value == null ? "" : value).trim();
  if (!text) return "";
  const match = text.match(/(?:^|[,&;])\s*(?:GROUP|group)\s*=\s*([^,&;]+)/);
  return (match ? match[1] : text).trim();
}

async function resolvePolicy(name) {
  const chain = [];
  let current = name;

  for (let i = 0; i < CFG.maxDepth; i += 1) {
    chain.push(current);
    const result = await surgeAPI(
      "GET",
      `/v1/policy_groups/select?group_name=${encodeURIComponent(current)}`
    );
    const selected =
      result.ok &&
      result.data &&
      typeof result.data.policy === "string"
        ? result.data.policy.trim()
        : "";

    if (!selected || selected === current || chain.indexOf(selected) !== -1) break;
    current = selected;
  }

  return { policy: current, chain };
}

async function checkExit(policy) {
  const start = Date.now();
  const result = await request({
    url: `${CFG.ipApi}&_=${Date.now()}`,
    policy,
    timeout: CFG.requestTimeout,
    headers: {
      Accept: "application/json",
      "Cache-Control": "no-cache",
    },
  });

  if (!result.ok) {
    return {
      ok: false,
      error: result.error,
      latency: Date.now() - start,
    };
  }

  const json = parseJSON(result.data);
  const ip = json && typeof json.ip === "string" ? json.ip.trim() : "";
  if (!ip) {
    return {
      ok: false,
      error: "出口 IP 接口返回无效",
      latency: Date.now() - start,
    };
  }

  return {
    ok: true,
    ip,
    latency: Date.now() - start,
    country: utility("geoip", ip),
    asn: utility("ipasn", ip),
    aso: utility("ipaso", ip),
  };
}

async function checkRemote(host, port) {
  const target = hostPort(host, port);
  const submitURL = `${CFG.checkHost}/check-tcp?host=${encodeURIComponent(
    target
  )}&max_nodes=${CFG.remoteNodes}`;

  const submitted = await probe(submitURL);
  if (!submitted.ok) {
    return {
      known: false,
      reason: `远端服务不可用：${submitted.error}`,
      items: [],
    };
  }

  const task = parseJSON(submitted.data);
  if (!task || !task.ok || !task.request_id || !task.nodes) {
    return { known: false, reason: "远端任务提交失败", items: [] };
  }

  const names = Object.keys(task.nodes);
  let parsed = null;

  for (let i = 0; i < CFG.maxPolls; i += 1) {
    await sleep(i === 0 ? CFG.pollDelay : 1500);
    const result = await probe(
      `${CFG.checkHost}/check-result/${encodeURIComponent(task.request_id)}`
    );
    if (!result.ok) continue;

    parsed = parseRemote(names, task.nodes, parseJSON(result.data) || {});
    if (parsed.success > 0 || parsed.completed >= names.length) break;
  }

  if (!parsed || parsed.completed === 0) {
    return {
      known: false,
      reason: "远端探测尚未返回有效结果",
      items: parsed ? parsed.items : [],
      url: task.permanent_link || "",
    };
  }

  return {
    known: true,
    ok: parsed.success > 0,
    success: parsed.success,
    total: names.length,
    items: parsed.items,
    url: task.permanent_link || "",
  };
}

async function probe(url) {
  const direct = await request({
    url,
    policy: "DIRECT",
    timeout: CFG.requestTimeout,
    headers: { Accept: "application/json", "Cache-Control": "no-cache" },
  });
  if (direct.ok) return direct;

  const fallback = await request({
    url,
    timeout: CFG.requestTimeout,
    headers: { Accept: "application/json", "Cache-Control": "no-cache" },
  });
  if (fallback.ok) return fallback;

  return {
    ok: false,
    error: `${direct.error || "DIRECT 失败"}；规则路由重试：${
      fallback.error || "失败"
    }`,
  };
}

function parseRemote(names, nodeMap, data) {
  let success = 0;
  let completed = 0;
  const items = [];

  names.forEach(function parseOne(name) {
    const meta = Array.isArray(nodeMap[name]) ? nodeMap[name] : [];
    const code = meta[0] || "";
    const raw = data[name];
    let status = "pending";
    let latency = null;

    if (Array.isArray(raw) && raw.length > 0) {
      const first = Array.isArray(raw[0]) ? raw[0][0] : raw[0];
      completed += 1;
      if (first && typeof first.time === "number") {
        status = "success";
        latency = first.time * 1000;
        success += 1;
      } else {
        status = "failure";
      }
    } else if (raw !== null && typeof raw !== "undefined") {
      completed += 1;
      status = "failure";
    }

    items.push({ code, status, latency });
  });

  return { success, completed, items };
}

function diagnose(node, direct, remote) {
  if (!direct.ok) {
    return {
      title: "本机网络异常",
      note: "请先检查 Wi‑Fi、蜂窝网络、DNS 或其他 VPN。",
      panelPrefix: "🟠",
      icon: "wifi.exclamationmark",
      color: "#FF9500",
    };
  }

  if (node.ok) {
    return {
      title: "节点目前可以正常使用",
      note: remote.known && !remote.ok ? "入口可能限制了探测机 IP。" : "",
      panelPrefix: "🟢",
      icon: "checkmark.shield.fill",
      color: "#34C759",
    };
  }

  if (remote.known && remote.ok) {
    return {
      title: "疑似本地运营商/GFW 阻断",
      note: "密码、协议、TLS/SNI 或证书错误也可能出现相同结果。",
      panelPrefix: "🔴",
      icon: "bolt.horizontal.icloud.fill",
      color: "#FF3B30",
    };
  }

  if (remote.known && !remote.ok) {
    return {
      title: "节点入口疑似离线或端口未开放",
      note: "请检查服务进程、防火墙、安全组和监听端口。",
      panelPrefix: "🔴",
      icon: "xmark.icloud.fill",
      color: "#FF3B30",
    };
  }

  return {
    title: "节点不可用，暂时无法区分原因",
    note: "请稍后重试并核对节点参数。",
    panelPrefix: "⚪️",
    icon: "questionmark.diamond.fill",
    color: "#8E8E93",
  };
}

function buildReport(context) {
  const chain = context.resolved.chain.join(" → ");
  const panelLines = [];
  const fullLines = [];

  panelLines.push(`策略：${chain}`);
  panelLines.push(
    context.node.ok
      ? `出口：${context.node.ip}${formatLocation(context.node)}`
      : `出口：❌ ${short(context.node.error)}`
  );
  panelLines.push(
    `节点：${context.node.ok ? "✅" : "❌"} ${formatMs(context.node.latency)}  ` +
      `直连：${context.direct.ok ? "✅" : "❌"} ${formatMs(context.direct.latency)}`
  );
  panelLines.push(formatRemoteSummary(context.remote));
  panelLines.push(`结论：${context.conclusion.title}`);
  panelLines.push(`更新：${formatTime(new Date())}`);

  fullLines.push(`策略：${chain}`);
  if (context.protocol) fullLines.push(`协议：${context.protocol}`);
  if (context.endpoint) {
    fullLines.push(`入口：${hostPort(context.endpoint.host, context.endpoint.port)}`);
  }
  fullLines.push("");
  fullLines.push(formatExit("节点代理", context.node));
  fullLines.push(formatExit("本机直连", context.direct));
  fullLines.push(formatRemoteSummary(context.remote));
  if (context.remote.items && context.remote.items.length) {
    fullLines.push(context.remote.items.map(formatRemoteItem).join("  "));
  }
  fullLines.push("");
  fullLines.push(`结论：${context.conclusion.title}`);
  if (context.conclusion.note) fullLines.push(`提示：${context.conclusion.note}`);

  return {
    panelContent: panelLines.join("\n"),
    fullContent: fullLines.join("\n"),
  };
}

function formatLocation(result) {
  const values = [result.country, result.asn].filter(Boolean);
  return values.length ? ` · ${values.join(" ")}` : "";
}

function formatRemoteSummary(remote) {
  if (remote.known) {
    return `远端 TCP：${remote.ok ? "✅ 可达" : "❌ 不可达"}（${
      remote.success
    }/${remote.total}）`;
  }
  return `远端 TCP：⚪ ${remote.reason || "未确认"}`;
}

function formatExit(label, result) {
  if (!result.ok) return `${label}：❌ 不可达（${short(result.error)}）`;
  const detail = [
    result.ip,
    result.country,
    [result.asn, result.aso].filter(Boolean).join(" "),
    formatMs(result.latency),
  ].filter(Boolean);
  return `${label}：✅ 正常（${detail.join(" · ")}）`;
}

function formatRemoteItem(item) {
  const location = flag(item.code) || item.code || "🌐";
  if (item.status === "success") return `${location} ${formatMs(item.latency)}`;
  if (item.status === "failure") return `${location} 失败`;
  return `${location} 等待`;
}

function findEndpoint(root) {
  const seen = [];

  function walk(value, depth) {
    if (value == null || depth > 10) return null;

    if (typeof value === "object") {
      if (seen.indexOf(value) !== -1) return null;
      seen.push(value);
    }

    if (typeof value === "string") return parseEndpoint(value);

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        const found = walk(value[i], depth + 1);
        if (found) return found;
      }
      return null;
    }

    if (typeof value === "object") {
      const keys = Object.keys(value);
      const normalized = keys.map(function mapKey(key) {
        return { key, norm: normKey(key), value: value[key] };
      });
      const hostItem = normalized.find(function findHost(item) {
        return [
          "server",
          "serverhost",
          "serveraddress",
          "hostname",
          "host",
          "address",
          "remotehost",
          "proxyhost",
          "endpoint",
        ].indexOf(item.norm) !== -1;
      });
      const portItem = normalized.find(function findPort(item) {
        return [
          "port",
          "serverport",
          "remoteport",
          "proxyport",
          "endpointport",
        ].indexOf(item.norm) !== -1;
      });

      if (hostItem && portItem) {
        const host = cleanHost(hostItem.value);
        const port = cleanPort(portItem.value);
        if (host && port) return { host, port };
      }

      for (let i = 0; i < normalized.length; i += 1) {
        const found = walk(normalized[i].value, depth + 1);
        if (found) return found;
      }
    }

    return null;
  }

  return walk(root, 0);
}

function parseEndpoint(value) {
  const text = String(value || "").trim();
  const match = text.match(
    /(?:^|[=,\s/])(?:[^@,\s/]+@)?(\[[0-9a-f:]+\]|[a-z0-9._-]+)\s*[,=:]\s*(\d{1,5})(?:[,\s/]|$)/i
  );
  if (!match) return null;
  const host = cleanHost(match[1]);
  const port = cleanPort(match[2]);
  return host && port ? { host, port } : null;
}

function findProtocol(root) {
  const values = [];
  const seen = [];

  function walk(value, depth) {
    if (value == null || depth > 8) return;
    if (typeof value === "object") {
      if (seen.indexOf(value) !== -1) return;
      seen.push(value);
    }

    if (Array.isArray(value)) {
      value.forEach(function each(item) {
        walk(item, depth + 1);
      });
      return;
    }
    if (typeof value !== "object") return;

    Object.keys(value).forEach(function eachKey(key) {
      const item = value[key];
      if (
        ["type", "protocol", "proxytype", "policytype", "transport"].indexOf(
          normKey(key)
        ) !== -1 &&
        typeof item === "string"
      ) {
        values.push(item.trim());
      }
      walk(item, depth + 1);
    });
  }

  walk(root, 0);
  const known = /(hysteria|tuic|wireguard|snell|shadowsocks|trojan|vmess|vless|socks|https?|ssh|quic)/i;
  return values.find(function findKnown(item) {
    return known.test(item);
  }) || values[0] || "";
}

function surgeAPI(method, path, body) {
  return new Promise(function executor(resolve) {
    try {
      $httpAPI(method, path, body || {}, function callback(result) {
        if (result && result.error) {
          resolve({ ok: false, error: errorText(result.error), data: result });
        } else {
          resolve({ ok: true, data: result });
        }
      });
    } catch (error) {
      resolve({ ok: false, error: errorText(error) });
    }
  });
}

function request(options) {
  return new Promise(function executor(resolve) {
    try {
      $httpClient.get(options, function callback(error, response, data) {
        if (error) {
          resolve({ ok: false, error: errorText(error) });
          return;
        }
        const status = Number(response && response.status);
        if (Number.isFinite(status) && (status < 200 || status >= 300)) {
          resolve({ ok: false, error: `HTTP ${status}`, status, data });
          return;
        }
        resolve({ ok: true, status, data });
      });
    } catch (error) {
      resolve({ ok: false, error: errorText(error) });
    }
  });
}

function utility(name, ip) {
  try {
    return typeof $utils !== "undefined" && typeof $utils[name] === "function"
      ? String($utils[name](ip) || "")
      : "";
  } catch (_) {
    return "";
  }
}

function parseJSON(value) {
  if (value && typeof value === "object") return value;
  try {
    return JSON.parse(String(value || ""));
  } catch (_) {
    return null;
  }
}

function cleanHost(value) {
  return String(value == null ? "" : value)
    .trim()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/^['"]|['"]$/g, "");
}

function cleanPort(value) {
  const port = parseInt(String(value || ""), 10);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 0;
}

function hostPort(host, port) {
  const text = String(host || "").trim();
  return `${text.indexOf(":") !== -1 && text.charAt(0) !== "[" ? `[${text}]` : text}:${port}`;
}

function normKey(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function formatMs(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms)) return "--ms";
  return `${ms >= 100 ? ms.toFixed(0) : ms >= 10 ? ms.toFixed(1) : ms.toFixed(2)}ms`;
}

function formatTime(date) {
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  return `${hours}:${minutes}`;
}

function short(value) {
  const text = errorText(value).replace(/\s+/g, " ").trim();
  return text.length > 45 ? `${text.slice(0, 45)}…` : text || "未知错误";
}

function errorText(error) {
  if (!error) return "";
  if (typeof error === "string") return error;
  if (error.message) return String(error.message);
  try {
    return JSON.stringify(error);
  } catch (_) {
    return String(error);
  }
}

function flag(code) {
  const value = String(code || "").toUpperCase();
  if (!/^[A-Z]{2}$/.test(value)) return "";
  try {
    return String.fromCodePoint.apply(
      null,
      value.split("").map(function toPoint(char) {
        return 127397 + char.charCodeAt(0);
      })
    );
  } catch (_) {
    return value;
  }
}

function sleep(ms) {
  return new Promise(function executor(resolve) {
    setTimeout(resolve, ms);
  });
}

function finish(payload) {
  if (finished) return;
  finished = true;
  $done(payload);
}
