/**
 * Surge 节点阻断检测
 *
 * 配置：
 * 节点阻断检测 = type=generic,script-path=<RAW_URL>,argument=节点选择,timeout=35
 *
 * argument 可填写策略组名称，也可直接填写具体节点名称。
 */

const CFG = {
  defaultTarget: "节点选择",
  ipApi: "https://api64.ipify.org?format=json",
  checkHost: "https://check-host.net",
  requestTimeout: 8,
  remoteNodes: 6,
  pollDelay: 3200,
  maxPolls: 3,
  maxDepth: 8,
};

let finished = false;

(async () => {
  const target = getArgument() || CFG.defaultTarget;
  if (!target) throw new Error("请在脚本配置中添加 argument=策略组名称");

  const resolved = await resolvePolicy(target);
  const policy = resolved.policy;
  const detailRes = await surgeAPI(
    "GET",
    `/v1/policies/detail?policy_name=${encodeURIComponent(policy)}`
  );

  const detail = detailRes.ok ? detailRes.data : null;
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

  const lines = [];
  lines.push(`策略：${resolved.chain.join(" → ")}`);
  if (protocol) lines.push(`协议：${protocol}`);
  if (endpoint) lines.push(`入口：${hostPort(endpoint.host, endpoint.port)}`);
  lines.push("");
  lines.push(formatExit("节点代理", node));
  lines.push(formatExit("本机直连", direct));

  if (remote.known) {
    lines.push(
      `远端 TCP：${remote.ok ? "✅ 可达" : "❌ 不可达"}（${remote.success}/${remote.total}）`
    );
  } else {
    lines.push(`远端 TCP：⚪ 未确认（${remote.reason || "无有效结果"}）`);
  }

  if (remote.items && remote.items.length) {
    lines.push(remote.items.map(formatRemoteItem).join("  "));
  }

  lines.push("");
  lines.push(`结论：${conclusion.title}`);
  if (conclusion.note) lines.push(`提示：${conclusion.note}`);

  const body = lines.join("\n");
  const options = remote.url
    ? { action: "open-url", url: remote.url, sound: false }
    : undefined;

  $notification.post(
    "节点阻断检测",
    target === policy ? policy : `${target} → ${policy}`,
    body,
    options
  );
  console.log(`[节点阻断检测]\n${body}`);
})()
  .catch((error) => {
    const message = errorText(error) || "未知错误";
    $notification.post("节点阻断检测", "执行失败", message);
    console.log(`[节点阻断检测] ${message}`);
  })
  .finally(done);

function getArgument() {
  try {
    if (typeof $intent !== "undefined" && $intent && $intent.parameter) {
      return String($intent.parameter).trim();
    }
  } catch (_) {}

  try {
    if (typeof $argument !== "undefined" && $argument != null) {
      return String($argument).trim();
    }
  } catch (_) {}

  return "";
}

async function resolvePolicy(name) {
  const chain = [];
  let current = name;

  for (let i = 0; i < CFG.maxDepth; i += 1) {
    chain.push(current);
    const res = await surgeAPI(
      "GET",
      `/v1/policy_groups/select?group_name=${encodeURIComponent(current)}`
    );
    const selected =
      res.ok && res.data && typeof res.data.policy === "string"
        ? res.data.policy.trim()
        : "";

    if (!selected || selected === current || chain.includes(selected)) break;
    current = selected;
  }

  return { policy: current, chain };
}

async function checkExit(policy) {
  const start = Date.now();
  const res = await request({
    url: `${CFG.ipApi}&_=${Date.now()}`,
    policy,
    timeout: CFG.requestTimeout,
    headers: { Accept: "application/json", "Cache-Control": "no-cache" },
  });

  if (!res.ok) {
    return { ok: false, error: res.error, latency: Date.now() - start };
  }

  const json = parseJSON(res.data);
  const ip = json && typeof json.ip === "string" ? json.ip.trim() : "";
  if (!ip) {
    return { ok: false, error: "出口 IP 接口返回无效", latency: Date.now() - start };
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
    return { known: false, reason: `远端服务不可用：${submitted.error}`, items: [] };
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

  names.forEach((name) => {
    const meta = Array.isArray(nodeMap[name]) ? nodeMap[name] : [];
    const code = meta[0] || "";
    const raw = data[name];
    let status = "pending";
    let latency = null;

    if (Array.isArray(raw) && raw[0]) {
      completed += 1;
      if (typeof raw[0].time === "number") {
        status = "success";
        latency = raw[0].time * 1000;
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
      title: "⚠️ 本机直连网络异常",
      note: "先检查 Wi‑Fi/蜂窝、DNS 或其他 VPN，再重新检测。",
    };
  }

  if (node.ok) {
    return {
      title: "✅ 节点目前可以正常使用",
      note: remote.known && !remote.ok ? "入口可能限制了探测机 IP。" : "",
    };
  }

  if (remote.known && remote.ok) {
    return {
      title: "🛑 疑似本地运营商/GFW 阻断",
      note: "密码、协议、TLS/SNI 或证书配置错误也可能出现相同结果。",
    };
  }

  if (remote.known && !remote.ok) {
    return {
      title: "❌ 节点入口疑似离线或端口未开放",
      note: "检查服务进程、防火墙、安全组和监听端口。",
    };
  }

  return {
    title: "❓ 节点不可用，但暂时无法区分原因",
    note: "稍后重试，并核对节点参数。",
  };
}

function formatExit(label, result) {
  if (!result.ok) return `${label}：❌ 不可达（${short(result.error)}）`;
  const detail = [result.ip, result.country, [result.asn, result.aso].filter(Boolean).join(" ")]
    .filter(Boolean)
    .concat(formatMs(result.latency));
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
      if (seen.includes(value)) return null;
      seen.push(value);
    }

    if (typeof value === "string") return parseEndpoint(value);

    if (Array.isArray(value)) {
      for (const item of value) {
        const result = walk(item, depth + 1);
        if (result) return result;
      }
      return null;
    }

    if (typeof value === "object") {
      const keys = Object.keys(value);
      const normalized = keys.map((key) => ({ key, norm: normKey(key), value: value[key] }));
      const hostItem = normalized.find((item) =>
        ["server", "serverhost", "serveraddress", "hostname", "host", "address", "remotehost", "proxyhost", "endpoint"].includes(item.norm)
      );
      const portItem = normalized.find((item) =>
        ["port", "serverport", "remoteport", "proxyport", "endpointport"].includes(item.norm)
      );

      if (hostItem && portItem) {
        const host = cleanHost(hostItem.value);
        const port = cleanPort(portItem.value);
        if (host && port) return { host, port };
      }

      for (const item of normalized) {
        const result = walk(item.value, depth + 1);
        if (result) return result;
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
      if (seen.includes(value)) return;
      seen.push(value);
    }

    if (Array.isArray(value)) return value.forEach((item) => walk(item, depth + 1));
    if (typeof value !== "object") return;

    Object.keys(value).forEach((key) => {
      const item = value[key];
      if (
        ["type", "protocol", "proxytype", "policytype", "transport"].includes(normKey(key)) &&
        typeof item === "string"
      ) {
        values.push(item.trim());
      }
      walk(item, depth + 1);
    });
  }

  walk(root, 0);
  const known = /(hysteria|tuic|wireguard|snell|shadowsocks|trojan|vmess|vless|socks|https?|ssh|quic)/i;
  return values.find((item) => known.test(item)) || values[0] || "";
}

function surgeAPI(method, path, body) {
  return new Promise((resolve) => {
    try {
      $httpAPI(method, path, body || {}, (result) => {
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
  return new Promise((resolve) => {
    try {
      $httpClient.get(options, (error, response, data) => {
        if (error) return resolve({ ok: false, error: errorText(error) });
        const status = Number(response && response.status);
        if (Number.isFinite(status) && (status < 200 || status >= 300)) {
          return resolve({ ok: false, error: `HTTP ${status}`, status, data });
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
  return `${text.includes(":") && !text.startsWith("[") ? `[${text}]` : text}:${port}`;
}

function normKey(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function formatMs(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms)) return "--ms";
  return `${ms >= 100 ? ms.toFixed(0) : ms >= 10 ? ms.toFixed(1) : ms.toFixed(2)}ms`;
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
    return String.fromCodePoint(...value.split("").map((char) => 127397 + char.charCodeAt(0)));
  } catch (_) {
    return value;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function done() {
  if (finished) return;
  finished = true;
  $done();
}
