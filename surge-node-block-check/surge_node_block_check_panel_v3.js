/**
 * Surge 节点检测面板 V3
 * 精简显示，修复将具体节点名直接作为 policy 导致的 “Policy doesn't exist” 问题。
 */

const DEFAULT_GROUP = "Proxy";
const IP_API = "https://api64.ipify.org?format=json";
const TIMEOUT = 8;
const MAX_DEPTH = 8;

let finished = false;

(async function main() {
  const panelMode = isPanelRun();
  const group = getTarget() || DEFAULT_GROUP;
  const resolved = await resolveSelected(group);
  const nodeName = resolved.policy || group;

  // 必须使用策略组名称发起请求，让 Surge 自动走该组当前所选节点。
  // 直接把叶子节点名称传给 policy，部分 Surge 版本会报 Policy doesn't exist。
  const [proxyResult, directResult] = await Promise.all([
    checkExit(group),
    checkExit("DIRECT"),
  ]);

  const result = buildResult(nodeName, proxyResult, directResult);

  if (panelMode) {
    finish({
      title: result.title,
      content: result.content,
      icon: result.icon,
      "icon-color": result.color,
    });
    return;
  }

  $notification.post("节点检测", nodeName, result.content);
  console.log(`[节点检测] ${nodeName}\n${result.content}`);
  finish();
})().catch(function onError(error) {
  const message = shortError(error);
  if (isPanelRun()) {
    finish({
      title: "节点检测失败",
      content: `错误：${message}\n点击右侧刷新按钮重试`,
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#FF3B30",
    });
    return;
  }

  $notification.post("节点检测", "执行失败", message);
  finish();
});

function buildResult(nodeName, proxy, direct) {
  if (proxy.ok) {
    const lines = [`出口 IP：${proxy.ip}`];
    const location = [proxy.country, proxy.asn].filter(Boolean).join(" · ");
    if (location) lines.push(`位置网络：${location}`);
    if (proxy.aso) lines.push(`运营商：${proxy.aso}`);
    lines.push(`状态：✅ 节点可用 · ${formatMs(proxy.latency)}`);

    return {
      title: `✅ ${nodeName}`,
      content: lines.join("\n"),
      icon: "checkmark.shield.fill",
      color: "#34C759",
    };
  }

  if (!direct.ok) {
    return {
      title: `🟠 ${nodeName}`,
      content: [
        "状态：本机网络异常",
        "请检查 Wi‑Fi、蜂窝网络或其他 VPN",
        `错误：${shortError(direct.error || proxy.error)}`,
      ].join("\n"),
      icon: "wifi.exclamationmark",
      color: "#FF9500",
    };
  }

  return {
    title: `🔴 ${nodeName}`,
    content: [
      "状态：❌ 节点不可用",
      "诊断：疑似线路阻断或节点配置异常",
      `错误：${shortError(proxy.error)}`,
    ].join("\n"),
    icon: "bolt.horizontal.icloud.fill",
    color: "#FF3B30",
  };
}

async function resolveSelected(name) {
  const chain = [];
  let current = name;

  for (let i = 0; i < MAX_DEPTH; i += 1) {
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
  const startedAt = Date.now();
  const result = await request({
    url: `${IP_API}&_=${Date.now()}`,
    policy,
    timeout: TIMEOUT,
    headers: {
      Accept: "application/json",
      "Cache-Control": "no-cache",
    },
  });

  if (!result.ok) {
    return {
      ok: false,
      error: result.error,
      latency: Date.now() - startedAt,
    };
  }

  const json = parseJSON(result.data);
  const ip = json && typeof json.ip === "string" ? json.ip.trim() : "";
  if (!ip) {
    return {
      ok: false,
      error: "出口 IP 接口返回无效",
      latency: Date.now() - startedAt,
    };
  }

  return {
    ok: true,
    ip,
    latency: Date.now() - startedAt,
    country: utility("geoip", ip),
    asn: utility("ipasn", ip),
    aso: utility("ipaso", ip),
  };
}

function request(options) {
  return new Promise((resolve) => {
    try {
      $httpClient.get(options, (error, response, data) => {
        if (error) {
          resolve({ ok: false, error: errorText(error) });
          return;
        }

        const status = Number(response && response.status);
        if (Number.isFinite(status) && (status < 200 || status >= 300)) {
          resolve({ ok: false, error: `HTTP ${status}` });
          return;
        }

        resolve({ ok: true, data });
      });
    } catch (error) {
      resolve({ ok: false, error: errorText(error) });
    }
  });
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

function getTarget() {
  try {
    if (typeof $argument !== "undefined" && $argument != null) {
      const text = String($argument).trim();
      const match = text.match(/(?:^|[,&;])\s*(?:GROUP|group)\s*=\s*([^,&;]+)/);
      return (match ? match[1] : text).trim();
    }
  } catch (_) {}

  return "";
}

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

function formatMs(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms)) return "--ms";
  return `${Math.max(0, Math.round(ms))}ms`;
}

function shortError(value) {
  const text = errorText(value).replace(/\s+/g, " ").trim() || "未知错误";
  return text.length > 55 ? `${text.slice(0, 55)}…` : text;
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

function finish(payload) {
  if (finished) return;
  finished = true;
  $done(payload);
}
