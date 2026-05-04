const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { randomUUID } = require("node:crypto");

const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 8787);
const STORE_LIMIT = clampNumber(process.env.OTP_STORE_LIMIT, 500, 1, 5000);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const ROOT_DIR = path.resolve(__dirname, "..");
const DATA_DIR = path.join(ROOT_DIR, "data");
const DATA_FILE = path.resolve(process.env.OTP_DATA_FILE || path.join(DATA_DIR, "otp-store.json"));
const DASHBOARD_FILE = path.join(ROOT_DIR, "public", "index.html");

const OTP_PATTERNS = [
  /(?:\u9A8C\u8BC1\u7801|\u9A57\u8B49\u78BC|\u6821\u9A8C\u7801|\u6821\u9A57\u78BC|\u52A8\u6001\u7801|\u52D5\u614B\u78BC|\u8BA4\u8BC1\u7801|\u8A8D\u8B49\u78BC|verification\s*code|verify\s*code|security\s*code|login\s*code|otp|passcode|one[-\s]*time\s*(?:password|passcode|pin))(?:\s*(?:is|:|=|-|\u662F|\u4E3A|\uFF1A))?\s*([a-zA-Z0-9][a-zA-Z0-9\s-]{3,11})/i,
  /(?<!\d)(\d(?:[\s-]?\d){3,7})(?!\d)/,
  /(?<![a-zA-Z0-9])([a-zA-Z0-9]{4,8})(?![a-zA-Z0-9])/i
];

ensureStoreFile();

const state = loadStore();

const server = http.createServer(async (req, res) => {
  try {
    setCorsHeaders(res);

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    const pathname = url.pathname;

    if (req.method === "GET" && pathname === "/") {
      sendFile(res, DASHBOARD_FILE, "text/html; charset=utf-8");
      return;
    }

    if (req.method === "GET" && pathname === "/api/health") {
      sendJson(res, 200, {
        ok: true,
        service: "waenhancerx-otp-server",
        port: PORT,
        stored: state.records.length,
        updatedAt: state.updatedAt
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/otp/webhook") {
      const body = await readJsonBody(req);
      const record = buildRecord(body);

      if (!record) {
        sendJson(res, 400, {
          ok: false,
          error: "A valid code or message containing a code is required."
        });
        return;
      }

      const storedRecord = upsertRecord(record);
      sendJson(res, 201, {
        ok: true,
        record: storedRecord
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/otp/latest") {
      const filtered = filterRecords(url.searchParams);
      const record = filtered[0];

      if (!record) {
        sendJson(res, 404, {
          ok: false,
          error: "No matching OTP found."
        });
        return;
      }

      sendJson(res, 200, {
        ok: true,
        record
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/otp/latest.txt") {
      const filtered = filterRecords(url.searchParams);
      const record = filtered[0];

      if (!record) {
        sendText(res, 404, "No matching OTP found.");
        return;
      }

      sendText(res, 200, record.code);
      return;
    }

    if (req.method === "GET" && pathname === "/api/otps") {
      const items = filterRecords(url.searchParams);
      sendJson(res, 200, {
        ok: true,
        total: state.records.length,
        count: items.length,
        items
      });
      return;
    }

    if (pathname === "/favicon.ico") {
      res.writeHead(204);
      res.end();
      return;
    }

    sendJson(res, 404, {
      ok: false,
      error: "Not found."
    });
  } catch (error) {
    console.error("[otp-server] request error:", error);
    sendJson(res, 500, {
      ok: false,
      error: "Internal server error."
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[otp-server] listening on http://${HOST}:${PORT}`);
  console.log(`[otp-server] data file: ${DATA_FILE}`);
});

function setCorsHeaders(res) {
  res.setHeader("Access-Control-Allow-Origin", CORS_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8"
  });
  res.end(body);
}

function sendText(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8"
  });
  res.end(String(payload));
}

function sendFile(res, filePath, contentType) {
  try {
    const content = fs.readFileSync(filePath);
    res.writeHead(200, {
      "Content-Type": contentType
    });
    res.end(content);
  } catch (error) {
    console.error("[otp-server] failed to read file:", error);
    sendJson(res, 500, {
      ok: false,
      error: "Failed to load dashboard."
    });
  }
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      throw new Error("Payload too large.");
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    return {};
  }

  return JSON.parse(raw);
}

function ensureStoreFile() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ updatedAt: null, records: [] }, null, 2));
  }
}

function loadStore() {
  try {
    const payload = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    const records = Array.isArray(payload) ? payload : payload.records;

    if (!Array.isArray(records)) {
      return { updatedAt: null, records: [] };
    }

    return {
      updatedAt: payload.updatedAt || null,
      records: records.map(normalizeStoredRecord)
    };
  } catch (error) {
    console.warn("[otp-server] failed to parse store, starting empty:", error.message);
    return { updatedAt: null, records: [] };
  }
}

function persistStore() {
  state.updatedAt = new Date().toISOString();
  fs.writeFileSync(DATA_FILE, JSON.stringify({
    updatedAt: state.updatedAt,
    records: state.records
  }, null, 2));
}

function buildRecord(payload) {
  const code = normalizeCode(payload.code || payload.otp || extractCode(payload.message || payload.text || ""));
  if (!code) {
    return null;
  }

  const receivedAt = normalizeDate(payload.received_at || payload.receivedAt || payload.timestamp || Date.now());
  const senderNumber = normalizePhone(payload.sender_number || payload.senderNumber || payload.from_number || payload.fromNumber || "");
  const senderName = cleanText(payload.sender_name || payload.senderName || payload.from_name || payload.fromName || "") || senderNumber || "Unknown";

  return normalizeStoredRecord({
    id: payload.id || randomUUID(),
    type: cleanText(payload.type) || "otp",
    source: cleanText(payload.source) || "whatsapp",
    code,
    message: cleanText(payload.message || payload.text || ""),
    senderName,
    senderNumber,
    messageId: cleanText(payload.message_id || payload.messageId || ""),
    chatJid: cleanText(payload.chat_jid || payload.chatJid || ""),
    receivedAt,
    createdAt: normalizeDate(Date.now())
  });
}

function normalizeStoredRecord(record) {
  return {
    id: cleanText(record.id) || randomUUID(),
    type: cleanText(record.type) || "otp",
    source: cleanText(record.source) || "whatsapp",
    code: normalizeCode(record.code) || "",
    message: cleanText(record.message) || "",
    senderName: cleanText(record.senderName || record.sender_name) || "Unknown",
    senderNumber: normalizePhone(record.senderNumber || record.sender_number || ""),
    messageId: cleanText(record.messageId || record.message_id || ""),
    chatJid: cleanText(record.chatJid || record.chat_jid || ""),
    receivedAt: normalizeDate(record.receivedAt || record.received_at || Date.now()),
    createdAt: normalizeDate(record.createdAt || record.created_at || Date.now())
  };
}

function upsertRecord(record) {
  const existingIndex = state.records.findIndex((item) => {
    return item.messageId && record.messageId && item.messageId === record.messageId;
  });

  if (existingIndex >= 0) {
    const existing = state.records[existingIndex];
    const merged = {
      ...existing,
      ...record,
      id: existing.id,
      createdAt: existing.createdAt
    };
    state.records.splice(existingIndex, 1);
    state.records.unshift(merged);
    persistStore();
    return merged;
  }

  state.records.unshift(record);
  state.records = state.records.slice(0, STORE_LIMIT);
  persistStore();
  return record;
}

function filterRecords(searchParams) {
  const senderNumber = normalizePhone(searchParams.get("sender_number") || "");
  const code = normalizeCode(searchParams.get("code") || "");
  const source = cleanText(searchParams.get("source") || "").toLowerCase();
  const after = normalizeDateOrNull(searchParams.get("after"));
  const limit = clampNumber(searchParams.get("limit"), 20, 1, 100);

  return state.records
    .filter((item) => {
      if (senderNumber && !item.senderNumber.includes(senderNumber)) {
        return false;
      }
      if (code && item.code !== code) {
        return false;
      }
      if (source && item.source.toLowerCase() !== source) {
        return false;
      }
      if (after && new Date(item.receivedAt).getTime() < after) {
        return false;
      }
      return true;
    })
    .slice(0, limit);
}

function normalizeCode(value) {
  const clean = String(value || "").replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
  if (!clean || clean.length < 4 || clean.length > 8) {
    return "";
  }

  return /\d/.test(clean) ? clean : "";
}

function extractCode(message) {
  const input = cleanText(message);
  if (!input) {
    return "";
  }

  for (const pattern of OTP_PATTERNS) {
    const match = input.match(pattern);
    if (!match || !match[1]) {
      continue;
    }

    const normalized = normalizeCode(match[1]);
    if (normalized) {
      return normalized;
    }
  }

  return "";
}

function normalizePhone(value) {
  return String(value || "").replace(/\D/g, "");
}

function cleanText(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).trim();
}

function normalizeDate(value) {
  const fallback = new Date().toISOString();
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  const numeric = Number(value);
  const date = Number.isFinite(numeric) ? new Date(numeric) : new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toISOString();
}

function normalizeDateOrNull(value) {
  if (!value) {
    return null;
  }

  const numeric = Number(value);
  const date = Number.isFinite(numeric) ? new Date(numeric) : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.getTime();
}

function clampNumber(value, fallback, min, max) {
  const numeric = Number.parseInt(value, 10);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, numeric));
}
