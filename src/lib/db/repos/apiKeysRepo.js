import { v4 as uuidv4 } from "uuid";
import { getAdapter } from "../driver.js";
import { parseJson, stringifyJson } from "../helpers/jsonCol.js";

const EMPTY_POLICY = {
  allowedModels: [],
  limits: {
    dailyTokens: null,
    totalTokens: null,
    dailyCost: null,
    totalCost: null,
  },
};

function toNullableNumber(value) {
  if (value === "" || value === null || value === undefined) return null;
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? num : null;
}

function normalizePolicy(data = {}) {
  const limits = data.limits || data;
  return {
    allowedModels: Array.isArray(data.allowedModels)
      ? [...new Set(data.allowedModels.filter((m) => typeof m === "string" && m.trim()).map((m) => m.trim()))]
      : [],
    limits: {
      dailyTokens: toNullableNumber(limits.dailyTokens),
      totalTokens: toNullableNumber(limits.totalTokens),
      dailyCost: toNullableNumber(limits.dailyCost),
      totalCost: toNullableNumber(limits.totalCost),
    },
  };
}

function rowPolicy(row) {
  return normalizePolicy({ ...EMPTY_POLICY, ...parseJson(row?.data, {}) });
}

function rowToKey(row) {
  if (!row) return null;
  const policy = rowPolicy(row);
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    machineId: row.machineId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
    allowedModels: policy.allowedModels,
    limits: policy.limits,
  };
}

function getUtcDayRange(date = new Date()) {
  const start = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

function tokensExpr() {
  return "COALESCE(promptTokens, 0) + COALESCE(completionTokens, 0)";
}

function getUsageForKey(db, key) {
  const day = getUtcDayRange();
  const total = db.get(
    `SELECT COALESCE(SUM(${tokensExpr()}), 0) AS tokens, COALESCE(SUM(cost), 0) AS cost FROM usageHistory WHERE apiKey = ?`,
    [key]
  );
  const daily = db.get(
    `SELECT COALESCE(SUM(${tokensExpr()}), 0) AS tokens, COALESCE(SUM(cost), 0) AS cost FROM usageHistory WHERE apiKey = ? AND timestamp >= ? AND timestamp < ?`,
    [key, day.start, day.end]
  );
  return {
    dailyTokens: Number(daily?.tokens || 0),
    totalTokens: Number(total?.tokens || 0),
    dailyCost: Number(daily?.cost || 0),
    totalCost: Number(total?.cost || 0),
  };
}

function attachUsage(db, key) {
  if (!key) return key;
  return { ...key, usage: getUsageForKey(db, key.key) };
}

export async function getApiKeys() {
  const db = await getAdapter();
  const rows = db.all(`SELECT * FROM apiKeys ORDER BY createdAt ASC`);
  return rows.map(rowToKey).map((key) => attachUsage(db, key));
}

export async function getApiKeyById(id) {
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
  return attachUsage(db, rowToKey(row));
}

export async function getApiKeyByKey(key) {
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [key]);
  return attachUsage(db, rowToKey(row));
}

export async function createApiKey(name, machineId, policy = {}) {
  if (!machineId) throw new Error("machineId is required");
  const db = await getAdapter();
  const { generateApiKeyWithMachine } = await import("@/shared/utils/apiKey");
  const result = generateApiKeyWithMachine(machineId);
  const normalizedPolicy = normalizePolicy(policy);
  const apiKey = {
    id: uuidv4(),
    name,
    key: result.key,
    machineId,
    isActive: true,
    createdAt: new Date().toISOString(),
    ...normalizedPolicy,
  };
  db.run(
    `INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt, data) VALUES(?, ?, ?, ?, ?, ?, ?)`,
    [apiKey.id, apiKey.key, apiKey.name, apiKey.machineId, 1, apiKey.createdAt, stringifyJson(normalizedPolicy)]
  );
  return attachUsage(db, apiKey);
}

export async function updateApiKey(id, data) {
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    if (!row) return;
    const current = rowToKey(row);
    const policy = normalizePolicy({
      allowedModels: data.allowedModels !== undefined ? data.allowedModels : current.allowedModels,
      limits: data.limits !== undefined ? data.limits : current.limits,
    });
    const merged = { ...current, ...data, ...policy };
    db.run(
      `UPDATE apiKeys SET key = ?, name = ?, machineId = ?, isActive = ?, data = ? WHERE id = ?`,
      [merged.key, merged.name, merged.machineId, merged.isActive ? 1 : 0, stringifyJson(policy), id]
    );
    result = attachUsage(db, merged);
  });
  return result;
}

export async function deleteApiKey(id) {
  const db = await getAdapter();
  const res = db.run(`DELETE FROM apiKeys WHERE id = ?`, [id]);
  return (res?.changes ?? 0) > 0;
}

export async function validateApiKey(key) {
  const db = await getAdapter();
  const row = db.get(`SELECT isActive FROM apiKeys WHERE key = ?`, [key]);
  if (!row) return false;
  return row.isActive === 1 || row.isActive === true;
}

export async function validateApiKeyPolicy(key, model) {
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE key = ?`, [key]);
  const apiKey = rowToKey(row);
  if (!apiKey || !apiKey.isActive) return { ok: false, status: 401, error: "Invalid API key" };

  if (apiKey.allowedModels.length > 0 && !apiKey.allowedModels.includes(model)) {
    return { ok: false, status: 403, error: `Model not allowed for this API key: ${model}` };
  }

  const usage = getUsageForKey(db, apiKey.key);
  const { limits } = apiKey;
  const checks = [
    ["dailyTokens", "Daily token limit exceeded"],
    ["totalTokens", "Total token limit exceeded"],
    ["dailyCost", "Daily cost limit exceeded"],
    ["totalCost", "Total cost limit exceeded"],
  ];
  for (const [field, message] of checks) {
    if (limits[field] !== null && usage[field] >= limits[field]) {
      return { ok: false, status: 429, error: message, usage, limits };
    }
  }

  return { ok: true, apiKey: { ...apiKey, usage } };
}
