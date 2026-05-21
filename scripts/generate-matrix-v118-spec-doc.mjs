#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later

import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";

const DEFAULT_SOURCE_URL = "https://spec.matrix.org/v1.18/client-server-api/api.json";
const DEFAULT_OUTPUT = "docs/matrix-v1.18-client-server-api.md";

function argValue(name, fallback) {
  const prefix = `${name}=`;
  const matched = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return matched === undefined ? fallback : matched.slice(prefix.length);
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`GET ${url} returned ${response.statusCode}`));
          response.resume();
          return;
        }
        response.setEncoding("utf8");
        let body = "";
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => resolve(body));
      })
      .on("error", reject);
  });
}

function markdownEscape(value) {
  return String(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll("\n", " ")
    .trim();
}

function methodOrder(method) {
  return ["get", "post", "put", "delete", "patch"].indexOf(method);
}

function authLabel(security) {
  if (security === undefined) {
    return "none";
  }
  if (security.some((entry) => Object.keys(entry).length === 0)) {
    return "optional";
  }
  const names = new Set(security.flatMap((entry) => Object.keys(entry)));
  const labels = [];
  if (names.has("accessTokenBearer") || names.has("accessTokenQuery")) {
    labels.push("access token");
  }
  if (names.has("appserviceAccessTokenBearer") || names.has("appserviceAccessTokenQuery")) {
    labels.push("appservice token");
  }
  if (names.has("signedRequest")) {
    labels.push("signed request");
  }
  return labels.length === 0 ? "custom" : labels.join(" / ");
}

function requestLabel(operation) {
  const body = operation.requestBody;
  if (body === undefined) {
    return "-";
  }
  const required = body.required === true ? "required" : "optional";
  const contentTypes = Object.keys(body.content ?? {});
  return `${required} ${contentTypes.length === 0 ? "body" : contentTypes.join(", ")}`;
}

function responseLabel(operation) {
  return Object.keys(operation.responses ?? {})
    .sort((left, right) => Number(left) - Number(right))
    .join(", ");
}

function isOperation(method) {
  return ["get", "post", "put", "delete", "patch"].includes(method);
}

const source = argValue("--source", DEFAULT_SOURCE_URL);
const output = argValue("--output", DEFAULT_OUTPUT);
const fixedDate = argValue("--date", new Date().toISOString().slice(0, 10));
const sourceText = source.startsWith("http://") || source.startsWith("https://")
  ? await fetchText(source)
  : fs.readFileSync(source, "utf8");
const api = JSON.parse(sourceText);
const sha256 = crypto.createHash("sha256").update(sourceText).digest("hex");

const operations = [];
for (const [routePath, pathItem] of Object.entries(api.paths ?? {})) {
  for (const [method, operation] of Object.entries(pathItem)) {
    if (!isOperation(method)) {
      continue;
    }
    operations.push({
      tag: operation.tags?.[0] ?? "untagged",
      method: method.toUpperCase(),
      methodSort: methodOrder(method),
      path: routePath,
      operationId: operation.operationId ?? "",
      auth: authLabel(operation.security),
      request: requestLabel(operation),
      responses: responseLabel(operation),
    });
  }
}

operations.sort((left, right) =>
  left.tag.localeCompare(right.tag) ||
  left.path.localeCompare(right.path) ||
  left.methodSort - right.methodSort ||
  left.method.localeCompare(right.method),
);

const tagCounts = new Map();
for (const operation of operations) {
  tagCounts.set(operation.tag, (tagCounts.get(operation.tag) ?? 0) + 1);
}

const lines = [
  "# Matrix v1.18 Client-Server API Reference",
  "",
  "> Generated file. Do not edit endpoint rows by hand; regenerate with `node scripts/generate-matrix-v118-spec-doc.mjs`.",
  "",
  "## Source",
  "",
  `- Official OpenAPI document: ${source}`,
  "- Human-readable reference: https://spec.matrix.org/v1.18/client-server-api/",
  `- OpenAPI: ${api.openapi ?? "unknown"}`,
  `- Title: ${api.info?.title ?? "unknown"}`,
  `- Version: ${api.info?.version ?? "unknown"}`,
  `- Generated: ${fixedDate}`,
  `- Source SHA-256: \`${sha256}\``,
  "",
  "## Summary",
  "",
  `- Paths: ${Object.keys(api.paths ?? {}).length}`,
  `- Operations: ${operations.length}`,
  `- Tags: ${tagCounts.size}`,
  "",
  "| Tag | Operations |",
  "| --- | ---: |",
];

for (const [tag, count] of [...tagCounts.entries()].sort((left, right) => left[0].localeCompare(right[0]))) {
  lines.push(`| ${markdownEscape(tag)} | ${count} |`);
}

let currentTag = "";
for (const operation of operations) {
  if (operation.tag !== currentTag) {
    currentTag = operation.tag;
    lines.push("", `## ${currentTag}`, "", "| Method | Path | Operation ID | Auth | Request body | Responses |", "| --- | --- | --- | --- | --- | --- |");
  }
  lines.push(
    `| \`${operation.method}\` | \`${markdownEscape(operation.path)}\` | \`${markdownEscape(operation.operationId)}\` | ${markdownEscape(operation.auth)} | ${markdownEscape(operation.request)} | ${markdownEscape(operation.responses)} |`,
  );
}

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, `${lines.join("\n")}\n`, "utf8");
console.log(`Wrote ${output} from ${source} (${operations.length} operations)`);
