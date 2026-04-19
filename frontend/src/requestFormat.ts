import type { Endpoint } from "./types";

const shellQuote = (value: string) => `'${value.replace(/'/g, `'\"'\"'`)}'`;

const parseRawRequest = (raw: string) => {
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  const [requestLine = "", ...rest] = lines;
  const match = requestLine.trim().match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/);
  if (!match) {
    return null;
  }
  const [, method, path] = match;
  const headerLines: string[] = [];
  const bodyLines: string[] = [];
  let bodyStarted = false;
  for (const line of rest) {
    if (!bodyStarted && line.trim() === "") {
      bodyStarted = true;
      continue;
    }
    if (bodyStarted) {
      bodyLines.push(line);
    } else {
      headerLines.push(line);
    }
  }
  const headers = headerLines
    .map((line) => {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex < 0) {
        return null;
      }
      return {
        name: line.slice(0, separatorIndex).trim(),
        value: line.slice(separatorIndex + 1).trim(),
      };
    })
    .filter((item): item is { name: string; value: string } => Boolean(item));
  return { method, path, headers, body: bodyLines.join("\n").trim() || null };
};

export function buildRawRequest(endpoint: Endpoint, hostLabel?: string): string {
  const method = (endpoint.method || "GET").toUpperCase();
  const lines = [`${method} ${endpoint.path} HTTP/1.1`];
  if (hostLabel) {
    lines.push(`Host: ${hostLabel}`);
  }
  for (const header of endpoint.request_headers || []) {
    lines.push(`${header.name}: ${header.value}`);
  }
  if (endpoint.request_content_type && !(endpoint.request_headers || []).some((header) => header.name.toLowerCase() === "content-type")) {
    lines.push(`Content-Type: ${endpoint.request_content_type}`);
  }
  lines.push("");
  if (endpoint.request_body) {
    lines.push(endpoint.request_body);
  }
  return lines.join("\n");
}

export function buildCurlFromEndpoint(endpoint: Endpoint, hostLabel?: string): string {
  const method = (endpoint.method || "GET").toUpperCase();
  const targetUrl = `http://${hostLabel || "example.local"}${endpoint.path}`;
  const segments = [`curl -X ${method} ${shellQuote(targetUrl)}`];
  for (const header of endpoint.request_headers || []) {
    segments.push(`-H ${shellQuote(`${header.name}: ${header.value}`)}`);
  }
  if (endpoint.request_content_type && !(endpoint.request_headers || []).some((header) => header.name.toLowerCase() === "content-type")) {
    segments.push(`-H ${shellQuote(`Content-Type: ${endpoint.request_content_type}`)}`);
  }
  if (endpoint.request_body) {
    segments.push(`--data-raw ${shellQuote(endpoint.request_body)}`);
  }
  return segments.join(" ");
}

export function buildCurlFromRawRequest(raw: string, hostLabel?: string): string | null {
  const parsed = parseRawRequest(raw);
  if (!parsed) {
    return null;
  }
  const targetUrl = `http://${hostLabel || "example.local"}${parsed.path}`;
  const segments = [`curl -X ${parsed.method.toUpperCase()} ${shellQuote(targetUrl)}`];
  for (const header of parsed.headers) {
    if (header.name.toLowerCase() === "host") {
      continue;
    }
    segments.push(`-H ${shellQuote(`${header.name}: ${header.value}`)}`);
  }
  if (parsed.body) {
    segments.push(`--data-raw ${shellQuote(parsed.body)}`);
  }
  return segments.join(" ");
}
