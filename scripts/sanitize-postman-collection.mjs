#!/usr/bin/env node
/**
 * Redacts common secrets from Postman Collection v2.x JSON (in-place path argv).
 * Does not execute collection scripts.
 */
import fs from "node:fs";
import path from "node:path";

const jwtRe = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

function redactJwt(s) {
  if (typeof s !== "string") return s;
  return s.replace(jwtRe, "{{jwt}}");
}

function looksLikeOpaqueToken(s) {
  if (typeof s !== "string" || s.length < 20) return false;
  if (s.includes("{{") && s.includes("}}")) return false;
  if (/^application\//i.test(s)) return false;
  if (/^text\//i.test(s)) return false;
  if (/^\d+$/.test(s)) return false;
  // long hex / base64url-ish without spaces
  if (/^[A-Za-z0-9+/=_-]+$/.test(s) && s.length >= 32) return true;
  return false;
}

function sanitizeAuth(a) {
  if (!a || typeof a !== "object") return;
  if (Array.isArray(a.bearer)) {
    for (const b of a.bearer) {
      if (b && typeof b === "object" && /^token$/i.test(String(b.key))) b.value = "{{accessToken}}";
    }
  }
  if (Array.isArray(a.apikey)) {
    for (const b of a.apikey) {
      if (b && typeof b === "object" && /^(value|key)$/i.test(String(b.key))) {
        if (String(b.key).toLowerCase() === "value") b.value = "{{apiKey}}";
      }
    }
  }
  for (const v of Object.values(a)) {
    if (typeof v === "string" && jwtRe.test(v)) {
      /* noop parent key unknown */
    }
  }
}

function processRequest(r) {
  if (!r || typeof r !== "object") return;
  if (Array.isArray(r.header)) {
    for (const h of r.header) {
      if (!h || h.disabled || typeof h.value !== "string") continue;
      const k = String(h.key || "");
      if (/^authorization$/i.test(k)) {
        h.value = /^Bearer\s+/i.test(h.value) ? "Bearer {{accessToken}}" : "{{authorization}}";
      } else if (/^(api-?key|x-api-key)$/i.test(k)) {
        h.value = "{{apiKey}}";
      } else {
        h.value = redactJwt(h.value);
        if (looksLikeOpaqueToken(h.value)) h.value = "{{secret}}";
      }
    }
  }
  if (r.body && typeof r.body.raw === "string") {
    r.body.raw = redactJwt(r.body.raw);
  }
  if (r.auth) sanitizeAuth(r.auth);
  if (typeof r.url === "string") r.url = redactJwt(r.url);
  if (r.url && typeof r.url === "object") {
    if (typeof r.url.raw === "string") r.url.raw = redactJwt(r.url.raw);
    if (Array.isArray(r.url.path)) {
      r.url.path = r.url.path.map((p) => (typeof p === "string" ? redactJwt(p) : p));
    }
  }
}

function walkItems(items) {
  if (!Array.isArray(items)) return;
  for (const it of items) {
    if (it && it.request) processRequest(it.request);
    if (it && Array.isArray(it.item)) walkItems(it.item);
  }
}

function sanitizeCollection(c) {
  if (!c || typeof c !== "object") return c;
  walkItems(c.item);
  if (c.auth) sanitizeAuth(c.auth);
  if (Array.isArray(c.variable)) {
    for (const v of c.variable) {
      if (!v || typeof v.value !== "string") continue;
      if (jwtRe.test(v.value) || looksLikeOpaqueToken(v.value)) v.value = `{{${v.key || "var"}}}`;
    }
  }
  return c;
}

const file = process.argv[2];
if (!file) {
  console.error("Usage: sanitize-postman-collection.mjs <file.postman_collection.json>");
  process.exit(1);
}
const abs = path.resolve(file);
const raw = JSON.parse(fs.readFileSync(abs, "utf8"));
sanitizeCollection(raw);
fs.writeFileSync(abs, JSON.stringify(raw, null, 2) + "\n", "utf8");
console.log("sanitized:", abs);
