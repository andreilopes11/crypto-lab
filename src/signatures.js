import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import { toBytes } from "./hash.js";

export function generateSigningKeyPair() {
  return generateKeyPairSync("ed25519");
}

export function exportPublicKey(publicKey) {
  return publicKey.export({ format: "pem", type: "spki" });
}

export function exportPrivateKey(privateKey) {
  return privateKey.export({ format: "pem", type: "pkcs8" });
}

export function signMessage(message, privateKey) {
  return cryptoSign(null, toBytes(message), privateKey).toString("base64");
}

export function verifySignature(message, signatureBase64, publicKey) {
  try {
    return cryptoVerify(
      null,
      toBytes(message),
      publicKey,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Structured payloads cannot contain non-finite numbers");
    }

    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    const entries = Object.entries(value)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));

    return `{${entries
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalJson(entryValue)}`)
      .join(",")}}`;
  }

  throw new TypeError(`Unsupported structured payload value: ${typeof value}`);
}

export function payloadBytes(payload) {
  return Buffer.from(canonicalJson(payload), "utf8");
}

export function signStructuredPayload(payload, privateKey) {
  return signMessage(payloadBytes(payload), privateKey);
}

export function verifyStructuredSignature(payload, signatureBase64, publicKey) {
  return verifySignature(payloadBytes(payload), signatureBase64, publicKey);
}
