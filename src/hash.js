import { createHash, timingSafeEqual } from "node:crypto";

export function toBytes(value) {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }

  if (typeof value === "string") {
    return Buffer.from(value, "utf8");
  }

  throw new TypeError("Expected a string, Buffer, or Uint8Array");
}

export function sha256Bytes(...chunks) {
  const hash = createHash("sha256");

  for (const chunk of chunks) {
    hash.update(toBytes(chunk));
  }

  return hash.digest();
}

export function hashMessage(message) {
  return sha256Bytes(message).toString("hex");
}

export function encodeUtf8ToHex(text) {
  return Buffer.from(text, "utf8").toString("hex");
}

export function decodeHexToUtf8(hex) {
  return Buffer.from(hex, "hex").toString("utf8");
}

export function constantTimeHexEqual(leftHex, rightHex) {
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");

  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}
