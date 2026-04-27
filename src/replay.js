import {
  signMessage,
  signStructuredPayload,
  verifySignature,
  verifyStructuredSignature,
} from "./signatures.js";

export function simulateReplayAttack({ message, privateKey, publicKey }) {
  const command = {
    message,
    signature: signMessage(message, privateKey),
  };

  const acceptedMessages = [];

  function submit(signedCommand) {
    const isAuthorized = verifySignature(
      signedCommand.message,
      signedCommand.signature,
      publicKey,
    );

    if (!isAuthorized) {
      return { accepted: false, reason: "bad-signature" };
    }

    acceptedMessages.push(signedCommand.message);
    return { accepted: true, reason: "signature-valid" };
  }

  return {
    command,
    firstAttempt: submit(command),
    replayAttempt: submit(command),
    executionCount: acceptedMessages.length,
  };
}

export class NonceLedger {
  constructor({ domain, publicKey, signerId = "demo-signer" }) {
    if (!domain) {
      throw new TypeError("NonceLedger requires a domain");
    }

    this.domain = domain;
    this.publicKey = publicKey;
    this.signerId = signerId;
    this.usedNonces = new Set();
    this.executions = [];
  }

  submit({ payload, signature }) {
    if (!payload || payload.domain !== this.domain) {
      return { accepted: false, reason: "wrong-domain" };
    }

    if (!payload.nonce) {
      return { accepted: false, reason: "missing-nonce" };
    }

    if (!verifyStructuredSignature(payload, signature, this.publicKey)) {
      return { accepted: false, reason: "bad-signature" };
    }

    const nonceKey = `${this.domain}:${this.signerId}:${payload.nonce}`;

    if (this.usedNonces.has(nonceKey)) {
      return { accepted: false, reason: "nonce-already-used" };
    }

    this.usedNonces.add(nonceKey);
    this.executions.push(payload);

    return { accepted: true, reason: "authorized-once" };
  }
}

export function createProtectedCommand(payload, privateKey) {
  return {
    payload,
    signature: signStructuredPayload(payload, privateKey),
  };
}

export function simulateReplayFix({ privateKey, publicKey }) {
  const transferDomain = "crypto-lab/transfer/v1";
  const adminDomain = "crypto-lab/admin/v1";
  const payload = {
    domain: transferDomain,
    nonce: "nonce-0001",
    action: "transfer",
    to: "alice",
    amount: 25,
  };

  const command = createProtectedCommand(payload, privateKey);
  const transferLedger = new NonceLedger({ domain: transferDomain, publicKey });
  const adminLedger = new NonceLedger({ domain: adminDomain, publicKey });

  return {
    command,
    firstAttempt: transferLedger.submit(command),
    replayAttempt: transferLedger.submit(command),
    crossDomainAttempt: adminLedger.submit(command),
    executionCount: transferLedger.executions.length,
  };
}
