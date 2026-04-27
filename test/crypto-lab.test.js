import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalJson,
  createProtectedCommand,
  encodeUtf8ToHex,
  decodeHexToUtf8,
  generateSigningKeyPair,
  hashMessage,
  MerkleTree,
  NonceLedger,
  signMessage,
  simulateReplayAttack,
  simulateReplayFix,
  verifyInclusion,
  verifySignature,
} from "../src/index.js";

test("encoding is reversible, while hashing is deterministic but not decoded", () => {
  const message = "digital ownership";
  const encoded = encodeUtf8ToHex(message);
  const digest = hashMessage(message);

  assert.equal(decodeHexToUtf8(encoded), message);
  assert.equal(hashMessage(message), digest);
  assert.equal(digest.length, 64);
  assert.notEqual(digest, message);
});

test("Merkle tree produces and verifies inclusion proofs", () => {
  const transactions = ["tx:1", "tx:2", "tx:3", "tx:4", "tx:5"];
  const tree = new MerkleTree(transactions);
  const proof = tree.getProof(2);

  assert.equal(verifyInclusion("tx:3", proof, tree.root), true);
  assert.equal(verifyInclusion("tx:999", proof, tree.root), false);
  assert.equal(verifyInclusion("tx:3", proof, hashMessage("wrong-root")), false);
});

test("Merkle tree rejects empty input and invalid proof indexes", () => {
  assert.throws(() => new MerkleTree([]), /non-empty/);

  const tree = new MerkleTree(["only"]);
  assert.throws(() => tree.getProof(1), /outside/);
});

test("Ed25519 signatures prove authorization by a private key holder", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const otherPair = generateSigningKeyPair();
  const message = "approve transfer 25";
  const signature = signMessage(message, privateKey);

  assert.equal(verifySignature(message, signature, publicKey), true);
  assert.equal(verifySignature("approve transfer 250", signature, publicKey), false);
  assert.equal(verifySignature(message, signature, otherPair.publicKey), false);
});

test("signature-only commands can be replayed", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const result = simulateReplayAttack({
    message: "transfer 25 tokens to alice",
    privateKey,
    publicKey,
  });

  assert.equal(result.firstAttempt.accepted, true);
  assert.equal(result.replayAttempt.accepted, true);
  assert.equal(result.executionCount, 2);
});

test("nonce and domain separation reject replays and cross-domain reuse", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const result = simulateReplayFix({ privateKey, publicKey });

  assert.equal(result.firstAttempt.accepted, true);
  assert.equal(result.replayAttempt.accepted, false);
  assert.equal(result.replayAttempt.reason, "nonce-already-used");
  assert.equal(result.crossDomainAttempt.accepted, false);
  assert.equal(result.crossDomainAttempt.reason, "wrong-domain");
  assert.equal(result.executionCount, 1);
});

test("fresh signatures over fresh nonces are accepted once per domain", () => {
  const { privateKey, publicKey } = generateSigningKeyPair();
  const ledger = new NonceLedger({
    domain: "crypto-lab/transfer/v1",
    publicKey,
    signerId: "alice",
  });
  const command = createProtectedCommand(
    {
      domain: "crypto-lab/transfer/v1",
      nonce: "nonce-0002",
      action: "transfer",
      to: "bob",
      amount: 10,
    },
    privateKey,
  );

  assert.equal(ledger.submit(command).accepted, true);
  assert.equal(ledger.submit(command).reason, "nonce-already-used");
});

test("canonical JSON makes structured signing stable across key order", () => {
  assert.equal(
    canonicalJson({ nonce: "1", domain: "crypto-lab", amount: 25 }),
    canonicalJson({ amount: 25, domain: "crypto-lab", nonce: "1" }),
  );
});
