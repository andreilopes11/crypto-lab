import {
  exportPublicKey,
  generateSigningKeyPair,
  hashMessage,
  MerkleTree,
  signMessage,
  simulateReplayAttack,
  simulateReplayFix,
  verifyInclusion,
  verifySignature,
} from "../src/index.js";

const message = "transfer 25 tokens to alice";
const digest = hashMessage(message);

console.log("1. Message hash");
console.log({ message, digest });

const transactions = [
  "mint 100 to treasury",
  "transfer 25 to alice",
  "transfer 10 to bob",
  "burn 1 from treasury",
];
const tree = new MerkleTree(transactions);
const proof = tree.getProof(1);

console.log("\n2. Merkle proof of inclusion");
console.log({
  root: tree.root,
  item: transactions[1],
  proof,
  verified: verifyInclusion(transactions[1], proof, tree.root),
});

const { privateKey, publicKey } = generateSigningKeyPair();
const signature = signMessage(message, privateKey);

console.log("\n3. Digital signature");
console.log({
  publicKey: exportPublicKey(publicKey),
  signature,
  verified: verifySignature(message, signature, publicKey),
});

console.log("\n4. Replay attack against signature-only command");
console.log(simulateReplayAttack({ message, privateKey, publicKey }));

console.log("\n5. Replay fix with nonce and domain separation");
console.log(simulateReplayFix({ privateKey, publicKey }));
