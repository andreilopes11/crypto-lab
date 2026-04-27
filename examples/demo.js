import { writeFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";

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

const DEFAULT_MESSAGE = "transfer 25 tokens to alice";
const LOG_FILE = new URL("./log.txt", import.meta.url);
const transcript = [];

function render(value) {
  if (typeof value === "string") {
    return value;
  }

  return inspect(value, {
    colors: false,
    compact: false,
    depth: null,
    sorted: false,
  });
}

function output(...values) {
  const line = values.map(render).join(" ");
  console.log(line);
  transcript.push(line);
}

async function readPipedMessage() {
  let data = "";
  stdin.setEncoding("utf8");

  for await (const chunk of stdin) {
    data += chunk;
  }

  return data.trim();
}

async function askForMessage() {
  const prompt = `Enter a message to hash and sign (blank uses "${DEFAULT_MESSAGE}"): `;

  if (stdin.isTTY) {
    const terminal = createInterface({ input: stdin, output: stdout });

    try {
      const answer = await terminal.question(prompt);
      transcript.push(`${prompt}${answer}`);
      return answer.trim() || DEFAULT_MESSAGE;
    } finally {
      terminal.close();
    }
  }

  const pipedMessage = await readPipedMessage();
  return pipedMessage || DEFAULT_MESSAGE;
}

async function main() {
  const message = await askForMessage();
  const digest = hashMessage(message);

  output("crypto-lab interactive run");
  output(`Started at: ${new Date().toISOString()}`);
  output(`Selected message: ${message}`);

  output("\n1. Message hash");
  output({ message, digest });

  const transactions = [
    "mint 100 to treasury",
    message,
    "transfer 10 to bob",
    "burn 1 from treasury",
  ];
  const tree = new MerkleTree(transactions);
  const proof = tree.getProof(1);

  output("\n2. Merkle proof of inclusion");
  output({
    root: tree.root,
    item: transactions[1],
    proof,
    verified: verifyInclusion(transactions[1], proof, tree.root),
  });

  const { privateKey, publicKey } = generateSigningKeyPair();
  const signature = signMessage(message, privateKey);

  output("\n3. Digital signature");
  output({
    publicKey: exportPublicKey(publicKey),
    signature,
    verified: verifySignature(message, signature, publicKey),
  });

  output("\n4. Replay attack against signature-only command");
  output(simulateReplayAttack({ message, privateKey, publicKey }));

  output("\n5. Replay fix with nonce and domain separation");
  output(simulateReplayFix({ privateKey, publicKey }));

  const savedLine = `\nLog saved to: ${fileURLToPath(LOG_FILE)}`;
  transcript.push(savedLine);
  await writeFile(LOG_FILE, `${transcript.join("\n")}\n`, "utf8");
  console.log(savedLine);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
