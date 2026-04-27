import { constantTimeHexEqual, sha256Bytes } from "./hash.js";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export function hashLeaf(item) {
  return sha256Bytes(LEAF_PREFIX, item).toString("hex");
}

export function hashNode(leftHex, rightHex) {
  return sha256Bytes(
    NODE_PREFIX,
    Buffer.from(leftHex, "hex"),
    Buffer.from(rightHex, "hex"),
  ).toString("hex");
}

export class MerkleTree {
  constructor(items) {
    if (!Array.isArray(items) || items.length === 0) {
      throw new TypeError("MerkleTree requires a non-empty array of items");
    }

    this.items = [...items];
    this.levels = [items.map((item) => hashLeaf(item))];

    while (this.levels.at(-1).length > 1) {
      const currentLevel = this.levels.at(-1);
      const nextLevel = [];

      for (let index = 0; index < currentLevel.length; index += 2) {
        const left = currentLevel[index];
        const right = currentLevel[index + 1] ?? left;
        nextLevel.push(hashNode(left, right));
      }

      this.levels.push(nextLevel);
    }
  }

  get root() {
    return this.levels.at(-1)[0];
  }

  getProof(index) {
    if (!Number.isInteger(index) || index < 0 || index >= this.items.length) {
      throw new RangeError("Proof index is outside the Merkle tree");
    }

    const proof = [];
    let nodeIndex = index;

    for (let levelIndex = 0; levelIndex < this.levels.length - 1; levelIndex += 1) {
      const level = this.levels[levelIndex];
      const isRightNode = nodeIndex % 2 === 1;
      let siblingIndex = isRightNode ? nodeIndex - 1 : nodeIndex + 1;

      if (siblingIndex >= level.length) {
        siblingIndex = nodeIndex;
      }

      proof.push({
        position: isRightNode ? "left" : "right",
        hash: level[siblingIndex],
      });

      nodeIndex = Math.floor(nodeIndex / 2);
    }

    return proof;
  }

  getProofs() {
    return this.items.map((_, index) => this.getProof(index));
  }
}

export function verifyInclusion(item, proof, expectedRoot) {
  if (!Array.isArray(proof)) {
    return false;
  }

  let currentHash = hashLeaf(item);

  for (const step of proof) {
    if (!step || (step.position !== "left" && step.position !== "right")) {
      return false;
    }

    if (typeof step.hash !== "string" || !/^[0-9a-f]{64}$/i.test(step.hash)) {
      return false;
    }

    currentHash =
      step.position === "left"
        ? hashNode(step.hash, currentHash)
        : hashNode(currentHash, step.hash);
  }

  if (typeof expectedRoot !== "string" || !/^[0-9a-f]{64}$/i.test(expectedRoot)) {
    return false;
  }

  return constantTimeHexEqual(currentHash, expectedRoot);
}
