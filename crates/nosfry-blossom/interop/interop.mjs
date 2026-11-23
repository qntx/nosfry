#!/usr/bin/env node
/**
 * Interop test: real blossom-client-sdk (5.1.0) against the nosfry
 * relay's Blossom HTTP endpoints.
 *
 * Exercises the real client flow against a live server: the SDK's
 * BUD-02 upload (HEAD /upload preflight -> 401 -> signed PUT),
 * has/download/list/delete, plus two raw-fetch uploads proving both
 * Authorization base64 encodings (standard padded and URL-safe
 * unpadded) are accepted.
 *
 * Run the relay first with blossom enabled (upload = "everyone",
 * public_url = the same base URL given here), then:
 *
 *   npm install            # once, installs pinned deps
 *   node interop.mjs http://127.0.0.1:7778
 *
 * Prints one PASS/FAIL line per step; exits 0 iff every step passed.
 */

import { randomBytes } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  Actions,
  createDeleteAuth,
  createListAuth,
  createUploadAuth,
} from "blossom-client-sdk";

const { deleteBlob, downloadBlob, hasBlob, listBlobs, uploadBlob } = Actions;

const base = process.argv[2]?.replace(/\/+$/, "");
if (!base) {
  console.error("usage: node interop.mjs <base-url>");
  process.exit(2);
}
const host = new URL(base).hostname;
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const now = () => Math.floor(Date.now() / 1000);

// Record the request sequence the SDK performs so the BUD-02
// preflight -> 401 -> PUT flow is observable.
const requests = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const res = await realFetch(url, init);
  requests.push(`${init?.method ?? "GET"} ${new URL(url).pathname} -> ${res.status}`);
  return res;
};

// Throwaway keypair; kind-24242 tokens are signed through the SDK's
// signer hook (`Signer` = draft -> SignedEvent).
const seckey = randomBytes(32);
const pubkey = hex(schnorr.getPublicKey(seckey));
function sign(draft) {
  const event = { ...draft, pubkey };
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const digest = sha256(new TextEncoder().encode(serialized));
  event.id = hex(digest);
  event.sig = hex(schnorr.sign(digest, seckey));
  return event;
}

let failures = 0;
function report(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures += 1;
}
async function step(name, fn) {
  try {
    report(name, await fn());
  } catch (error) {
    report(name, false, String(error));
  }
}

// --- SDK flow -----------------------------------------------------

const blobBytes = randomBytes(100_000);
const blob = new Blob([blobBytes], { type: "application/octet-stream" });
const hash = hex(sha256(blobBytes));

let uploaded = null;
await step("sdk upload (BUD-02 HEAD /upload -> 401 -> PUT)", async () => {
  requests.length = 0;
  uploaded = await uploadBlob(base, blob, {
    onAuth: (server, sha256) => createUploadAuth(sign, sha256, { servers: [base] }),
  });
  const flow = requests.join(", ");
  if (uploaded.sha256 !== hash) throw new Error(`descriptor sha256 ${uploaded.sha256}`);
  if (!flow.includes("HEAD /upload -> 401") || !flow.includes("PUT /upload -> "))
    throw new Error(`unexpected request flow: ${flow}`);
  return true;
});

await step("sdk hasBlob (HEAD /<sha256>)", async () => await hasBlob(base, hash));

await step("sdk downloadBlob bytes match", async () => {
  const res = await downloadBlob(base, hash, {
    onAuth: (server, sha256) => createUploadAuth(sign, sha256, { servers: [base] }),
  });
  const got = new Uint8Array(await res.arrayBuffer());
  return got.length === blobBytes.length && got.every((b, i) => b === blobBytes[i]);
});

await step("sdk listBlobs (list auth)", async () => {
  const page = await listBlobs(base, pubkey, {
    auth: await createListAuth(sign, { servers: [base] }),
  });
  return page.some((d) => d.sha256 === hash);
});

await step("sdk deleteBlob", async () => {
  return await deleteBlob(base, hash, {
    auth: await createDeleteAuth(sign, hash, { servers: [base] }),
  });
});

await step("sdk hasBlob false after delete (404)", async () => {
  return !(await hasBlob(base, hash));
});

// --- raw fetch: both Authorization base64 encodings ---------------

async function rawUpload(encode) {
  const body = randomBytes(777);
  const bodyHash = hex(sha256(body));
  const event = sign({
    kind: 24242,
    created_at: now(),
    tags: [
      ["t", "upload"],
      ["x", bodyHash],
      ["server", host],
      ["expiration", String(now() + 3600)],
    ],
    content: "raw upload",
  });
  const res = await realFetch(`${base}/upload`, {
    method: "PUT",
    headers: {
      Authorization: `Nostr ${encode(Buffer.from(JSON.stringify(event)))}`,
      "Content-Type": "application/octet-stream",
    },
    body,
  });
  return res.status === 201 || res.status === 200;
}

await step("raw PUT /upload, standard padded base64", async () => {
  return rawUpload((b) => b.toString("base64"));
});
await step("raw PUT /upload, unpadded base64url", async () => {
  return rawUpload((b) => b.toString("base64url"));
});

process.exit(failures === 0 ? 0 : 1);
