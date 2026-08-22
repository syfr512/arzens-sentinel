import http from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runSafePassiveScan } from "./core";

let lab: http.Server | undefined;
let priorNodeEnv: string | undefined;

beforeEach(() => { priorNodeEnv = process.env.NODE_ENV; process.env.NODE_ENV = "test"; });

afterEach(async () => {
  if (lab) await new Promise<void>((resolve, reject) => lab?.close(error => error ? reject(error) : resolve()));
  lab = undefined;
  process.env.NODE_ENV = priorNodeEnv;
});

describe("loopback-only controlled HTTP lab", () => {
  it("observes known passive signals over a real local HTTP exchange without allowing those targets in live workflows", async () => {
    lab = http.createServer((_request, response) => {
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Set-Cookie": "session=controlled-lab-secret; Path=/",
        "Access-Control-Allow-Origin": "*",
        "Server": "Arzens-Controlled-Lab/1.0",
      });
      response.end('<!doctype html><img src="http://assets.example.test/icon.png">');
    });
    await new Promise<void>(resolve => lab?.listen(0, "127.0.0.1", () => resolve()));
    const address = lab.address();
    if (!address || typeof address === "string") throw new Error("Controlled lab did not bind an ephemeral loopback port.");
    const target = `http://127.0.0.1:${address.port}/`;
    const result = await runSafePassiveScan(target, "safe_passive", { maxPages: 1, maxRedirects: 1, maxResponseBytes: 16_384, timeoutMs: 3_000 }, { scope: { origin: `http://127.0.0.1:${address.port}`, scopePath: "/" }, controlledLab: true });
    const ids = result.findings.map(item => item.ruleId);
    expect(result.summary.scannedEndpoints).toBe(1);
    expect(ids).toEqual(expect.arrayContaining(["ARS-HEAD-001", "ARS-COOKIE-001", "ARS-COOKIE-002", "ARS-COOKIE-003", "ARS-CORS-001", "ARS-DISC-001", "ARS-TRANS-001"]));
    expect(result.findings.every(item => !item.evidence.includes("controlled-lab-secret"))).toBe(true);
  });
});
