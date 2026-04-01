// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import path from "node:path";
import { spawnSync } from "node:child_process";

const require = createRequire(import.meta.url);
const { redactSecrets, runCapture } = require("../bin/lib/runner");

describe("redactSecrets", () => {
  it("redacts NVIDIA_API_KEY=value", () => {
    const input = 'openshell provider create --credential "NVIDIA_API_KEY=nvapi-abc123XYZ"';
    const result = redactSecrets(input);
    expect(result).not.toContain("nvapi-abc123XYZ");
    expect(result).toContain("NVIDIA_API_KEY=***");
  });

  it("redacts bare nvapi- tokens", () => {
    const input = "Bearer nvapi-SomeSecretToken123";
    const result = redactSecrets(input);
    expect(result).not.toContain("nvapi-SomeSecretToken123");
    expect(result).toContain("nvapi-So***");
  });

  it("redacts GITHUB_TOKEN=value", () => {
    const result = redactSecrets("GITHUB_TOKEN=ghp_1234567890abcdef");
    expect(result).not.toContain("ghp_1234567890abcdef");
    expect(result).toContain("GITHUB_TOKEN=***");
  });

  it("redacts TELEGRAM_BOT_TOKEN=value", () => {
    const result = redactSecrets("TELEGRAM_BOT_TOKEN=123456:ABC-DEF");
    expect(result).not.toContain("123456:ABC-DEF");
    expect(result).toContain("TELEGRAM_BOT_TOKEN=***");
  });

  it("redacts OPENAI_API_KEY=value", () => {
    const result = redactSecrets("OPENAI_API_KEY=sk-proj-abc123");
    expect(result).not.toContain("sk-proj-abc123");
    expect(result).toContain("OPENAI_API_KEY=***");
  });

  it("redacts SLACK_BOT_TOKEN=value", () => {
    const result = redactSecrets("SLACK_BOT_TOKEN=xoxb-1234");
    expect(result).not.toContain("xoxb-1234");
    expect(result).toContain("SLACK_BOT_TOKEN=***");
  });

  it("redacts DISCORD_BOT_TOKEN=value", () => {
    const result = redactSecrets("DISCORD_BOT_TOKEN=MTk4NjIy");
    expect(result).not.toContain("MTk4NjIy");
    expect(result).toContain("DISCORD_BOT_TOKEN=***");
  });

  it("returns input unchanged when no secrets present", () => {
    const input = "openshell sandbox create --name my-assistant";
    expect(redactSecrets(input)).toBe(input);
  });

  it("redacts multiple different secrets in one string", () => {
    const input = "NVIDIA_API_KEY=nvapi-secret GITHUB_TOKEN=ghp_token123";
    const result = redactSecrets(input);
    expect(result).not.toContain("nvapi-secret");
    expect(result).not.toContain("ghp_token123");
    expect(result).toContain("NVIDIA_API_KEY=***");
    expect(result).toContain("GITHUB_TOKEN=***");
  });

  it("redacts double-quoted secret values", () => {
    const result = redactSecrets('GITHUB_TOKEN="ghp_secretValue123"');
    expect(result).not.toContain("ghp_secretValue123");
    expect(result).toBe("GITHUB_TOKEN=***");
  });

  it("redacts single-quoted secret values", () => {
    const result = redactSecrets("NVIDIA_API_KEY='nvapi-secretValue123'");
    expect(result).not.toContain("nvapi-secretValue123");
    expect(result).toBe("NVIDIA_API_KEY=***");
  });

  it("handles empty string", () => {
    expect(redactSecrets("")).toBe("");
  });

  it("handles null and undefined without throwing", () => {
    expect(redactSecrets(null)).toBe("");
    expect(redactSecrets(undefined)).toBe("");
  });

  it("produces identical results on consecutive calls", () => {
    const input = "NVIDIA_API_KEY=nvapi-test123";
    const r1 = redactSecrets(input);
    const r2 = redactSecrets(input);
    expect(r1).toBe(r2);
    expect(r1).not.toContain("nvapi-test123");
  });

  it("redacts generic env-style secret names", () => {
    const result = redactSecrets('TEST_API_KEY="super-secret-value"');
    expect(result).toBe("TEST_API_KEY=***");
    expect(result).not.toContain("super-secret-value");
  });

  it("run() error output redacts secrets (integration)", () => {
    // Spawn a child that requires runner.js and calls run() with a command
    // that will fail, then captures stderr to verify redaction.
    const runnerPath = path.join(import.meta.dirname, "..", "bin", "lib", "runner");
    const script = `
      const { run } = require(${JSON.stringify(runnerPath)});
      // Override process.exit so the child doesn't exit before we capture output
      process.exit = () => {};
      run("false NVIDIA_API_KEY=nvapi-realSecretValue123");
    `;
    const result = spawnSync("node", ["-e", script], {
      cwd: path.join(import.meta.dirname, ".."),
      encoding: "utf-8",
      timeout: 10000,
    });
    expect(result.stderr).toContain("NVIDIA_API_KEY=***");
    expect(result.stderr).not.toContain("nvapi-realSecretValue123");
  });

  it("run() redacts secrets when command is truncated before closing quote (regression)", () => {
    const runnerPath = path.join(import.meta.dirname, "..", "bin", "lib", "runner");
    const script = `
      const { run } = require(${JSON.stringify(runnerPath)});
      process.exit = () => {};
      const longPadding = ${JSON.stringify("x".repeat(5000))};
      run('false "NVIDIA_API_KEY=nvapi-truncatedSecret' + longPadding + '"');
    `;
    const result = spawnSync("node", ["-e", script], {
      cwd: path.join(import.meta.dirname, ".."),
      encoding: "utf-8",
      timeout: 10000,
    });
    expect(result.stderr).toContain("NVIDIA_API_KEY=***");
    expect(result.stderr).not.toContain("nvapi-truncatedSecret");
  });

  it("runInteractive() error output redacts secrets (integration)", () => {
    const runnerPath = path.join(import.meta.dirname, "..", "bin", "lib", "runner");
    const script = `
      const { runInteractive } = require(${JSON.stringify(runnerPath)});
      process.exit = () => {};
      runInteractive("false GITHUB_TOKEN=ghp_realSecretValue123");
    `;
    const result = spawnSync("node", ["-e", script], {
      cwd: path.join(import.meta.dirname, ".."),
      encoding: "utf-8",
      timeout: 10000,
    });
    expect(result.stderr).toContain("GITHUB_TOKEN=***");
    expect(result.stderr).not.toContain("ghp_realSecretValue123");
  });

  it("runCapture() thrown error redacts message/stdout/stderr", () => {
    try {
      runCapture("bash -lc 'echo NVIDIA_API_KEY=nvapi-realSecret >&2; exit 1'");
      throw new Error("expected runCapture to throw");
    } catch (err) {
      expect(String(err.message)).toContain("NVIDIA_API_KEY=***");
      expect(String(err.message)).not.toContain("nvapi-realSecret");
      expect(String(err.stderr || "")).toContain("NVIDIA_API_KEY=***");
      expect(String(err.stderr || "")).not.toContain("nvapi-realSecret");
    }
  });

  it("runCapture() thrown error redacts err.output array", () => {
    try {
      runCapture("bash -lc 'echo GITHUB_TOKEN=ghp_secretOutputValue >&2; exit 1'");
      throw new Error("expected runCapture to throw");
    } catch (err) {
      if (Array.isArray(err.output)) {
        for (const chunk of err.output) {
          if (chunk != null) {
            expect(String(chunk)).not.toContain("ghp_secretOutputValue");
          }
        }
      }
    }
  });
});
