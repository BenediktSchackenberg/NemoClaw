// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getExpectedOpenshellVersion,
  warnOnOpenshellVersionMismatch,
  getInstalledOpenshellVersion,
} from "../bin/lib/onboard";

// Helper: create a temp install-openshell.sh with a given MIN_VERSION
function makeTmpInstallScript(minVersion) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-openshell-test-"));
  const scriptPath = path.join(dir, "install-openshell.sh");
  fs.writeFileSync(scriptPath, `#!/usr/bin/env bash\nMIN_VERSION="${minVersion}"\necho "done"\n`);
  return { dir, scriptPath };
}

describe("getExpectedOpenshellVersion", () => {
  it("reads MIN_VERSION from install-openshell.sh", () => {
    const { scriptPath } = makeTmpInstallScript("0.0.22");
    // Temporarily override SCRIPTS path by spying — use vi.spyOn on fs
    const origReadFileSync = fs.readFileSync;
    vi.spyOn(fs, "readFileSync").mockImplementation((p, ...args) => {
      if (String(p).endsWith("install-openshell.sh")) {
        return origReadFileSync(scriptPath, ...args);
      }
      return origReadFileSync(p, ...args);
    });

    const version = getExpectedOpenshellVersion();
    expect(version).toBe("0.0.22");

    vi.restoreAllMocks();
  });

  it("returns null when install script is missing", () => {
    vi.spyOn(fs, "readFileSync").mockImplementation((p) => {
      if (String(p).endsWith("install-openshell.sh")) throw new Error("ENOENT");
      throw new Error("unexpected");
    });

    const version = getExpectedOpenshellVersion();
    expect(version).toBeNull();

    vi.restoreAllMocks();
  });

  it("returns null when MIN_VERSION line is missing from script", () => {
    vi.spyOn(fs, "readFileSync").mockReturnValueOnce(
      "#!/usr/bin/env bash\n# no MIN_VERSION here\n",
    );

    const version = getExpectedOpenshellVersion();
    expect(version).toBeNull();

    vi.restoreAllMocks();
  });
});

describe("warnOnOpenshellVersionMismatch", () => {
  let stderrOutput;

  beforeEach(() => {
    stderrOutput = [];
    vi.spyOn(console, "error").mockImplementation((...args) => stderrOutput.push(args.join(" ")));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("emits no warning when versions match", () => {
    vi.spyOn(fs, "readFileSync").mockReturnValueOnce('MIN_VERSION="0.0.22"\n');
    warnOnOpenshellVersionMismatch("0.0.22");
    expect(stderrOutput).toHaveLength(0);
  });

  it("warns when installed version is newer", () => {
    vi.spyOn(fs, "readFileSync").mockReturnValueOnce('MIN_VERSION="0.0.22"\n');
    warnOnOpenshellVersionMismatch("0.0.23");
    expect(stderrOutput.some((l) => l.includes("newer"))).toBe(true);
    expect(stderrOutput.some((l) => l.includes("0.0.23"))).toBe(true);
    expect(stderrOutput.some((l) => l.includes("0.0.22"))).toBe(true);
  });

  it("warns when installed version is older", () => {
    vi.spyOn(fs, "readFileSync").mockReturnValueOnce('MIN_VERSION="0.0.22"\n');
    warnOnOpenshellVersionMismatch("0.0.7");
    expect(stderrOutput.some((l) => l.includes("older"))).toBe(true);
    expect(stderrOutput.some((l) => l.includes("0.0.7"))).toBe(true);
    expect(stderrOutput.some((l) => l.includes("0.0.22"))).toBe(true);
  });

  it("skips gracefully when install script is missing (no crash)", () => {
    vi.spyOn(fs, "readFileSync").mockImplementation((p) => {
      if (String(p).endsWith("install-openshell.sh")) throw new Error("ENOENT");
      throw new Error("unexpected");
    });
    // Should not throw even if expectedVersion is null
    expect(() => warnOnOpenshellVersionMismatch("0.0.7")).not.toThrow();
    expect(stderrOutput).toHaveLength(0);
  });

  it("skips gracefully when installed version is empty/null", () => {
    vi.spyOn(fs, "readFileSync").mockReturnValueOnce('MIN_VERSION="0.0.22"\n');
    expect(() => warnOnOpenshellVersionMismatch(null)).not.toThrow();
    expect(() => warnOnOpenshellVersionMismatch("")).not.toThrow();
    expect(stderrOutput).toHaveLength(0);
  });
});
