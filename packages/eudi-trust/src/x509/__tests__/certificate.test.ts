import { describe, expect, it } from "vitest";

import { includesCertificate, normalizeCertificate } from "../certificate";

describe("includesCertificate", () => {
  const certificate = "a+/b==";

  it("matches a certificate regardless of alphabet, padding and whitespace", () => {
    expect(includesCertificate([certificate], " a-_b\n")).toBe(true);
    expect(includesCertificate(["a-_b"], certificate)).toBe(true);
  });

  it("does not match a different certificate", () => {
    expect(includesCertificate([certificate], "a+/c==")).toBe(false);
    expect(includesCertificate([], certificate)).toBe(false);
  });
});

describe("normalizeCertificate", () => {
  it("strips only the trailing padding", () => {
    expect(normalizeCertificate("ab=cd==")).toBe("ab=cd");
  });

  it("handles long runs of padding characters", () => {
    expect(normalizeCertificate(`${"=".repeat(100_000)}x`)).toBe(
      `${"=".repeat(100_000)}x`,
    );
  });
});
