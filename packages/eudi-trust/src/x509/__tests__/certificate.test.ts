import { describe, expect, it } from "vitest";

import {
  includesCertificate,
  normalizeCertificate,
  normalizeDistinguishedName,
} from "../certificate";

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

describe("normalizeDistinguishedName", () => {
  it("ignores the case, the spacing and the order of the RDNs", () => {
    expect(normalizeDistinguishedName("CN = Issuer CA , O=Provider,C=IT")).toBe(
      normalizeDistinguishedName("c=it,o=provider,cn=issuer ca"),
    );
  });

  it("does not split on an escaped comma", () => {
    expect(normalizeDistinguishedName("O=Foo\\, Inc.,C=IT")).toBe(
      "c=it,o=foo\\, inc.",
    );
  });

  it("handles long runs of whitespace", () => {
    expect(normalizeDistinguishedName(`${" ".repeat(100_000)}x`)).toBe("x");
    expect(normalizeDistinguishedName(`CN${" ".repeat(100_000)}`)).toBe("cn");
  });
});
