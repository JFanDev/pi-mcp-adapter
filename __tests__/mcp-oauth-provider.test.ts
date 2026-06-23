import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { McpOAuthProvider } from "../mcp-oauth-provider.js";
import { updateOAuthState } from "../mcp-auth.js";

describe("McpOAuthProvider authorization fallback", () => {
  const originalOAuthDir = process.env.MCP_OAUTH_DIR;
  const serverUrl = "https://api.example.com/mcp";
  let authDir: string;

  beforeEach(() => {
    authDir = mkdtempSync(join(tmpdir(), "pi-mcp-oauth-provider-"));
    process.env.MCP_OAUTH_DIR = authDir;
  });

  afterEach(() => {
    rmSync(authDir, { recursive: true, force: true });
    if (originalOAuthDir === undefined) {
      delete process.env.MCP_OAUTH_DIR;
    } else {
      process.env.MCP_OAUTH_DIR = originalOAuthDir;
    }
  });

  it("includes configured scope in client metadata", () => {
    const provider = new McpOAuthProvider("scoped", serverUrl, { scope: "mcp:employee:write" }, { onRedirect: async () => {} });

    expect(provider.clientMetadata.scope).toBe("mcp:employee:write");
  });

  it("uses configured resource when its origin matches the server", async () => {
    const provider = new McpOAuthProvider(
      "resource-match",
      serverUrl,
      { resource: "https://api.example.com/" },
      { onRedirect: async () => {} },
    );

    await expect(provider.validateResourceURL!(serverUrl)).resolves.toEqual(new URL("https://api.example.com/"));
  });

  it("rejects configured resource from a different origin", async () => {
    const provider = new McpOAuthProvider(
      "resource-mismatch",
      serverUrl,
      { resource: "https://other.example.com/" },
      { onRedirect: async () => {} },
    );

    await expect(provider.validateResourceURL!(serverUrl)).rejects.toThrow(/does not match MCP server/);
  });

  it("throws UnauthorizedError when state is requested outside a user-initiated flow", async () => {
    const provider = new McpOAuthProvider("state-missing", serverUrl, {}, { onRedirect: async () => {} });

    await expect(provider.state()).rejects.toBeInstanceOf(UnauthorizedError);
    await expect(provider.state()).rejects.toThrow(/Re-authentication required/);
  });

  it("throws UnauthorizedError before redirecting when no OAuth flow is in progress", async () => {
    let redirected = false;
    const provider = new McpOAuthProvider("redirect-missing", serverUrl, {}, {
      onRedirect: async () => {
        redirected = true;
      },
    });

    await expect(provider.redirectToAuthorization(new URL("https://auth.example.com/authorize")))
      .rejects.toBeInstanceOf(UnauthorizedError);
    expect(redirected).toBe(false);
  });

  it("still redirects when startAuth has seeded OAuth state", async () => {
    const authUrl = new URL("https://auth.example.com/authorize");
    let redirected: URL | undefined;
    updateOAuthState("redirect-active", "state-abc");
    const provider = new McpOAuthProvider("redirect-active", serverUrl, {}, {
      onRedirect: async (url) => {
        redirected = url;
      },
    });

    await provider.redirectToAuthorization(authUrl);

    expect(redirected).toBe(authUrl);
  });
});
