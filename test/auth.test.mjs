import assert from "node:assert/strict";
import test from "node:test";
const memoryStorage = () => {
  const values = new Map();
  return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: (key) => values.delete(key) };
};
const browser = (search = "", pathname = "/zauth") => {
  const storage = memoryStorage();
  const location = { search, href: `https://app.example${pathname}${search}`, origin: "https://app.example", pathname };
  return { storage, window: { location, history: { replaceState(_state, _title, url) { location.href = url; location.search = new URL(url).search; } } } };
};
const installBrowser = (env) => {
  const original = { window: globalThis.window, sessionStorage: globalThis.sessionStorage, fetch: globalThis.fetch };
  globalThis.window = env.window;
  globalThis.sessionStorage = env.storage;
  return () => Object.assign(globalThis, original);
};
const credentialsProvider = (overrides = {}) => ({
  name: "credentials", authorization_url: "https://auth.example/authorize", token_url: "https://auth.example/token", user_info_url: "", scopes: [], pkce_supported: false, token_transport: "bearer", clientId: "public-client", clientSecret: "must-not-be-sent", ...overrides,
});
const { AuthError, AuthGuard, ServerAuthGuard } = await import("../dist/index.js");

test("provider errors are surfaced and clear all callback state", async () => {
  const env = browser("?error=access_denied&error_description=Cancelled&state=state-1");
  const restore = installBrowser(env);
  try {
    env.storage.setItem("@zuzjs/auth:auth_state", JSON.stringify({ verifier: "verifier", state: "state-1", provider: "credentials", redirectUri: "https://app.example/zauth", metaTag: "" }));
    env.storage.setItem("@zuzjs/auth:auth_state-return-to", "/account");
    const auth = new AuthGuard({ providers: [credentialsProvider()] });
    await assert.rejects(auth.handleRedirect(), (error) => error instanceof AuthError && error.code === "PROVIDER_ERROR");
    assert.equal(env.storage.getItem("@zuzjs/auth:auth_state"), null);
    assert.equal(env.storage.getItem("@zuzjs/auth:auth_state-return-to"), null);
    assert.equal(env.window.location.search, "");
  } finally { restore(); }
});

test("browser code exchange always sends PKCE but never a client secret", async () => {
  const env = browser("?code=auth-code&state=state-1");
  const restore = installBrowser(env);
  try {
    env.storage.setItem("@zuzjs/auth:auth_state", JSON.stringify({ verifier: "verifier", state: "state-1", provider: "credentials", redirectUri: "https://app.example/zauth", metaTag: "" }));
    let requestBody = "";
    globalThis.fetch = async (_url, init) => { requestBody = String(init?.body ?? ""); return new Response(JSON.stringify({ access_token: "access", expires_in: 3600 }), { status: 200 }); };
    const token = await new AuthGuard({ providers: [credentialsProvider()] }).handleRedirect();
    assert.equal(token.access_token, "access");
    const form = new URLSearchParams(requestBody);
    assert.equal(form.get("code_verifier"), "verifier");
    assert.equal(form.has("client_secret"), false);
  } finally { restore(); }
});

test("signIn requires a safe same-origin return path and forces PKCE S256", async () => {
  const env = browser("", "/dashboard");
  const restore = installBrowser(env);
  try {
    const auth = new AuthGuard({ providers: [credentialsProvider()] });
    await assert.rejects(auth.signIn("credentials", { returnTo: "//evil.example" }), (error) => error instanceof AuthError && error.code === "INVALID_RETURN_TO");
    await assert.rejects(auth.signIn("credentials", { returnTo: "/account?tab=security" }), (error) => error instanceof AuthError && error.code === "NAVIGATION_FAILED");
    const url = new URL(env.window.location.href);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.ok(url.searchParams.get("code_challenge"));
  } finally { restore(); }
});

test("refresh response and malformed JSON are validated with useful errors", async () => {
  const env = browser();
  const restore = installBrowser(env);
  try {
    const auth = new AuthGuard({ providers: [credentialsProvider()] });
    globalThis.fetch = async () => new Response("not-json", { status: 200 });
    await assert.rejects(auth.signInAnonymously({ providerId: "credentials" }), (error) => error instanceof AuthError && error.message.includes("Response body: not-json"));
    globalThis.fetch = async () => new Response(JSON.stringify({ access_token: "access" }), { status: 200 });
    await assert.rejects(auth.refreshAuthToken("credentials", "refresh"), (error) => error instanceof AuthError && error.code === "INVALID_TOKEN_RESPONSE");
  } finally { restore(); }
});

test("ServerAuthGuard uses a server secret, PKCE verifier, and normalized provider profile", async () => {
  const requests = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    if (String(url) === "https://auth.example/token") return new Response(JSON.stringify({ access_token: "server-access", refresh_token: "server-refresh", expires_in: 3600 }), { status: 200 });
    if (String(url) === "https://auth.example/me") return new Response(JSON.stringify({ id: "user-1", email: "user@example.com", display_name: "User" }), { status: 200 });
    throw new Error(`Unexpected URL: ${url}`);
  };
  try {
    const auth = new ServerAuthGuard({ providers: [credentialsProvider({ user_info_url: "https://auth.example/me", profileMethod: "GET", normalizeProfile: (raw) => ({ id: String(raw.id), email: raw.email, name: raw.display_name, avatar_url: null, raw }) })] });
    const token = await auth.getAuthTokenByCode({ code: "code", session: { verifier: "verifier", state: "state", provider: "credentials", redirectUri: "https://app.example/zauth", metaTag: "" } });
    assert.equal(token.profile?.id, "user-1");
    assert.equal(token.profile?.name, "User");
    const form = new URLSearchParams(String(requests[0].init.body));
    assert.equal(form.get("client_secret"), "must-not-be-sent");
    assert.equal(form.get("code_verifier"), "verifier");
  } finally { globalThis.fetch = originalFetch; }
});
