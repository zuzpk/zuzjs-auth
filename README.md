# @zuzjs/auth

Browser-focused OAuth 2.0 authorization-code and PKCE helpers for TypeScript applications.

`@zuzjs/auth` provides framework-agnostic redirect handling, PKCE S256, CSRF-state validation, token-response validation, and optional normalized profiles. It uses Web Crypto and Fetch; the published bundle has no runtime dependency imports.

## Security model

- Browser authorization-code redirects always use **PKCE S256** and validate `state`.
- Browser flows never transmit `clientSecret`. Use a trusted backend for confidential-client exchanges, refreshes that require a secret, OIDC ID-token validation, and any privileged grant.
- To exchange the authorization code on your backend, set `exchangeCodeInBrowser: false` (the legacy `fetchTokenInfoOnServer: false` remains supported). `handleRedirect()` then returns `{ code, session, returnTo, metaTag }`.
- This package does **not** verify OIDC `id_token` JWTs. Validate signatures, issuer, audience, nonce, and expiry against JWKS on your backend before treating an OIDC identity as authenticated.
- `returnTo` accepts only same-origin application paths.

## Supported flows

- OAuth2 redirect flow: `auth.signIn(providerId)` + `auth.handleRedirect()`
- Direct email/password token flow: `auth.signInWithEmailAndPassword(...)`
- Create-user plus token flow: `auth.createUserWithEmailAndPassword(...)`
- Anonymous token flow: `auth.signInAnonymously(...)`

> Direct password and client-credentials-style grants are only safe when the provider explicitly supports browser use and does not require a secret. Prefer a backend for confidential providers.

## Example

```ts
import { AuthGuard, Google } from "@zuzjs/auth";

const auth = new AuthGuard({
  providers: [Google({ clientId: "your-public-client-id" })],
  redirectUri: "https://app.example.com/zauth",
});

await auth.signIn("google", { returnTo: "/dashboard" });
// On the callback route:
const result = await auth.handleRedirect();
```

For a backend token exchange:

```ts
const auth = new AuthGuard({
  providers: [Google({ clientId: "your-public-client-id" })],
  exchangeCodeInBrowser: false,
});

const pending = await auth.handleRedirect();
// Send pending.code and pending.session to your trusted backend over HTTPS.
```

## Built-in providers

- `google`
- `dropbox`
- `apple`
- `facebook`
- `twitter` (X OAuth2)
- `github`
- `credentials` (direct token endpoint)
- `anonymous` (client-credentials-style token endpoint)

### Apple

Apple identity claims are provided through its ID token and one-time authorization response. This package intentionally does not call an Apple userinfo endpoint. Process and validate Apple identity data on a trusted backend.

## Phone sign-in

`auth.signInWithPhone(...)` intentionally throws `PHONE_AUTH_REQUIRES_BACKEND`.

Phone auth requires a trusted backend for SMS-provider credentials, OTP replay protection, anti-abuse checks, and rate limiting:

1. Verify OTP on your backend.
2. Mint or return OAuth-style access/refresh tokens.
3. Consume those tokens in your application.
