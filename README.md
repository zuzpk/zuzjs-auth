# @zuzjs/auth
Secure OAuth2 for the modern web. Zero dependencies, maximum safety.

**@zuzjs/auth** is a lightweight, framework-agnostic TypeScript library designed to handle the "Sign-In and Return Tokens" flow using the modern PKCE (Proof Key for Code Exchange) standard. No heavy dependencies, no bloated middleware—just pure Web Crypto and Fetch.

## Supported Flows

- OAuth2/OIDC redirect flow via `auth.signIn(providerId)` + `auth.handleRedirect()`
- Direct email/password token flow via `auth.signInWithEmailAndPassword(...)`
- Create user + token flow via `auth.createUserWithEmailAndPassword(...)`
- Anonymous token flow via `auth.signInAnonymously(...)`

## Built-in Providers

- `google`
- `dropbox`
- `apple`
- `facebook`
- `twitter` (X OAuth2)
- `github`
- `credentials` (direct token endpoint)
- `anonymous` (client credentials style token endpoint)

## Phone Sign-In

`auth.signInWithPhone(...)` intentionally throws `PHONE_AUTH_REQUIRES_BACKEND`.

Phone auth needs a trusted backend for SMS provider credentials, OTP replay protection, anti-abuse checks, and rate-limiting. Recommended approach:

1. Verify OTP on your backend.
2. Mint/return OAuth-style access and refresh tokens.
3. Consume those tokens in your app with your existing auth flow.