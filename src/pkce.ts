/**
 * PKCE (Proof Key for Code Exchange) — RFC 7636
 * Uses Web Crypto API exclusively. No external dependencies.
 */

/**
 * Converts an ArrayBuffer to a Base64URL-encoded string.
 * Base64URL differs from Base64 in three ways:
 *   '+' → '-'
 *   '/' → '_'
 *   '=' padding removed
 */
function arrayBufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // btoa produces standard Base64; we transform to Base64URL
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Generates a cryptographically random code_verifier.
 * Spec requires 43–128 characters from [A-Z a-z 0-9 - . _ ~].
 * We generate 32 random bytes → 43-char Base64URL string (fits perfectly).
 */
export function generateVerifier(): string {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return arrayBufferToBase64URL(randomBytes.buffer);
}

/**
 * Derives the code_challenge from a verifier using S256 method.
 * Algorithm: BASE64URL(SHA-256(ASCII(code_verifier)))
 */
export async function generateChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return arrayBufferToBase64URL(digest);
}

/**
 * Generates a cryptographically random state token for CSRF protection.
 * 16 bytes → 22-char Base64URL string.
 */
export function generateState(): string {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  return arrayBufferToBase64URL(randomBytes.buffer);
}