import { Providers } from "./providers";

/** Built-in provider IDs plus names supplied by custom provider configurations. */
export type ProviderId = keyof typeof Providers | (string & {});

export interface OAuthProvider extends OAuthProviderParams {
  /** Human-readable provider identifier. */
  name: string;
  /** OAuth2 authorization endpoint. */
  authorization_url: string;
  /** OAuth2 token exchange endpoint. */
  token_url: string;
  /** Endpoint to fetch the authenticated user's profile, when available. */
  user_info_url: string;
  /** Default scopes to request. */
  scopes: string[];
  /**
   * Retained for compatibility. Browser authorization-code flows always use
   * PKCE S256, regardless of this value.
   */
  pkce_supported: boolean;
  /**
   * How to pass the token when fetching user info.
   * "bearer" → Authorization: Bearer <token>
   * "query" is legacy and should be avoided because URL tokens can leak.
   */
  token_transport: "bearer" | "query";
  /** Map a raw provider profile to the library's normalized profile. */
  normalizeProfile?: (raw: Record<string, unknown>) => NormalizedProfile;
  /** HTTP method for profile retrieval; defaults to GET (Dropbox defaults to POST). */
  profileMethod?: "GET" | "POST";
  /** Optional POST request body for profile retrieval. */
  profileBody?: BodyInit | null;
  clientId?: string;
  /**
   * Kept for server-side compatibility. AuthGuard is browser-oriented and
   * never sends this value; perform confidential-client exchanges on a backend.
   */
  clientSecret?: string;
  /** Optional additional query params added during authorization redirect. */
  authorizationParams?: Record<string, string>;
  /** Optional additional form params added during token exchange. */
  tokenParams?: Record<string, string>;
  /** Grant type for direct email/password sign-in. Defaults to "password". */
  passwordGrantType?: string;
  /** Endpoint to create a user via email/password; defaults to token_url. */
  createUserUrl?: string;
  /** Grant type for create-user flow; defaults to passwordGrantType or "password". */
  createUserGrantType?: string;
  /** Field name for email in a create-user body; defaults to usernameField or "username". */
  createUserEmailField?: string;
  /** Field name for password in a create-user body; defaults to passwordField or "password". */
  createUserPasswordField?: string;
  /** Optional extra form fields added during create-user requests. */
  createUserParams?: Record<string, string>;
  /** Field name for email/username in password-grant body. Defaults to "username". */
  usernameField?: string;
  /** Field name for password in password-grant body. Defaults to "password". */
  passwordField?: string;
  /** Grant type for anonymous sign-in. Defaults to "client_credentials". */
  anonymousGrantType?: string;
}

export interface OAuthProviderParams {
  clientId?: string;
  /** Kept for server-side compatibility; never transmitted by AuthGuard. */
  clientSecret?: string;
  scopes?: string[];
}

export type OAuthProviderFactory = (options?: OAuthProviderParams) => OAuthProvider;
export type OAuthProviderInput = OAuthProvider | OAuthProviderFactory;

export interface NormalizedProfile {
  id: string;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  raw: Record<string, unknown>;
}

export interface AuthConfig {
  /** OAuth providers enabled for this guard. */
  providers: OAuthProviderInput[];
  /** Registered OAuth redirect URI. Defaults to `${location.origin}/zauth`. */
  redirectUri?: string;
  /** Per-provider scope overrides. */
  scopes?: Partial<Record<ProviderId, string[]>>;
  /** Storage key prefix for sessionStorage entries. */
  storageKey?: string;
  /**
   * Legacy option retained for compatibility. true (the default) exchanges in
   * the browser; false returns code/session material for a backend exchange.
   * Prefer exchangeCodeInBrowser in new integrations.
   */
  fetchTokenInfoOnServer?: boolean;
  /**
   * Explicit replacement for fetchTokenInfoOnServer. Defaults to the legacy
   * option's effective behavior (true). Set false for a backend exchange.
   */
  exchangeCodeInBrowser?: boolean;
}

export interface SignInWithEmailAndPasswordInput {
  providerId: ProviderId;
  email: string;
  password: string;
  scope?: string[];
}

export interface CreateUserWithEmailAndPasswordInput {
  providerId: ProviderId;
  email: string;
  password: string;
  scope?: string[];
  additionalParams?: Record<string, string>;
}

/** @deprecated Use SignInWithEmailAndPasswordInput instead. */
export type SignInWithEmailInput = SignInWithEmailAndPasswordInput;

export interface SignInAnonymouslyInput {
  providerId: ProviderId;
  scope?: string[];
}

export interface SignInWithPhoneInput {
  phoneNumber: string;
  code?: string;
}

export interface StoredPKCEState {
  verifier: string;
  state: string;
  provider: ProviderId;
  redirectUri: string;
  metaTag: string;
}

export interface AuthToken {
  access_token: string;
  refresh_token: string | null;
  expires_in: number | null;
  token_type: string;
  scope: string | null;
  profile: NormalizedProfile | null;
  provider: ProviderId;
}

export interface RefreshResult {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

export interface PendingCodeExchange {
  code: string;
  session: StoredPKCEState;
  returnTo?: string;
  metaTag?: string;
}

export type RedirectResult = (AuthToken | PendingCodeExchange) & {
  returnTo?: string;
  metaTag?: string;
};

export interface SignInOptions {
  /** The same-origin application path to return to after sign-in. */
  returnTo?: string;
  /** Application-defined metadata retained through the OAuth redirect. */
  metaTag?: string;
}
