import { Providers } from "./providers";

export type ProviderId = keyof typeof Providers

export interface OAuthProvider extends OAuthProviderParams {
  /** Human-readable name */
  name: string;
  /** OAuth2 authorization endpoint */
  authorization_url: string;
  /** OAuth2 token exchange endpoint */
  token_url: string;
  /** Endpoint to fetch authenticated user's profile */
  user_info_url: string;
  /** Default scopes to request */
  scopes: string[];
  /** Whether this provider supports PKCE (all modern providers do) */
  pkce_supported: boolean;
  /**
   * How to pass the token when fetching user info.
   * "bearer" → Authorization: Bearer <token>
   * "query"  → ?access_token=<token> (legacy, e.g. older GitHub)
   */
  token_transport: "bearer" | "query";
  /**
   * Optional: map raw provider profile fields to a normalized shape.
   * If omitted, the raw response is returned as-is.
   */
  normalizeProfile?: (raw: Record<string, unknown>) => NormalizedProfile;
  clientId?: string;
  clientSecret?: string;
} 

export interface OAuthProviderParams {
    clientId?: string;
    clientSecret?: string;
    scopes?: string[];
}

export interface NormalizedProfile {
  id: string;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  raw: Record<string, unknown>;
}

export interface AuthConfig {
    /** OAuth2 client_id for each provider you want to support */
    // clientId: Partial<Record<ProviderId, string>>;
    providers: (OAuthProvider | ((options?: OAuthProviderParams) => OAuthProvider))[],
    /**
     * The URL your app redirects back to after OAuth consent.
     * Must be registered in the provider's developer console.
     */
    redirectUri?: string;
    /**
     * Optional per-provider scope overrides.
     * Merged with (and takes precedence over) provider defaults.
     */
    scopes?: Partial<Record<ProviderId, string[]>>;
    /**
     * Storage key prefix for sessionStorage entries.
     * Defaults to "__guard_".
     */
    storageKey?: string;

    /**
     * If true will fetchToken Details on client side
     * If false then only code will be returned
     * @default true
     */
    fetchTokenInfoOnServer?: boolean

}

export interface StoredPKCEState {
  verifier: string;
  state: string;
  provider: ProviderId;
  redirectUri: string;
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