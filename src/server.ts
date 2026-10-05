import { AuthError } from "./client";
import { setupProvider } from "./providers";
import {
  AuthConfig,
  AuthToken,
  NormalizedProfile,
  OAuthProvider,
  ProviderId,
  RefreshResult,
  StoredPKCEState,
} from "./types";

/**
 * Server-only OAuth helper for confidential-client token exchanges.
 * Never import or instantiate this class in browser/client-component code.
 */
export class ServerAuthGuard {
  private readonly config: AuthConfig;
  private readonly providers: Map<ProviderId, OAuthProvider>;

  constructor(config: AuthConfig) {
    this.config = config;
    this.providers = new Map(
      config.providers.map((input) => {
        const provider = setupProvider(input);
        return [provider.name as ProviderId, provider];
      })
    );

    this.getAuthTokenByCode = this.getAuthTokenByCode.bind(this);
    this.refreshAuthToken = this.refreshAuthToken.bind(this);
  }

  private getProvider(id: ProviderId): OAuthProvider {
    const provider = this.providers.get(id);
    if (!provider) throw new AuthError(`Provider ${id} not configured.`, "MISSING_PROVIDER");
    return provider;
  }

  private getClientId(provider: OAuthProvider): string {
    const envKey = `AUTH_${provider.name.toUpperCase()}_ID`;
    const clientId = provider.clientId ?? process.env[envKey];
    if (!clientId) throw new AuthError(`No Client ID for ${provider.name}`, "MISSING_CONFIG");
    return clientId;
  }

  private requireEndpoint(value: string | undefined, name: string, providerName: string): string {
    if (!value) throw new AuthError(`${name} is required for provider ${providerName}.`, "MISSING_PROVIDER_ENDPOINT");
    return value;
  }

  private optionalString(value: unknown): string | undefined {
    return typeof value === "string" && value.length > 0 ? value : undefined;
  }

  private optionalNumber(value: unknown): number | undefined {
    return typeof value === "number" && Number.isFinite(value) ? value : undefined;
  }

  private parseTokenResponse(response: Record<string, unknown>): Omit<AuthToken, "profile" | "provider"> {
    const access_token = this.optionalString(response.access_token);
    if (!access_token) {
      throw new AuthError("Token exchange succeeded but no string access_token was returned.", "NO_ACCESS_TOKEN");
    }
    return {
      access_token,
      refresh_token: this.optionalString(response.refresh_token) ?? null,
      expires_in: this.optionalNumber(response.expires_in) ?? null,
      token_type: this.optionalString(response.token_type) ?? "Bearer",
      scope: this.optionalString(response.scope) ?? null,
    };
  }

  private parseRefreshResponse(response: Record<string, unknown>): RefreshResult {
    const access_token = this.optionalString(response.access_token);
    const expires_in = this.optionalNumber(response.expires_in);
    if (!access_token || expires_in === undefined) {
      throw new AuthError("Refresh response must include a string access_token and numeric expires_in.", "INVALID_TOKEN_RESPONSE");
    }
    const refresh_token = this.optionalString(response.refresh_token);
    return {
      access_token,
      expires_in,
      token_type: this.optionalString(response.token_type) ?? "Bearer",
      ...(refresh_token ? { refresh_token } : {}),
    };
  }

  private async fetchJSON<T>(url: string, init: RequestInit, errorCode: string): Promise<T> {
    let response: Response;
    try {
      response = await fetch(url, init);
    } catch (cause) {
      throw new AuthError(`Network request failed for ${url}.`, errorCode, cause);
    }

    const text = await response.text().catch(() => "");
    if (!response.ok) {
      const detail = text ? ` Server says: ${text.slice(0, 240)}` : "";
      throw new AuthError(`Request failed (${response.status} ${response.statusText}) for ${url}.${detail}`, errorCode, undefined, response.status);
    }
    if (response.status === 204) return {} as T;
    try {
      return JSON.parse(text) as T;
    } catch (cause) {
      const detail = text ? ` Response body: ${text.slice(0, 240)}` : "";
      throw new AuthError(`Failed to parse JSON response from ${url}.${detail}`, errorCode, cause);
    }
  }

  private async fetchProfile(provider: OAuthProvider, accessToken: string): Promise<NormalizedProfile | null> {
    if (!provider.user_info_url) return null;
    try {
      let url = provider.user_info_url;
      const headers: Record<string, string> = { Accept: "application/json" };
      if (provider.token_transport === "bearer") headers.Authorization = `Bearer ${accessToken}`;
      else url = `${url}${url.includes("?") ? "&" : "?"}access_token=${encodeURIComponent(accessToken)}`;

      const method = provider.profileMethod ?? (provider.user_info_url.includes("dropboxapi") ? "POST" : "GET");
      const init: RequestInit = { method, headers };
      if (method === "POST") {
        headers["Content-Type"] = "application/json";
        init.body = provider.profileBody ?? "null";
      }
      const raw = await this.fetchJSON<Record<string, unknown>>(url, init, "PROFILE_FETCH_FAILED");
      return provider.normalizeProfile ? provider.normalizeProfile(raw) : null;
    } catch (error) {
      // Profiles are enrichment; a valid access token remains usable if this API fails.
      if (error instanceof AuthError && error.code === "PROFILE_FETCH_FAILED") return null;
      throw error;
    }
  }

  /** Exchange a PKCE authorization code using server-only confidential credentials. */
  async getAuthTokenByCode({ code, session }: { code: string; session: StoredPKCEState }): Promise<AuthToken> {
    try {
      if (!code || !session?.verifier || !session?.redirectUri || !session?.provider) {
        throw new AuthError("Invalid authorization-code exchange input.", "INVALID_EXCHANGE_INPUT");
      }
      const provider = this.getProvider(session.provider);
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: session.redirectUri,
        client_id: this.getClientId(provider),
        code_verifier: session.verifier,
      });
      if (provider.clientSecret) body.set("client_secret", provider.clientSecret);
      for (const [key, value] of Object.entries(provider.tokenParams ?? {})) body.set(key, value);

      const response = await this.fetchJSON<Record<string, unknown>>(
        this.requireEndpoint(provider.token_url, "token_url", provider.name),
        { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: body.toString() },
        "TOKEN_EXCHANGE_FAILED"
      );
      const parsed = this.parseTokenResponse(response);
      return { ...parsed, profile: await this.fetchProfile(provider, parsed.access_token), provider: session.provider };
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError(`Get token by code failed. ${error instanceof Error ? error.message : String(error)}`, "TOKEN_EXCHANGE_FAILED", error);
    }
  }

  /** Refresh a token using server-only confidential credentials when configured. */
  async refreshAuthToken(providerId: ProviderId, refreshToken: string): Promise<RefreshResult> {
    try {
      const provider = this.getProvider(providerId);
      const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: this.getClientId(provider) });
      if (provider.clientSecret) body.set("client_secret", provider.clientSecret);
      for (const [key, value] of Object.entries(provider.tokenParams ?? {})) body.set(key, value);
      const response = await this.fetchJSON<Record<string, unknown>>(
        this.requireEndpoint(provider.token_url, "token_url", provider.name),
        { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body: body.toString() },
        "TOKEN_REFRESH_FAILED"
      );
      return this.parseRefreshResponse(response);
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError(`Refresh token failed. ${error instanceof Error ? error.message : String(error)}`, "TOKEN_REFRESH_FAILED", error);
    }
  }
}
