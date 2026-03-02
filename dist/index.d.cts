type ProviderId = keyof typeof Providers;
interface OAuthProvider extends OAuthProviderParams {
    /** Human-readable name */
    name: string;
    /** OAuth2 authorization endpoint */
    authorization_url: string;
    /** OAuth2 token exchange endpoint */
    token_url: string;
    /** Endpoint to fetch authenticated user's profile */
    user_info_url: string;
    /** Default scopes to request */
    default_scopes: string[];
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
interface OAuthProviderParams {
    clientId?: string;
    clientSecret?: string;
}
interface NormalizedProfile {
    id: string;
    email: string | null;
    name: string | null;
    avatar_url: string | null;
    raw: Record<string, unknown>;
}
interface AuthConfig {
    /** OAuth2 client_id for each provider you want to support */
    providers: (OAuthProvider | ((options?: OAuthProviderParams) => OAuthProvider))[];
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
    fetchTokenInfoOnServer?: boolean;
}
interface StoredPKCEState {
    verifier: string;
    state: string;
    provider: ProviderId;
    redirectUri: string;
}
interface AuthToken {
    access_token: string;
    refresh_token: string | null;
    expires_in: number | null;
    token_type: string;
    scope: string | null;
    profile: NormalizedProfile | null;
    provider: ProviderId;
}

declare const Dropbox: (options?: OAuthProviderParams) => OAuthProvider;

declare const Google: (options?: OAuthProviderParams) => OAuthProvider;

declare const Providers: {
    google: (options?: OAuthProviderParams) => OAuthProvider;
    dropbox: (options?: OAuthProviderParams) => OAuthProvider;
};
declare function setupProvider(provider: any): OAuthProvider;

declare class AuthGuard {
    private readonly config;
    private readonly providers;
    constructor(config: AuthConfig);
    private getProvider;
    private getClientId;
    private resolveScopes;
    private saveSession;
    private loadSession;
    private clearSession;
    private exchangeCode;
    private fetchProfile;
    private fetchJSON;
    getAuthTokenByCode({ code, session }: {
        code: string;
        session: StoredPKCEState;
    }): Promise<AuthToken>;
    handleRedirect(): Promise<any>;
    /**
     * Checks whether the current page load is an OAuth callback.
     * Useful for conditional rendering ("Loading…" vs normal page).
     */
    isCallback(): boolean;
    /**
    * Initiates the OAuth2 sign-in flow for the given provider.
    * Generates PKCE verifier + challenge, stores them in sessionStorage,
    * then redirects the browser to the provider's authorization URL.
    *
    * @param providerId - One of "google" | "dropbox" | "github"
    */
    signIn(providerId: ProviderId): Promise<any>;
}

export { AuthGuard, Dropbox, Google, type NormalizedProfile, type OAuthProvider, type ProviderId, Providers, setupProvider };
