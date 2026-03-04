import { generateChallenge, generateState, generateVerifier } from "./pkce";
import { setupProvider } from "./providers";
import { AuthConfig, AuthToken, NormalizedProfile, OAuthProvider, ProviderId, RefreshResult, StoredPKCEState } from "./types";

const STORAGE_KEY_AUTH_STATE = "@zuzjs/auth:auth_state";
const STORAGE_KEY_DISCOVERY_CACHE = "@zuzjs/auth:discovery";

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export class AuthGuard {

    private readonly config: AuthConfig;
    private readonly providers: Map<ProviderId, OAuthProvider>;

    constructor(config: AuthConfig) {
        this.config = {
            ...config,
            fetchTokenInfoOnServer: config.fetchTokenInfoOnServer ?? true,
            storageKey: config.storageKey ?? STORAGE_KEY_AUTH_STATE,
        };
        this.providers = new Map();
        // Normalize the providers passed in the config
        config.providers.forEach((p) => {
            const initialized = setupProvider(p);
            this.providers.set(initialized.name as ProviderId, initialized);
        });

        // BIND METHODS TO PREVENT 'THIS' ERRORS
        this.signIn = this.signIn.bind(this);
        this.handleRedirect = this.handleRedirect.bind(this);
        this.isCallback = this.isCallback.bind(this);
        this.getAuthTokenByCode = this.getAuthTokenByCode.bind(this);
        this.refreshAuthToken = this.refreshAuthToken.bind(this);
    }

    private getProvider(id: ProviderId): OAuthProvider {
        const provider = this.providers.get(id);
        if (!provider) {
            throw new AuthError(`Provider ${id.toString()} not configured.`, "MISSING_PROVIDER");
        }
        return provider;
    }

    private getClientId(provider: OAuthProvider): string {
        
        // Check object property
        if (provider.clientId) return provider.clientId;

        // Check Environment (matches NEXTAUTH_ style or your custom ZUZ_ style)
        const envKey = `AUTH_${provider.name.toUpperCase()}_ID`;
        const envValue = typeof process !== "undefined" ? process.env[envKey] : undefined;

        if (!envValue) {
        throw new AuthError(`No Client ID for ${provider.name}`, "MISSING_CONFIG");
        }
        return envValue;
    }

    private resolveScopes(providerId: ProviderId, provider: OAuthProvider): string {
        const overrides = this.config.scopes?.[providerId];
        const scopes = overrides ?? provider.scopes;
        return scopes.join(" ");
    }

    private saveSession(data: StoredPKCEState, returnTo?: string): void {
        try {
            sessionStorage.setItem(this.config.storageKey!, JSON.stringify(data));
            if ( returnTo ) sessionStorage.setItem(`${this.config.storageKey!}-return-to`, returnTo);
        } catch {
        throw new AuthError(
            "Failed to write to sessionStorage. Ensure the browser allows storage.",
            "STORAGE_WRITE_FAILED"
        );
        }
    }

    private loadSession(): StoredPKCEState {
        const raw = sessionStorage.getItem(this.config.storageKey!);
        if (!raw) {
            throw new AuthError(
                "No PKCE session found. The sign-in flow may not have been initiated correctly.",
                "SESSION_NOT_FOUND"
            );
        }
        try {
            return JSON.parse(raw) as StoredPKCEState;
        } catch {
            throw new AuthError(
                "Corrupted PKCE session in sessionStorage.",
                "SESSION_CORRUPT"
            );
        }
    }

    private clearSession(): void {
        sessionStorage.removeItem(this.config.storageKey!);
    }

    private async exchangeCode(opts: {
        code: string;
        session: StoredPKCEState;
        provider: OAuthProvider;
        clientId: string;
    }): Promise<AuthToken> {

        const { code, session, provider, clientId } = opts;

        const body = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: session.redirectUri,
            client_id: clientId,
        });

        if (provider.clientSecret) {
            body.set("client_secret", provider.clientSecret);
        }

        if (provider.pkce_supported) {
            body.set("code_verifier", session.verifier);
        }

        const tokenResponse = await this.fetchJSON<Record<string, unknown>>(
            provider.token_url,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    // GitHub requires this to get JSON back
                    Accept: "application/json",
                },
                body: body.toString(),
            },
            "TOKEN_EXCHANGE_FAILED"
        );

        const access_token = tokenResponse.access_token as string | undefined;
        if (!access_token) {
            throw new AuthError(
                "Token exchange succeeded but no access_token was returned.",
                "NO_ACCESS_TOKEN"
            );
        }

        const refresh_token = (tokenResponse.refresh_token as string) ?? null;
        const expires_in = (tokenResponse.expires_in as number) ?? null;
        const token_type = (tokenResponse.token_type as string) ?? "Bearer";
        const scope = (tokenResponse.scope as string) ?? null;

        // Fetch user profile
        const profile = await this.fetchProfile(provider, access_token);

        return {
            access_token,
            refresh_token,
            expires_in,
            token_type,
            scope,
            profile,
            provider: session.provider,
        };
    }

    private async fetchProfile(
        provider: OAuthProvider,
        access_token: string
    ): Promise<NormalizedProfile | null> {
        try {
        let url = provider.user_info_url;
        const headers: Record<string, string> = {
            Accept: "application/json",
        };

        if (provider.token_transport === "bearer") {
            headers["Authorization"] = `Bearer ${access_token}`;
        } else {
            url = `${url}?access_token=${encodeURIComponent(access_token)}`;
        }

        // Dropbox /2/users/get_current_account requires a POST with null body
        const method =
            provider.user_info_url.includes("dropboxapi") ? "POST" : "GET";
        const fetchOpts: RequestInit = { method, headers };
        if (method === "POST") {
            fetchOpts.body = "null";
            headers["Content-Type"] = "application/json";
        }

        const raw = await this.fetchJSON<Record<string, unknown>>(
            url,
            fetchOpts,
            "PROFILE_FETCH_FAILED"
        );

        return provider.normalizeProfile ? provider.normalizeProfile(raw) : null;
        } catch (err) {
        // Profile fetch failure is non-fatal — return null rather than throw
        if (err instanceof AuthError && err.code === "PROFILE_FETCH_FAILED") {
            return null;
        }
        throw err;
        }
    }

    private async fetchJSON<T>(
        url: string,
        init: RequestInit,
        errorCode: string
    ): Promise<T> {
        let response: Response;
        try {
        response = await fetch(url, init);
        } catch (networkErr) {
        throw new AuthError(
            `Network request failed: ${url}`,
            errorCode,
            networkErr
        );
        }

        if (!response.ok) {
        let body = "(no body)";
        try {
            body = await response.text();
        } catch {
            /* ignore */
        }
        throw new AuthError(
            `HTTP ${response.status} from ${url}: ${body}`,
            errorCode
        );
        }

        try {
        return (await response.json()) as T;
        } catch (parseErr) {
        throw new AuthError(
            `Failed to parse JSON response from ${url}`,
            errorCode,
            parseErr
        );
        }
    }

    async getAuthTokenByCode({ code, session }: {
        code: string;
        session: StoredPKCEState;
    }) : Promise<AuthToken> {
        const provider = this.getProvider(session.provider);
        const clientId = this.getClientId(provider);

        const tokenSet = await this.exchangeCode({
            code,
            session,
            provider,
            clientId,
        })

        return tokenSet

    }

    async handleRedirect(autoRedirect: boolean = false): Promise<any> {

        const params = new URLSearchParams(window.location.search);
        const code = params.get("code");
        const state = params.get("state");

        // Check if we are actually in a redirect flow
        if (!code) return null;

        const session = this.loadSession();

        // CSRF verification
        if (!state || state !== session.state) {
            this.clearSession();
            throw new AuthError(
                "State mismatch. Possible CSRF attack — request was rejected.",
                "STATE_MISMATCH"
            );
        }

        // Check for provider error response
        const error = params.get("error");
        if (error) {
            const description = params.get("error_description") ?? error;
            this.clearSession();
            throw new AuthError(
                `Provider returned an error: ${description}`,
                "PROVIDER_ERROR"
            );
        }

        // Clean the URL immediately (remove code, state, etc.)
        const cleanUrl = new URL(window.location.href);
        cleanUrl.searchParams.delete("code");
        cleanUrl.searchParams.delete("state");
        cleanUrl.searchParams.delete("scope");
        cleanUrl.searchParams.delete("error");
        cleanUrl.searchParams.delete("error_description");
        window.history.replaceState({}, "", cleanUrl.toString());

        const provider = this.getProvider(session.provider);
        const clientId = this.getClientId(provider);
        
        const returnTo = sessionStorage.getItem(`${this.config.storageKey!}-return-to`);
        
        let tokenSet : (AuthToken | { code: string; session: StoredPKCEState }) & {
            returnTo: string | undefined
        };

        if ( this.config.fetchTokenInfoOnServer === true ){
    
            tokenSet = {
                ...(await this.exchangeCode({
                    code,
                    session,
                    provider,
                    clientId,
                })),
                returnTo: returnTo ?? undefined
            };

            

        }
        else{

            tokenSet = {
                code,
                session,
                returnTo: returnTo ?? undefined
            }

        }

        this.clearSession()

        if (returnTo && autoRedirect === true) {
            window.location.href = window.location.origin + returnTo;
        }

        return tokenSet

    }

    /**
     * Uses a refresh_token to acquire a new access_token without user interaction.
     * @param providerId The ID of the provider (e.g., 'dropbox')
     * @param refreshToken The refresh token stored from a previous sign-in
     */
    async refreshAuthToken(providerId: ProviderId, refreshToken: string): Promise<RefreshResult> {

        const provider = this.getProvider(providerId);
        const clientId = this.getClientId(provider);

        const body = new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: clientId,
        });

        // Note: Some providers (like GitHub) require client_secret for refreshes 
        // if it's a private app, but for PKCE/Public clients, clientId is usually enough.
        if (provider.clientSecret) {
            body.set("client_secret", provider.clientSecret);
        }

        const response = await this.fetchJSON<RefreshResult>(
            provider.token_url,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                body: body.toString(),
            },
            "TOKEN_REFRESH_FAILED"
        );

        return response;
    }

    /**
     * Checks whether the current page load is an OAuth callback.
     * Useful for conditional rendering ("Loading…" vs normal page).
     */
    isCallback(): boolean {
        const url = new URL(window.location.href);
        return url.searchParams.has("code") || url.searchParams.has("error");
    }

    /**
    * Initiates the OAuth2 sign-in flow for the given provider.
    * Generates PKCE verifier + challenge, stores them in sessionStorage,
    * then redirects the browser to the provider's authorization URL.
    *
    * @param providerId - One of "google" | "dropbox" | "github"
    */
    async signIn(
        providerId: ProviderId,
        options?: {
            returnTo?: string;
        }
    ): Promise<any> {

        // Capture the current sub-path
        const returnTo = options?.returnTo || window.location.pathname;

        const provider = this.getProvider(providerId);
        const clientId = this.getClientId(provider);
        
        this.config.redirectUri = this.config.redirectUri || window.location.origin + `/zauth`

        // Generate CSRF state
        const state = generateState()

        // PKCE
        const verifier = generateVerifier();

        const params: Record<string, string> = {
            response_type: "code",
            client_id: clientId,
            redirect_uri: this.config.redirectUri,
            scope: this.resolveScopes(providerId, provider),
            state,
        };

        if (provider.pkce_supported) {
            const challenge = await generateChallenge(verifier);
            params.code_challenge = challenge;
            params.code_challenge_method = "S256";
        }

        // Dropbox requires token_access_type for offline (refresh) tokens
        switch(providerId){
            case "dropbox":
                params.token_access_type = "offline";
                break;
            case "google":
                params.access_type = "offline";
                params.prompt = "consent";
                break;
        }

        // console.log(`--`, providerId, params)

        // Persist verifier + state before leaving the page
        this.saveSession({ 
            redirectUri: this.config.redirectUri,
            verifier, 
            state, 
            provider: providerId 
        }, returnTo);

        // Build and navigate to the authorization URL
        const url = new URL(provider.authorization_url);
        for (const [key, value] of Object.entries(params)) {
            url.searchParams.set(key, value);
        }

        // This function never returns — the browser navigates away.
        window.location.href = url.toString();
        throw new AuthError("Navigation should have occurred.", "NAVIGATION_FAILED");

    }


}