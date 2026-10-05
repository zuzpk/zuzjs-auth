import { generateChallenge, generateState, generateVerifier } from "./pkce";
import { setupProvider } from "./providers";
import {
    AuthConfig,
    AuthToken,
    CreateUserWithEmailAndPasswordInput,
    NormalizedProfile,
    OAuthProvider,
    PendingCodeExchange,
    ProviderId,
    RedirectResult,
    RefreshResult,
    SignInAnonymouslyInput,
    SignInOptions,
    SignInWithEmailAndPasswordInput,
    SignInWithPhoneInput,
    StoredPKCEState,
} from "./types";

const STORAGE_KEY_AUTH_STATE = "@zuzjs/auth:auth_state";

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
        public readonly cause?: unknown,
        public readonly status?: number
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
            // Keep the legacy default/behavior for existing consumers.
            fetchTokenInfoOnServer: config.fetchTokenInfoOnServer ?? true,
            exchangeCodeInBrowser: config.exchangeCodeInBrowser ?? config.fetchTokenInfoOnServer ?? true,
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
        this.signInWithEmailAndPassword = this.signInWithEmailAndPassword.bind(this);
        this.createUserWithEmailAndPassword = this.createUserWithEmailAndPassword.bind(this);
        this.signInAnonymously = this.signInAnonymously.bind(this);
        this.signInWithPhone = this.signInWithPhone.bind(this);
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

    private requireEndpoint(value: string | undefined, name: string, providerName: string): string {
        if (!value) {
            throw new AuthError(
                `${name} is required for provider ${providerName}.`,
                "MISSING_PROVIDER_ENDPOINT"
            );
        }
        return value;
    }

    private parseTokenResponse(tokenResponse: Record<string, unknown>): Omit<AuthToken, "profile" | "provider"> {
        const access_token = this.optionalString(tokenResponse.access_token);
        if (!access_token) {
            throw new AuthError(
                "Token exchange succeeded but no string access_token was returned.",
                "NO_ACCESS_TOKEN"
            );
        }

        return {
            access_token,
            refresh_token: this.optionalString(tokenResponse.refresh_token) ?? null,
            expires_in: this.optionalNumber(tokenResponse.expires_in) ?? null,
            token_type: this.optionalString(tokenResponse.token_type) ?? "Bearer",
            scope: this.optionalString(tokenResponse.scope) ?? null,
        };
    }

    private parseRefreshResponse(tokenResponse: Record<string, unknown>): RefreshResult {
        const access_token = this.optionalString(tokenResponse.access_token);
        const expires_in = this.optionalNumber(tokenResponse.expires_in);
        if (!access_token || expires_in === undefined) {
            throw new AuthError(
                "Refresh response must include a string access_token and numeric expires_in.",
                "INVALID_TOKEN_RESPONSE"
            );
        }

        const refresh_token = this.optionalString(tokenResponse.refresh_token);
        return {
            access_token,
            expires_in,
            token_type: this.optionalString(tokenResponse.token_type) ?? "Bearer",
            ...(refresh_token ? { refresh_token } : {}),
        };
    }

    private optionalString(value: unknown): string | undefined {
        return typeof value === "string" && value.length > 0 ? value : undefined;
    }

    private optionalNumber(value: unknown): number | undefined {
        return typeof value === "number" && Number.isFinite(value) ? value : undefined;
    }

    private async fetchProfileIfAvailable(provider: OAuthProvider, accessToken: string): Promise<NormalizedProfile | null> {
        if (!provider.user_info_url) {
            return null;
        }
        return this.fetchProfile(provider, accessToken);
    }

    private saveSession(data: StoredPKCEState, returnTo?: string): void {
        try {
            sessionStorage.setItem(this.config.storageKey!, JSON.stringify(data));
            const returnToKey = `${this.config.storageKey!}-return-to`;
            if (returnTo) sessionStorage.setItem(returnToKey, returnTo);
            else sessionStorage.removeItem(returnToKey);
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
            const parsed = JSON.parse(raw) as Partial<StoredPKCEState>;
            const verifier = this.optionalString(parsed.verifier);
            const state = this.optionalString(parsed.state);
            const provider = this.optionalString(parsed.provider);
            const redirectUri = this.optionalString(parsed.redirectUri);
            if (!verifier || !state || !provider || !redirectUri) {
                throw new Error("Invalid PKCE state shape");
            }
            return {
                verifier,
                state,
                provider,
                redirectUri,
                metaTag: this.optionalString(parsed.metaTag) ?? "",
            };
        } catch {
            throw new AuthError(
                "Corrupted PKCE session in sessionStorage.",
                "SESSION_CORRUPT"
            );
        }
    }

    private clearSession(): void {
        sessionStorage.removeItem(this.config.storageKey!);
        sessionStorage.removeItem(`${this.config.storageKey!}-return-to`);
    }

    private normalizeReturnTo(returnTo: string): string {
        if (!returnTo.startsWith("/") || returnTo.startsWith("//") || returnTo.includes("\\")) {
            throw new AuthError("returnTo must be a same-origin application path.", "INVALID_RETURN_TO");
        }
        const target = new URL(returnTo, window.location.origin);
        if (target.origin !== window.location.origin) {
            throw new AuthError("returnTo must remain on the current origin.", "INVALID_RETURN_TO");
        }
        return `${target.pathname}${target.search}${target.hash}`;
    }

    private async exchangeCode(opts: {
        code: string;
        session: StoredPKCEState;
        provider: OAuthProvider;
        clientId: string;
    }): Promise<AuthToken> {

        const { code, session, provider, clientId } = opts;

        const tokenUrl = this.requireEndpoint(provider.token_url, "token_url", provider.name);

        const body = new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: session.redirectUri,
            client_id: clientId,
        });

        // AuthGuard is browser-oriented: never send confidential client secrets.
        // Exchange confidential-client codes on a backend instead.
        body.set("code_verifier", session.verifier);

        if (provider.tokenParams) {
            Object.entries(provider.tokenParams).forEach(([key, value]) => {
                body.set(key, value);
            });
        }

        const tokenResponse = await this.fetchJSON<Record<string, unknown>>(
            tokenUrl,
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

        const parsed = this.parseTokenResponse(tokenResponse);

        // Fetch user profile
        const profile = await this.fetchProfileIfAvailable(provider, parsed.access_token);

        return {
            ...parsed,
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
            const reason = networkErr instanceof Error ? networkErr.message : "Unknown network error";
            const networkHint = this.getNetworkHint(reason);
            throw new AuthError(
                `Network request failed for ${url}. ${networkHint}`,
                errorCode,
                networkErr
            );
        }

        if (!response.ok) {
            let body = "";
            try {
                body = await response.text();
            } catch {
                /* ignore */
            }

            const bodyMessage = this.getResponseMessage(body);
            const statusHint = this.getHttpStatusHint(response.status);
            const detail = bodyMessage ? ` ${bodyMessage}` : "";
            const hint = statusHint ? ` ${statusHint}` : "";
            throw new AuthError(
                `Request failed (${response.status} ${response.statusText}) for ${url}.${detail}${hint}`,
                errorCode,
                undefined,
                response.status
            );
        }

        if (response.status === 204) {
            return {} as T;
        }

        const text = await response.text().catch(() => "");
        try {
            return JSON.parse(text) as T;
        } catch (parseErr) {
            const snippet = text ? ` Response body: ${text.slice(0, 240)}` : "";
            throw new AuthError(
                `Failed to parse JSON response from ${url}.${snippet}`,
                errorCode,
                parseErr
            );
        }
    }

    private getNetworkHint(reason: string): string {
        const normalized = reason.toLowerCase();
        if (normalized.includes("failed to fetch") || normalized.includes("networkerror")) {
            return "This is usually a CORS, DNS, SSL, or connectivity issue. If you see a 401 in DevTools, verify your API allows browser CORS for this origin and accepts OPTIONS/POST requests.";
        }
        return `Reason: ${reason}`;
    }

    private getResponseMessage(body: string): string {
        const trimmed = body.trim();
        if (!trimmed) return "";

        try {
            const parsed = JSON.parse(trimmed) as Record<string, unknown>;
            const message =
                (parsed.error_description as string | undefined)
                ?? (parsed.error as string | undefined)
                ?? (parsed.message as string | undefined);
            return message ? `Server says: ${message}` : `Server says: ${trimmed.slice(0, 240)}`;
        } catch {
            return `Server says: ${trimmed.slice(0, 240)}`;
        }
    }

    private getHttpStatusHint(status: number): string {
        switch (status) {
            case 400:
                return "Check request payload and required fields.";
            case 401:
                return "Unauthorized. Verify credentials, appId/apiKey, and auth provider config.";
            case 403:
                return "Forbidden. The server understood the request but denied access.";
            case 404:
                return "Endpoint not found. Verify server route and base URL.";
            case 429:
                return "Rate limited by server. Retry after a delay.";
            default:
                return status >= 500 ? "Server error. Check backend logs for details." : "";
        }
    }

    private withAuthContext<T>(operation: string, err: unknown, code: string): never {
        if (err instanceof AuthError) {
            throw new AuthError(
                `${operation} failed. ${err.message}`,
                err.code || code,
                err.cause,
                err.status
            );
        }

        const message = err instanceof Error ? err.message : String(err);
        throw new AuthError(`${operation} failed. ${message}`, code, err);
    }

    async getAuthTokenByCode({ code, session }: {
        code: string;
        session: StoredPKCEState;
    }) : Promise<AuthToken> {
        try {
            const provider = this.getProvider(session.provider);
            const clientId = this.getClientId(provider);

            const tokenSet = await this.exchangeCode({
                code,
                session,
                provider,
                clientId,
            })

            return tokenSet
        } catch (err) {
            return this.withAuthContext("Get token by code", err, "TOKEN_EXCHANGE_FAILED");
        }

    }

    async handleRedirect(autoRedirect: boolean = false): Promise<RedirectResult | null> {
        const params = new URLSearchParams(window.location.search);
        const code = params.get("code");
        const error = params.get("error");
        const state = params.get("state");

        // A page without OAuth callback parameters is not a callback.
        if (!code && !error) return null;

        let session: StoredPKCEState;
        try {
            session = this.loadSession();
        } catch (err) {
            // An unsolicited provider error still needs a useful error result.
            if (error && err instanceof AuthError && err.code === "SESSION_NOT_FOUND") {
                throw new AuthError(`Provider returned an error: ${params.get("error_description") ?? error}`, "PROVIDER_ERROR", err);
            }
            throw err;
        }

        if (!state || state !== session.state) {
            this.clearSession();
            throw new AuthError(
                "State mismatch. Possible CSRF attack — request was rejected.",
                "STATE_MISMATCH"
            );
        }

        this.cleanCallbackUrl();

        if (error) {
            const description = params.get("error_description") ?? error;
            this.clearSession();
            throw new AuthError(`Provider returned an error: ${description}`, "PROVIDER_ERROR");
        }

        // code is guaranteed by the callback check above because error has returned.
        const provider = this.getProvider(session.provider);
        const storedReturnTo = sessionStorage.getItem(`${this.config.storageKey!}-return-to`);
        const returnTo = storedReturnTo ? this.normalizeReturnTo(storedReturnTo) : undefined;
        const metaTag = session.metaTag || undefined;

        try {
            let result: RedirectResult;
            if (this.config.exchangeCodeInBrowser) {
                const clientId = this.getClientId(provider);
                result = {
                    ...(await this.exchangeCode({ code: code!, session, provider, clientId })),
                    returnTo,
                    metaTag,
                };
            } else {
                const pending: PendingCodeExchange = { code: code!, session, returnTo, metaTag };
                result = pending;
            }

            if (returnTo && autoRedirect) {
                window.location.href = new URL(returnTo, window.location.origin).toString();
            }
            return result;
        } finally {
            this.clearSession();
        }
    }

    private cleanCallbackUrl(): void {
        const cleanUrl = new URL(window.location.href);
        ["code", "state", "scope", "error", "error_description"].forEach((key) => cleanUrl.searchParams.delete(key));
        window.history.replaceState({}, "", cleanUrl.toString());
    }

    /**
     * Uses a refresh_token to acquire a new access_token without user interaction.
     * @param providerId The ID of the provider (e.g., 'dropbox')
     * @param refreshToken The refresh token stored from a previous sign-in
     */
    async refreshAuthToken(providerId: ProviderId, refreshToken: string): Promise<RefreshResult> {
        try {
            const provider = this.getProvider(providerId);
            const clientId = this.getClientId(provider);
            const tokenUrl = this.requireEndpoint(provider.token_url, "token_url", provider.name);

            const body = new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: clientId,
            });

            // Confidential-client refreshes belong on a backend; this browser flow
            // deliberately never sends provider.clientSecret.
            if (provider.tokenParams) {
                Object.entries(provider.tokenParams).forEach(([key, value]) => {
                    body.set(key, value);
                });
            }

            const response = await this.fetchJSON<Record<string, unknown>>(
                tokenUrl,
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

            return this.parseRefreshResponse(response);
        } catch (err) {
            return this.withAuthContext("Refresh token", err, "TOKEN_REFRESH_FAILED");
        }
    }

    /**
     * Checks whether the current page load is an OAuth callback.
     * Useful for conditional rendering ("Loading…" vs normal page).
     */
    isCallback(): boolean {
        const url = new URL(window.location.href);
        return url.searchParams.has("code") || url.searchParams.has("error");
    }

    async signInWithEmailAndPassword(input: SignInWithEmailAndPasswordInput): Promise<AuthToken> {
        try {
            const provider = this.getProvider(input.providerId);
            const clientId = this.getClientId(provider);
            const tokenUrl = this.requireEndpoint(provider.token_url, "token_url", provider.name);

            const usernameField = provider.usernameField ?? "username";
            const passwordField = provider.passwordField ?? "password";

            const body = new URLSearchParams({
                grant_type: provider.passwordGrantType ?? "password",
                client_id: clientId,
                [usernameField]: input.email,
                [passwordField]: input.password,
            });

            const scope = input.scope?.join(" ") ?? this.resolveScopes(input.providerId, provider);
            if (scope) {
                body.set("scope", scope);
            }

            if (provider.tokenParams) {
                Object.entries(provider.tokenParams).forEach(([key, value]) => {
                    body.set(key, value);
                });
            }

            const tokenResponse = await this.fetchJSON<Record<string, unknown>>(
                tokenUrl,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Accept: "application/json",
                    },
                    body: body.toString(),
                },
                "EMAIL_SIGNIN_FAILED"
            );

            const parsed = this.parseTokenResponse(tokenResponse);
            const profile = await this.fetchProfileIfAvailable(provider, parsed.access_token);

            return {
                ...parsed,
                profile,
                provider: input.providerId,
            };
        } catch (err) {
            return this.withAuthContext("Sign-in with email/password", err, "EMAIL_SIGNIN_FAILED");
        }
    }

    async createUserWithEmailAndPassword(input: CreateUserWithEmailAndPasswordInput): Promise<AuthToken> {
        try {
            const provider = this.getProvider(input.providerId);
            const clientId = this.getClientId(provider);
            const createUserUrl = this.requireEndpoint(
                provider.createUserUrl ?? provider.token_url,
                "createUserUrl or token_url",
                provider.name
            );

            const emailField = provider.createUserEmailField ?? provider.usernameField ?? "username";
            const passwordField = provider.createUserPasswordField ?? provider.passwordField ?? "password";

            const body = new URLSearchParams({
                grant_type: provider.createUserGrantType ?? provider.passwordGrantType ?? "password",
                client_id: clientId,
                [emailField]: input.email,
                [passwordField]: input.password,
            });

            const scope = input.scope?.join(" ") ?? this.resolveScopes(input.providerId, provider);
            if (scope) {
                body.set("scope", scope);
            }

            if (provider.createUserParams) {
                Object.entries(provider.createUserParams).forEach(([key, value]) => {
                    body.set(key, value);
                });
            }

            if (provider.tokenParams) {
                Object.entries(provider.tokenParams).forEach(([key, value]) => {
                    if (!body.has(key)) {
                        body.set(key, value);
                    }
                });
            }

            if (input.additionalParams) {
                Object.entries(input.additionalParams).forEach(([key, value]) => {
                    body.set(key, value);
                });
            }

            const tokenResponse = await this.fetchJSON<Record<string, unknown>>(
                createUserUrl,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Accept: "application/json",
                    },
                    body: body.toString(),
                },
                "EMAIL_CREATE_USER_FAILED"
            );

            const parsed = this.parseTokenResponse(tokenResponse);
            const profile = await this.fetchProfileIfAvailable(provider, parsed.access_token);

            return {
                ...parsed,
                profile,
                provider: input.providerId,
            };
        } catch (err) {
            return this.withAuthContext("Create user with email/password", err, "EMAIL_CREATE_USER_FAILED");
        }
    }

    async signInAnonymously(input: SignInAnonymouslyInput): Promise<AuthToken> {
        try {
            const provider = this.getProvider(input.providerId);
            const clientId = this.getClientId(provider);
            const tokenUrl = this.requireEndpoint(provider.token_url, "token_url", provider.name);

            const body = new URLSearchParams({
                grant_type: provider.anonymousGrantType ?? "client_credentials",
                client_id: clientId,
            });

            const scope = input.scope?.join(" ") ?? this.resolveScopes(input.providerId, provider);
            if (scope) {
                body.set("scope", scope);
            }

            if (provider.tokenParams) {
                Object.entries(provider.tokenParams).forEach(([key, value]) => {
                    body.set(key, value);
                });
            }

            const tokenResponse = await this.fetchJSON<Record<string, unknown>>(
                tokenUrl,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Accept: "application/json",
                    },
                    body: body.toString(),
                },
                "ANONYMOUS_SIGNIN_FAILED"
            );

            const parsed = this.parseTokenResponse(tokenResponse);
            const profile = await this.fetchProfileIfAvailable(provider, parsed.access_token);

            return {
                ...parsed,
                profile,
                provider: input.providerId,
            };
        } catch (err) {
            return this.withAuthContext("Anonymous sign-in", err, "ANONYMOUS_SIGNIN_FAILED");
        }
    }

    async signInWithPhone(_input: SignInWithPhoneInput): Promise<never> {
        throw new AuthError(
            "Phone sign-in is not implemented in @zuzjs/auth because OTP verification requires a trusted backend (SMS provider secrets, rate-limits, replay protection, and fraud checks). Use your backend to verify OTP and return OAuth-style tokens, then consume them in your app.",
            "PHONE_AUTH_REQUIRES_BACKEND"
        );
    }

    /**
    * Initiates the OAuth2 sign-in flow for the given provider.
    * Generates PKCE verifier + challenge, stores them in sessionStorage,
    * then redirects the browser to the provider's authorization URL.
    *
    * @param providerId - One of the configured provider IDs (e.g., 'google', 'facebook')
    * @param options - Optional parameters, e.g. { returnTo: "/app" }
    *                  returnTo is the path within your app to return to after sign-in
    */
    async signIn(providerId: ProviderId, options?: SignInOptions): Promise<never> {
        // Capture and validate the current same-origin application path.
        const returnTo = this.normalizeReturnTo(options?.returnTo ?? window.location.pathname);

        const provider = this.getProvider(providerId);
        const authorizationUrl = this.requireEndpoint(provider.authorization_url, "authorization_url", provider.name);
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

        // PKCE S256 is mandatory for browser authorization-code flows.
        const challenge = await generateChallenge(verifier);
        params.code_challenge = challenge;
        params.code_challenge_method = "S256";

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

        if (provider.authorizationParams) {
            Object.entries(provider.authorizationParams).forEach(([key, value]) => {
                params[key] = value;
            });
        }

        // console.log(`--`, providerId, params)

        // Persist verifier + state before leaving the page
        this.saveSession({ 
            redirectUri: this.config.redirectUri,
            verifier, 
            state, 
            provider: providerId,
            metaTag: options?.metaTag ?? ``,
        }, returnTo);

        // Build and navigate to the authorization URL
        const url = new URL(authorizationUrl);
        for (const [key, value] of Object.entries(params)) {
            url.searchParams.set(key, value);
        }

        // This function never returns — the browser navigates away.
        // console.log(options)
        window.location.href = url.toString();
        throw new AuthError("Navigation should have occurred.", "NAVIGATION_FAILED");

    }


}