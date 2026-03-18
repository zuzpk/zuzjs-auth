import { OAuthProvider, OAuthProviderParams } from "../types";

const Apple = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "apple",
    authorization_url: "https://appleid.apple.com/auth/authorize",
    token_url: "https://appleid.apple.com/auth/token",
    user_info_url: "https://appleid.apple.com/auth/userinfo",
    scopes: ["name", "email"],
    pkce_supported: true,
    token_transport: "bearer",
    authorizationParams: {
        response_mode: "query",
    },
    ...options,
    normalizeProfile(raw) {
        return {
            id: String(raw.sub ?? raw.id ?? ""),
            email: (raw.email as string) ?? null,
            name: (raw.name as string) ?? null,
            avatar_url: null,
            raw,
        };
    },
});

export default Apple;
