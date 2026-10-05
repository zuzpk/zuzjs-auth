import { OAuthProvider, OAuthProviderParams } from "../types";

const GitHub = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "github",
    authorization_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    user_info_url: "https://api.github.com/user",
    scopes: ["read:user", "user:email"],
    pkce_supported: true,
    token_transport: "bearer",
    ...options,
    normalizeProfile(raw) {
        return {
            id: String(raw.id ?? ""),
            email: (raw.email as string) ?? null,
            name: (raw.name as string) ?? (raw.login as string) ?? null,
            avatar_url: (raw.avatar_url as string) ?? null,
            raw,
        };
    },
});

export default GitHub;
