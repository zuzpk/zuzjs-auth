import { OAuthProvider, OAuthProviderParams } from "../types";

const Twitter = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "twitter",
    authorization_url: "https://x.com/i/oauth2/authorize",
    token_url: "https://api.x.com/2/oauth2/token",
    user_info_url: "https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url",
    scopes: ["users.read", "tweet.read", "offline.access"],
    pkce_supported: true,
    token_transport: "bearer",
    ...options,
    normalizeProfile(raw) {
        const data = (raw.data as Record<string, unknown> | undefined) ?? raw;
        return {
            id: String(data.id ?? ""),
            email: null,
            name: (data.name as string) ?? (data.username as string) ?? null,
            avatar_url: (data.profile_image_url as string) ?? null,
            raw,
        };
    },
});

export default Twitter;
