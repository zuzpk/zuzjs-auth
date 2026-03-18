import { OAuthProvider, OAuthProviderParams } from "../types";

const Facebook = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "facebook",
    authorization_url: "https://www.facebook.com/v21.0/dialog/oauth",
    token_url: "https://graph.facebook.com/v21.0/oauth/access_token",
    user_info_url: "https://graph.facebook.com/me?fields=id,name,email,picture",
    scopes: ["public_profile", "email"],
    pkce_supported: true,
    token_transport: "bearer",
    ...options,
    normalizeProfile(raw) {
        const picture = raw.picture as
            | { data?: { url?: string } }
            | undefined;
        return {
            id: String(raw.id ?? ""),
            email: (raw.email as string) ?? null,
            name: (raw.name as string) ?? null,
            avatar_url: picture?.data?.url ?? null,
            raw,
        };
    },
});

export default Facebook;
