import { OAuthProvider, OAuthProviderParams } from "../types";

const Google = (options: OAuthProviderParams = {}) : OAuthProvider => ({
    name: "google",
    authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    user_info_url: "https://openidconnect.googleapis.com/v1/userinfo",
    scopes: ["openid", "email", "profile"],
    pkce_supported: true,
    token_transport: "bearer",
    ...options,
    normalizeProfile(raw) {
      return {
        id: String(raw.sub ?? raw.id ?? ""),
        email: (raw.email as string) ?? null,
        name: (raw.name as string) ?? null,
        avatar_url: (raw.picture as string) ?? null,
        raw,
      };
    },
})

export default Google