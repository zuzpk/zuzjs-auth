import { OAuthProvider, OAuthProviderParams } from "../types";

const Credentials = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "credentials",
    authorization_url: "",
    token_url: "",
    user_info_url: "",
    scopes: ["openid", "profile", "email", "offline_access"],
    pkce_supported: false,
    token_transport: "bearer",
    passwordGrantType: "password",
    usernameField: "username",
    passwordField: "password",
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
});

export default Credentials;
