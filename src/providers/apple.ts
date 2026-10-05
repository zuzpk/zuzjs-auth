import { OAuthProvider, OAuthProviderParams } from "../types";

/**
 * Apple identity claims are delivered in an ID token and, for name/email, an
 * optional one-time authorization response. Validate and process those values
 * on a trusted backend. AuthGuard therefore does not call a non-existent Apple
 * userinfo endpoint after the browser exchange.
 */
const Apple = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "apple",
    authorization_url: "https://appleid.apple.com/auth/authorize",
    token_url: "https://appleid.apple.com/auth/token",
    user_info_url: "",
    scopes: ["name", "email"],
    pkce_supported: true,
    token_transport: "bearer",
    authorizationParams: {
        response_mode: "form_post",
    },
    ...options,
});

export default Apple;
