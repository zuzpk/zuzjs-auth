import { OAuthProvider, OAuthProviderParams } from "../types";

const Anonymous = (options: OAuthProviderParams = {}): OAuthProvider => ({
    name: "anonymous",
    authorization_url: "",
    token_url: "",
    user_info_url: "",
    scopes: ["anonymous"],
    pkce_supported: false,
    token_transport: "bearer",
    anonymousGrantType: "client_credentials",
    ...options,
});

export default Anonymous;
