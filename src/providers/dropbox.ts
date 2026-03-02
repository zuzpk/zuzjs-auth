import { OAuthProvider, OAuthProviderParams } from "../types";

const Dropbox = (options: OAuthProviderParams = {}) : OAuthProvider => ({
    name: "dropbox",
    authorization_url: "https://www.dropbox.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
    user_info_url: "https://api.dropboxapi.com/2/users/get_current_account",
    default_scopes: ["account_info.read"],
    pkce_supported: true,
    token_transport: "bearer",
    ...options,
    normalizeProfile(raw) {
      const name = raw.name as { display_name?: string } | undefined;
      const email = raw.email as string | undefined;
      const photo = raw.profile_photo_url as string | undefined;
      return {
        id: String(raw.account_id ?? ""),
        email: email ?? null,
        name: name?.display_name ?? null,
        avatar_url: photo ?? null,
        raw,
      };
    }
})

export default Dropbox