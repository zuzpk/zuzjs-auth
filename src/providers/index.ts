import { OAuthProvider } from "../types";
import Dropbox from "./dropbox";
import Google from "./google";

export const Providers = {
    google: Google,
    dropbox: Dropbox
}

export function setupProvider(provider: any): OAuthProvider {
  if (typeof provider === "function") {
    return provider();
  }
  return provider;
}

export {
    Dropbox,
    Google
};

