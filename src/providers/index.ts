import { OAuthProvider } from "../types";
import Anonymous from "./anonymous";
import Apple from "./apple";
import Credentials from "./credentials";
import Dropbox from "./dropbox";
import Facebook from "./facebook";
import GitHub from "./github";
import Google from "./google";
import Twitter from "./twitter";

export const Providers = {
    google: Google,
    dropbox: Dropbox,
    apple: Apple,
    facebook: Facebook,
    twitter: Twitter,
    github: GitHub,
    credentials: Credentials,
    anonymous: Anonymous,
}

export function setupProvider(provider: any): OAuthProvider {
  if (typeof provider === "function") {
    return provider();
  }
  return provider;
}

export {
  Anonymous,
  Apple,
  Credentials,
  Dropbox,
  Facebook,
  GitHub,
  Google,
  Twitter
};

