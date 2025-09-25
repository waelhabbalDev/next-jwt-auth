import { AuthCookieConfig } from "../types";
export declare const getAccessCookie: (token: string, name: string, maxAge: number) => AuthCookieConfig;
export declare const getRefreshCookie: (token: string, name: string, maxAge: number) => AuthCookieConfig;
export declare const getClearAccessCookie: (name: string) => AuthCookieConfig;
export declare const getClearRefreshCookie: (name: string) => AuthCookieConfig;
