"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = exports.AuthProvider = exports.verifyAccessToken = void 0;
exports.createAuth = createAuth;
const server_1 = require("next/server");
const authentication_1 = require("./server/authentication");
const cookies_1 = require("./core/cookies");
const headers_1 = require("next/headers");
__exportStar(require("./types"), exports);
__exportStar(require("./core/errors"), exports);
var tokens_1 = require("./core/tokens");
Object.defineProperty(exports, "verifyAccessToken", { enumerable: true, get: function () { return tokens_1.verifyAccessToken; } });
var provider_1 = require("./client/provider");
Object.defineProperty(exports, "AuthProvider", { enumerable: true, get: function () { return provider_1.AuthProvider; } });
var use_auth_1 = require("./client/use-auth");
Object.defineProperty(exports, "useAuth", { enumerable: true, get: function () { return use_auth_1.useAuth; } });
function createAuth(config) {
    if (config.secrets.accessTokenSecret.length < 32)
        throw new Error("Access token secret must be at least 32 characters long for security.");
    if (config.secrets.refreshTokenSecret.length < 32)
        throw new Error("Refresh token secret must be at least 32 characters long for security.");
    if (config.cookies.access.maxAge <= 0 || config.cookies.refresh.maxAge <= 0)
        throw new Error("Cookie maxAge must be positive numbers.");
    const effectiveConfig = {
        ...config,
        rotationStrategy: config.rotationStrategy ?? "always",
    };
    const getAuthSession = async (req) => {
        const { session, newTokens } = await (0, authentication_1.getAuthSession)(effectiveConfig, req);
        if (!req && newTokens) {
            const cookieStore = await (0, headers_1.cookies)();
            if (!newTokens.accessToken) {
                cookieStore.set((0, cookies_1.getClearAccessCookie)(effectiveConfig.cookies.access.name));
                cookieStore.set((0, cookies_1.getClearRefreshCookie)(effectiveConfig.cookies.refresh.name));
            }
            else {
                cookieStore.set((0, cookies_1.getAccessCookie)(newTokens.accessToken, effectiveConfig.cookies.access.name, effectiveConfig.cookies.access.maxAge));
                if (newTokens.refreshToken)
                    cookieStore.set((0, cookies_1.getRefreshCookie)(newTokens.refreshToken, effectiveConfig.cookies.refresh.name, effectiveConfig.cookies.refresh.maxAge));
            }
        }
        return session;
    };
    const signIn = (loginIdentifier, secret) => (0, authentication_1.signIn)(loginIdentifier, secret, effectiveConfig);
    const signOut = () => (0, authentication_1.signOut)(effectiveConfig);
    const createAuthMiddleware = (matcher = () => true) => {
        return async (req) => {
            if (!matcher(req))
                return server_1.NextResponse.next();
            const { newTokens } = await (0, authentication_1.getAuthSession)(effectiveConfig, req);
            const response = server_1.NextResponse.next();
            if (newTokens) {
                if (!newTokens.accessToken) {
                    response.cookies.set((0, cookies_1.getClearAccessCookie)(effectiveConfig.cookies.access.name));
                    response.cookies.set((0, cookies_1.getClearRefreshCookie)(effectiveConfig.cookies.refresh.name));
                }
                else {
                    response.cookies.set((0, cookies_1.getAccessCookie)(newTokens.accessToken, effectiveConfig.cookies.access.name, effectiveConfig.cookies.access.maxAge));
                    if (newTokens.refreshToken)
                        response.cookies.set((0, cookies_1.getRefreshCookie)(newTokens.refreshToken, effectiveConfig.cookies.refresh.name, effectiveConfig.cookies.refresh.maxAge));
                }
            }
            return response;
        };
    };
    return { getAuthSession, signIn, signOut, createAuthMiddleware };
}
//# sourceMappingURL=index.js.map