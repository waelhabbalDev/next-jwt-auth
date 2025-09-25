"use strict";
"use server";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signIn = signIn;
exports.signOut = signOut;
exports.getAuthSession = getAuthSession;
const headers_1 = require("next/headers");
const tokens_1 = require("../core/tokens");
const cookies_1 = require("../core/cookies");
const errors_1 = require("../core/errors");
async function issueAndSetTokens(identity, config) {
    const { secrets, cookies: cookieConfig, jwt } = config;
    const accessToken = await (0, tokens_1.issueAccessToken)(identity, secrets.accessTokenSecret, cookieConfig.access.maxAge, jwt);
    const refreshToken = await (0, tokens_1.issueRefreshToken)(identity, secrets.refreshTokenSecret, cookieConfig.refresh.maxAge, jwt);
    const cookieStore = await (0, headers_1.cookies)();
    cookieStore.set((0, cookies_1.getAccessCookie)(accessToken, cookieConfig.access.name, cookieConfig.access.maxAge));
    cookieStore.set((0, cookies_1.getRefreshCookie)(refreshToken, cookieConfig.refresh.name, cookieConfig.refresh.maxAge));
    return { accessToken, refreshToken };
}
async function signIn(loginIdentifier, secret, config) {
    const identity = await config.dal.fetchIdentityByCredentials(loginIdentifier, secret);
    if (!identity)
        throw new errors_1.InvalidCredentialsError();
    if (identity.isForbidden)
        throw new errors_1.IdentityForbiddenError();
    await issueAndSetTokens(identity, config);
    const { version, isForbidden, ...publicIdentity } = identity;
    return publicIdentity;
}
async function signOut(config) {
    const cookieStore = await (0, headers_1.cookies)();
    const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
    cookieStore.set((0, cookies_1.getClearAccessCookie)(config.cookies.access.name));
    cookieStore.set((0, cookies_1.getClearRefreshCookie)(config.cookies.refresh.name));
    if (!refreshTokenValue)
        return;
    const verified = await (0, tokens_1.verifyRefreshToken)(refreshTokenValue, config.secrets.refreshTokenSecret);
    if (!verified)
        return;
    const { identifier } = verified.payload;
    await config.dal.invalidateAllSessionsForIdentity(identifier);
}
async function getAuthSession(config, req) {
    const cookieStore = req ? req.cookies : await (0, headers_1.cookies)();
    const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
    if (!refreshTokenValue)
        return { session: null };
    const verifiedRefresh = await (0, tokens_1.verifyRefreshToken)(refreshTokenValue, config.secrets.refreshTokenSecret);
    if (!verifiedRefresh)
        return { session: null, newTokens: null };
    const { identifier, version, jti, iat } = verifiedRefresh.payload;
    if (!iat)
        return { session: null, newTokens: null };
    if (await config.dal.isTokenJtiUsed(jti)) {
        await config.dal.invalidateAllSessionsForIdentity(identifier);
        console.warn("SECURITY ALERT: Reused refresh token detected. All sessions invalidated.");
        return { session: null, newTokens: null };
    }
    const reuseGracePeriod = config.cookies.refresh.maxAge + 60;
    await config.dal.markTokenJtiAsUsed(jti, reuseGracePeriod);
    const identity = await config.dal.fetchIdentityForSession(identifier);
    if (!identity || identity.isForbidden || identity.version !== version) {
        return { session: null, newTokens: null };
    }
    const tokenAge = Math.floor(Date.now() / 1000) - iat;
    const rotationThreshold = config.cookies.access.maxAge;
    const shouldRotateRefresh = config.rotationStrategy === "always" || tokenAge >= rotationThreshold;
    const newAccessToken = await (0, tokens_1.issueAccessToken)(identity, config.secrets.accessTokenSecret, config.cookies.access.maxAge, config.jwt);
    let newRefreshToken;
    if (shouldRotateRefresh)
        newRefreshToken = await (0, tokens_1.issueRefreshToken)(identity, config.secrets.refreshTokenSecret, config.cookies.refresh.maxAge, config.jwt);
    const { version: _, isForbidden: __, ...publicIdentity } = identity;
    return {
        session: { identity: publicIdentity },
        newTokens: shouldRotateRefresh
            ? { accessToken: newAccessToken, refreshToken: newRefreshToken }
            : { accessToken: newAccessToken },
    };
}
//# sourceMappingURL=authentication.js.map