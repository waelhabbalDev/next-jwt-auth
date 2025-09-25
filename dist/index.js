"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  AuthError: () => AuthError,
  IdentityForbiddenError: () => IdentityForbiddenError,
  InvalidCredentialsError: () => InvalidCredentialsError,
  createAuth: () => createAuth,
  verifyAccessToken: () => verifyAccessToken
});
module.exports = __toCommonJS(src_exports);
var import_server = require("next/server");

// src/authentication.ts
var import_headers = require("next/headers");

// src/tokens.ts
var import_jose = require("jose");
var import_uuid = require("uuid");
var getSecretKey = (secret) => new TextEncoder().encode(secret);
async function issueAccessToken(identity, secret, expiresIn, jwtOptions) {
  const { version, isForbidden, ...payload } = identity;
  let jwt = new import_jose.SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(getSecretKey(secret));
}
async function verifyAccessToken(token, secret) {
  try {
    const { payload } = await (0, import_jose.jwtVerify)(
      token,
      getSecretKey(secret)
    );
    return { payload };
  } catch {
    return null;
  }
}
async function issueRefreshToken(identity, secret, expiresIn, jwtOptions) {
  const payload = {
    identifier: identity.identifier,
    version: identity.version,
    jti: (0, import_uuid.v4)()
  };
  let jwt = new import_jose.SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(getSecretKey(secret));
}
async function verifyRefreshToken(token, secret) {
  try {
    const { payload } = await (0, import_jose.jwtVerify)(
      token,
      getSecretKey(secret)
    );
    return { payload };
  } catch {
    return null;
  }
}

// src/cookies.ts
var isProduction = process.env.NODE_ENV === "production";
var baseCookieConfig = {
  httpOnly: true,
  secure: isProduction,
  sameSite: "strict",
  path: "/"
};
var getAccessCookie = (token, name, maxAge) => ({
  name,
  value: token,
  ...baseCookieConfig,
  maxAge
});
var getRefreshCookie = (token, name, maxAge) => ({
  name,
  value: token,
  ...baseCookieConfig,
  maxAge
});
var getClearAccessCookie = (name) => ({
  name,
  value: "",
  ...baseCookieConfig,
  maxAge: -1
});
var getClearRefreshCookie = (name) => ({
  name,
  value: "",
  ...baseCookieConfig,
  maxAge: -1
});

// src/errors.ts
var AuthError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
  }
};
var InvalidCredentialsError = class extends AuthError {
  constructor() {
    super("Invalid credentials provided.");
    this.name = "InvalidCredentialsError";
  }
};
var IdentityForbiddenError = class extends AuthError {
  constructor() {
    super("This identity is forbidden from logging in.");
    this.name = "IdentityForbiddenError";
  }
};

// src/authentication.ts
async function issueAndSetTokens(identity, config) {
  const { secrets, cookies: cookieConfig, jwt } = config;
  const accessToken = await issueAccessToken(
    identity,
    secrets.accessTokenSecret,
    cookieConfig.access.maxAge,
    jwt
  );
  const refreshToken = await issueRefreshToken(
    identity,
    secrets.refreshTokenSecret,
    cookieConfig.refresh.maxAge,
    jwt
  );
  const cookieStore = await (0, import_headers.cookies)();
  cookieStore.set(
    getAccessCookie(
      accessToken,
      cookieConfig.access.name,
      cookieConfig.access.maxAge
    )
  );
  cookieStore.set(
    getRefreshCookie(
      refreshToken,
      cookieConfig.refresh.name,
      cookieConfig.refresh.maxAge
    )
  );
  return { accessToken, refreshToken };
}
async function signIn(signInIdentifier, secret, config) {
  const identity = await config.dal.fetchIdentityByCredentials(
    signInIdentifier,
    secret
  );
  if (!identity) throw new InvalidCredentialsError();
  if (identity.isForbidden) throw new IdentityForbiddenError();
  await issueAndSetTokens(identity, config);
  const { version, isForbidden, ...publicIdentity } = identity;
  return publicIdentity;
}
async function signOut(config) {
  const cookieStore = await (0, import_headers.cookies)();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  cookieStore.set(getClearAccessCookie(config.cookies.access.name));
  cookieStore.set(getClearRefreshCookie(config.cookies.refresh.name));
  if (!refreshTokenValue) return;
  const verified = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret
  );
  if (!verified) return;
  const { identifier } = verified.payload;
  await config.dal.invalidateAllSessionsForIdentity(identifier);
}
async function getAuthSession(config, req) {
  const cookieStore = req ? req.cookies : await (0, import_headers.cookies)();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  if (!refreshTokenValue) return { session: null };
  const verifiedRefresh = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret
  );
  if (!verifiedRefresh) return { session: null, newTokens: null };
  const { identifier, version, jti, iat } = verifiedRefresh.payload;
  if (!iat) return { session: null, newTokens: null };
  if (await config.dal.isTokenJtiUsed(jti)) {
    await config.dal.invalidateAllSessionsForIdentity(identifier);
    console.warn(
      "SECURITY ALERT: Reused refresh token detected. All sessions invalidated."
    );
    return { session: null, newTokens: null };
  }
  const reuseGracePeriod = config.cookies.refresh.maxAge + 60;
  await config.dal.markTokenJtiAsUsed(jti, reuseGracePeriod);
  const identity = await config.dal.fetchIdentityForSession(identifier);
  if (!identity || identity.isForbidden || identity.version !== version) {
    return { session: null, newTokens: null };
  }
  const tokenAge = Math.floor(Date.now() / 1e3) - iat;
  const rotationThreshold = config.cookies.access.maxAge;
  const shouldRotateRefresh = config.rotationStrategy === "always" || tokenAge >= rotationThreshold;
  const newAccessToken = await issueAccessToken(
    identity,
    config.secrets.accessTokenSecret,
    config.cookies.access.maxAge,
    config.jwt
  );
  let newRefreshToken;
  if (shouldRotateRefresh)
    newRefreshToken = await issueRefreshToken(
      identity,
      config.secrets.refreshTokenSecret,
      config.cookies.refresh.maxAge,
      config.jwt
    );
  const { version: _, isForbidden: __, ...publicIdentity } = identity;
  return {
    session: { identity: publicIdentity },
    newTokens: shouldRotateRefresh ? { accessToken: newAccessToken, refreshToken: newRefreshToken } : { accessToken: newAccessToken }
  };
}

// src/index.ts
var import_headers2 = require("next/headers");
function createAuth(config) {
  if (config.secrets.accessTokenSecret.length < 32)
    throw new Error(
      "Access token secret must be at least 32 characters long for security."
    );
  if (config.secrets.refreshTokenSecret.length < 32)
    throw new Error(
      "Refresh token secret must be at least 32 characters long for security."
    );
  if (config.cookies.access.maxAge <= 0 || config.cookies.refresh.maxAge <= 0)
    throw new Error("Cookie maxAge must be positive numbers.");
  const effectiveConfig = {
    ...config,
    rotationStrategy: config.rotationStrategy ?? "always"
  };
  const getAuthSession2 = async () => {
    const { session, newTokens } = await getAuthSession(
      effectiveConfig
    );
    if (newTokens) {
      const cookieStore = await (0, import_headers2.cookies)();
      if (!newTokens.accessToken) {
        cookieStore.set(
          getClearAccessCookie(effectiveConfig.cookies.access.name)
        );
        cookieStore.set(
          getClearRefreshCookie(effectiveConfig.cookies.refresh.name)
        );
      } else {
        cookieStore.set(
          getAccessCookie(
            newTokens.accessToken,
            effectiveConfig.cookies.access.name,
            effectiveConfig.cookies.access.maxAge
          )
        );
        if (newTokens.refreshToken)
          cookieStore.set(
            getRefreshCookie(
              newTokens.refreshToken,
              effectiveConfig.cookies.refresh.name,
              effectiveConfig.cookies.refresh.maxAge
            )
          );
      }
    }
    return session;
  };
  const signIn2 = (signInIdentifier, secret) => signIn(signInIdentifier, secret, effectiveConfig);
  const signOut2 = () => signOut(effectiveConfig);
  const createAuthMiddleware = (matcher = () => true) => {
    return async (req) => {
      if (!matcher(req)) return import_server.NextResponse.next();
      const { newTokens } = await getAuthSession(effectiveConfig, req);
      const response = import_server.NextResponse.next();
      if (newTokens) {
        if (!newTokens.accessToken) {
          response.cookies.set(
            getClearAccessCookie(effectiveConfig.cookies.access.name)
          );
          response.cookies.set(
            getClearRefreshCookie(effectiveConfig.cookies.refresh.name)
          );
        } else {
          response.cookies.set(
            getAccessCookie(
              newTokens.accessToken,
              effectiveConfig.cookies.access.name,
              effectiveConfig.cookies.access.maxAge
            )
          );
          if (newTokens.refreshToken)
            response.cookies.set(
              getRefreshCookie(
                newTokens.refreshToken,
                effectiveConfig.cookies.refresh.name,
                effectiveConfig.cookies.refresh.maxAge
              )
            );
        }
      }
      return response;
    };
  };
  return { getAuthSession: getAuthSession2, signIn: signIn2, signOut: signOut2, createAuthMiddleware };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthError,
  IdentityForbiddenError,
  InvalidCredentialsError,
  createAuth,
  verifyAccessToken
});
