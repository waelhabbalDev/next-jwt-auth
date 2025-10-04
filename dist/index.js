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
  ForbiddenError: () => ForbiddenError,
  IdentityForbiddenError: () => IdentityForbiddenError,
  InvalidCredentialsError: () => InvalidCredentialsError,
  NotAuthenticatedError: () => NotAuthenticatedError,
  createAuth: () => createAuth,
  verifyAccessToken: () => verifyAccessToken
});
module.exports = __toCommonJS(src_exports);
var import_server = require("next/server");
var import_headers2 = require("next/headers");
var import_navigation = require("next/navigation");

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
var NotAuthenticatedError = class extends AuthError {
  constructor() {
    super("Not authenticated.");
    this.name = "NotAuthenticatedError";
  }
};
var ForbiddenError = class extends AuthError {
  constructor(message = "Forbidden: You do not have the required permissions.") {
    super(message);
    this.name = "ForbiddenError";
  }
};

// src/authentication.ts
var AUTH_HEADER_KEY = "x-auth-identity";
async function validateSessionFromCookies(config, req) {
  console.log("[next-jwt-auth] Performing full auth check from cookies.");
  const cookieStore = req ? req.cookies : await (0, import_headers.cookies)();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  if (!refreshTokenValue) {
    return { session: null, failureReason: "NO_REFRESH_TOKEN" };
  }
  const verifiedRefresh = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret
  );
  if (!verifiedRefresh) {
    return {
      session: null,
      newTokens: null,
      failureReason: "INVALID_REFRESH_TOKEN"
    };
  }
  const { identifier, version, jti, iat } = verifiedRefresh.payload;
  const nowInSeconds = Math.floor(Date.now() / 1e3);
  const tokenAge = iat ? nowInSeconds - iat : -1;
  if (tokenAge === -1) {
    return {
      session: null,
      newTokens: null,
      failureReason: "INVALID_REFRESH_TOKEN"
    };
  }
  if (await config.dal.isTokenJtiUsed(jti)) {
    await config.dal.invalidateAllSessionsForIdentity(identifier);
    console.warn(
      `[next-jwt-auth] SECURITY ALERT: Reused refresh token detected (JTI: ${jti}). All sessions for this user have been invalidated.`
    );
    return {
      session: null,
      newTokens: null,
      failureReason: "JTI_REUSE_DETECTED"
    };
  }
  const identity = await config.dal.fetchIdentityForSession(identifier);
  if (!identity) {
    return {
      session: null,
      newTokens: null,
      failureReason: "ACCOUNT_NOT_FOUND"
    };
  }
  if (identity.isForbidden) {
    return {
      session: null,
      newTokens: null,
      failureReason: "ACCOUNT_FORBIDDEN"
    };
  }
  if (identity.version !== version) {
    return {
      session: null,
      newTokens: null,
      failureReason: "VERSION_MISMATCH"
    };
  }
  const rotationThreshold = config.cookies.access.maxAge;
  const shouldRotateRefresh = tokenAge >= rotationThreshold;
  const newAccessToken = await issueAccessToken(
    identity,
    config.secrets.accessTokenSecret,
    config.cookies.access.maxAge,
    config.jwt
  );
  let newRefreshToken;
  if (shouldRotateRefresh) {
    console.log(
      `[next-jwt-auth] Rotating refresh token (Age: ${tokenAge}s >= Threshold: ${rotationThreshold}s, JTI: ${jti}).`
    );
    const reuseExpiration = config.cookies.refresh.maxAge + 60;
    await config.dal.markTokenJtiAsUsed(jti, reuseExpiration);
    newRefreshToken = await issueRefreshToken(
      identity,
      config.secrets.refreshTokenSecret,
      config.cookies.refresh.maxAge,
      config.jwt
    );
  }
  const { version: _, isForbidden: __, ...publicIdentity } = identity;
  return {
    session: { identity: publicIdentity },
    newTokens: { accessToken: newAccessToken, refreshToken: newRefreshToken }
  };
}
async function getAuthSession(config, req) {
  if (!req) {
    const headersList = await (0, import_headers.headers)();
    const identityHeader = headersList.get(AUTH_HEADER_KEY);
    if (identityHeader) {
      try {
        console.log(
          "[next-jwt-auth] Using pre-validated identity from header."
        );
        const identity = JSON.parse(identityHeader);
        return { session: { identity }, newTokens: void 0 };
      } catch (e) {
        console.error(
          `[next-jwt-auth] Malformed ${AUTH_HEADER_KEY} header. Falling back to cookie validation.`,
          e
        );
      }
    }
  }
  return validateSessionFromCookies(config, req);
}
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
  await config.dal.invalidateAllSessionsForIdentity(
    verified.payload.identifier
  );
}

// src/utils.ts
function validateAndSanitizeBaseUrl(url) {
  if (typeof url !== "string" || url.length === 0) {
    throw new Error(
      "Auth configuration error: `baseUrl` is required and must be a non-empty string."
    );
  }
  try {
    const urlObject = new URL(url);
    if (urlObject.pathname !== "/" && urlObject.pathname !== "") {
      throw new Error(
        `Auth configuration error: \`baseUrl\` ("${url}") must not contain a path. Please provide the origin only (e.g., "https://example.com").`
      );
    }
    if (urlObject.search !== "") {
      throw new Error(
        `Auth configuration error: \`baseUrl\` ("${url}") must not contain query parameters.`
      );
    }
    if (urlObject.hash !== "") {
      throw new Error(
        `Auth configuration error: \`baseUrl\` ("${url}") must not contain a fragment hash.`
      );
    }
    return urlObject.origin;
  } catch (error) {
    if (error instanceof TypeError) {
      throw new Error(
        `Auth configuration error: Invalid \`baseUrl\` provided ("${url}"). It must be an absolute URL (e.g., "https://example.com").`
      );
    }
    throw error;
  }
}
function sanitizeRedirectPath(pathname) {
  if (!pathname || typeof pathname !== "string") {
    return "/";
  }
  if (pathname.startsWith("/") && !pathname.startsWith("//") && !pathname.startsWith("/\\")) {
    return pathname;
  }
  return "/";
}

// src/index.ts
var HEADER_PATHNAME_KEY = "x-auth-pathname";
function createAuth(config) {
  if (!config.secrets.accessTokenSecret || config.secrets.accessTokenSecret.length < 32)
    throw new Error(
      "Auth configuration error: Access token secret must be at least 32 characters long."
    );
  if (!config.secrets.refreshTokenSecret || config.secrets.refreshTokenSecret.length < 32)
    throw new Error(
      "Auth configuration error: Refresh token secret must be at least 32 characters long."
    );
  if (!config.cookies.access.maxAge || config.cookies.access.maxAge <= 0 || !config.cookies.refresh.maxAge || config.cookies.refresh.maxAge <= 0)
    throw new Error(
      "Auth configuration error: Cookie maxAge must be a positive number of seconds."
    );
  if (!config.redirects.unauthenticated)
    throw new Error(
      "Auth configuration error: `redirects.unauthenticated` path is required."
    );
  if (!config.redirects.unauthorized)
    throw new Error(
      "Auth configuration error: `redirects.unauthorized` path is required."
    );
  if (!config.redirects.forbidden)
    throw new Error(
      "Auth configuration error: `redirects.forbidden` path is required."
    );
  const validatedBaseUrl = validateAndSanitizeBaseUrl(config.baseUrl);
  const effectiveConfig = {
    ...config,
    baseUrl: validatedBaseUrl,
    redirects: config.redirects
  };
  const getAuthSession2 = async () => {
    const { session, newTokens } = await getAuthSession(effectiveConfig);
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
        if (newTokens.refreshToken) {
          cookieStore.set(
            getRefreshCookie(
              newTokens.refreshToken,
              effectiveConfig.cookies.refresh.name,
              effectiveConfig.cookies.refresh.maxAge
            )
          );
        }
      }
    }
    return session;
  };
  const signIn2 = (signInIdentifier, secret) => signIn(signInIdentifier, secret, effectiveConfig);
  const signOut2 = () => signOut(effectiveConfig);
  const createAuthMiddleware = (matcher = () => true) => {
    return async (req) => {
      if (!matcher(req)) return import_server.NextResponse.next();
      const requestHeaders = new Headers(req.headers);
      requestHeaders.set(HEADER_PATHNAME_KEY, req.nextUrl.pathname);
      const { session, newTokens } = await getAuthSession(
        effectiveConfig,
        req
      );
      if (session) {
        requestHeaders.set(AUTH_HEADER_KEY, JSON.stringify(session.identity));
      }
      const response = import_server.NextResponse.next({
        request: { headers: requestHeaders }
      });
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
          if (newTokens.refreshToken) {
            response.cookies.set(
              getRefreshCookie(
                newTokens.refreshToken,
                effectiveConfig.cookies.refresh.name,
                effectiveConfig.cookies.refresh.maxAge
              )
            );
          }
        }
      }
      return response;
    };
  };
  const buildRedirectUrl = async (targetPath, params = {}) => {
    const headersList = await (0, import_headers2.headers)();
    const rawPathname = headersList.get(HEADER_PATHNAME_KEY);
    const currentPath = sanitizeRedirectPath(rawPathname);
    const url = new URL(targetPath, effectiveConfig.baseUrl);
    if (targetPath === effectiveConfig.redirects.unauthenticated) {
      url.searchParams.set("callbackUrl", currentPath);
    }
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return `${url.pathname}${url.search}`;
  };
  const protectPage = async (options) => {
    const { session, failureReason } = await getAuthSession(
      effectiveConfig
    );
    if (failureReason === "ACCOUNT_FORBIDDEN") {
      const redirectPath = await buildRedirectUrl(
        options?.forbiddenRedirect || effectiveConfig.redirects.forbidden,
        { ...options?.redirectParams, error: "account_suspended" }
      );
      (0, import_navigation.redirect)(redirectPath);
    }
    if (!session) {
      const redirectPath = await buildRedirectUrl(
        options?.unauthenticatedRedirect || effectiveConfig.redirects.unauthenticated,
        options?.redirectParams
      );
      (0, import_navigation.redirect)(redirectPath);
    }
    if (options?.authorize) {
      const isAuthorized = await options.authorize(
        session.identity,
        options.context
      );
      if (!isAuthorized) {
        const redirectPath = await buildRedirectUrl(
          options?.unauthorizedRedirect || effectiveConfig.redirects.unauthorized,
          options?.redirectParams
        );
        (0, import_navigation.redirect)(redirectPath);
      }
    }
    return session;
  };
  const protectAction = async (options) => {
    const { session, failureReason } = await getAuthSession(
      effectiveConfig
    );
    if (failureReason === "ACCOUNT_FORBIDDEN") {
      throw new ForbiddenError("This account is suspended.");
    }
    if (!session) {
      throw new NotAuthenticatedError();
    }
    if (options?.authorize) {
      const isAuthorized = await options.authorize(
        session.identity,
        options.context
      );
      if (!isAuthorized) {
        throw new ForbiddenError();
      }
    }
    return session;
  };
  const protectApi = async (options) => {
    const { session, failureReason } = await getAuthSession(
      effectiveConfig
    );
    if (failureReason === "ACCOUNT_FORBIDDEN") {
      return {
        response: import_server.NextResponse.json(
          { error: "Account suspended" },
          { status: 403 }
        )
      };
    }
    if (!session) {
      return {
        response: import_server.NextResponse.json(
          { error: "Not authenticated" },
          { status: 401 }
        )
      };
    }
    if (options?.authorize) {
      const isAuthorized = await options.authorize(
        session.identity,
        options.context
      );
      if (!isAuthorized) {
        return {
          response: import_server.NextResponse.json({ error: "Forbidden" }, { status: 403 })
        };
      }
    }
    return { session };
  };
  return {
    getAuthSession: getAuthSession2,
    signIn: signIn2,
    signOut: signOut2,
    createAuthMiddleware,
    protectPage,
    protectAction,
    protectApi
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthError,
  ForbiddenError,
  IdentityForbiddenError,
  InvalidCredentialsError,
  NotAuthenticatedError,
  createAuth,
  verifyAccessToken
});
