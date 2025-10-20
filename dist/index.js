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

// src/server/index.ts
var server_exports = {};
__export(server_exports, {
  AuthError: () => AuthError,
  CsrfError: () => CsrfError,
  ForbiddenError: () => ForbiddenError,
  IdentityForbiddenError: () => IdentityForbiddenError,
  InvalidCredentialsError: () => InvalidCredentialsError,
  NotAuthenticatedError: () => NotAuthenticatedError,
  RateLimitError: () => RateLimitError,
  createAuth: () => createAuth,
  verifyAccessToken: () => verifyAccessToken
});
module.exports = __toCommonJS(server_exports);
var import_react = require("react");
var import_headers2 = require("next/headers");
var import_server2 = require("next/server");

// src/common/utils.ts
function validateAndSanitizeBaseUrl(url) {
  if (typeof url !== "string" || url.length === 0) {
    throw new Error(
      "Auth configuration error: `baseUrl` is required and must be a non-empty string."
    );
  }
  try {
    const urlObject = new URL(url);
    if (urlObject.protocol !== "http:" && urlObject.protocol !== "https:") {
      throw new Error(
        `Auth configuration error: Invalid protocol in \`baseUrl\` ("${url}"). It must be "http" or "https".`
      );
    }
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
  if (!pathname.startsWith("/") || pathname.includes("..") || // Disallow path traversal
  pathname.startsWith("//") || pathname.startsWith("/\\")) {
    return "/";
  }
  return pathname;
}

// src/server/authentication.ts
var import_headers = require("next/headers");

// src/common/tokens.ts
var import_jose = require("jose");
var import_uuid = require("uuid");
function getKey(key) {
  if (typeof key === "string") {
    return new TextEncoder().encode(key);
  }
  return key;
}
function resolveSigningKey(secret) {
  if (typeof secret === "string") {
    return { key: getKey(secret) };
  }
  if (Array.isArray(secret)) {
    return { key: getKey(secret[0].key), kid: secret[0].kid };
  }
  return { key: getKey(secret.key), kid: secret.kid };
}
function createKeyResolver(secret) {
  return async (protectedHeader) => {
    if (typeof secret === "string") return getKey(secret);
    if (!Array.isArray(secret)) return getKey(secret.key);
    const kid = protectedHeader.kid;
    if (!kid) {
      throw new Error(
        "Token missing 'kid' in protected header, which is required for key rotation."
      );
    }
    const matchingKey = secret.find((s) => s.kid === kid);
    if (!matchingKey) {
      throw new Error(`No matching key found for kid: ${kid}`);
    }
    return getKey(matchingKey.key);
  };
}
var getAlgorithm = (alg) => {
  if (alg === "RS256") return "RS256";
  return "HS256";
};
async function issueAccessToken(identity, secret, expiresIn, jwtOptions) {
  const { version, isForbidden, ...payload } = identity;
  const algorithm = getAlgorithm(jwtOptions?.alg);
  const signingKey = resolveSigningKey(secret);
  let jwt = new import_jose.SignJWT(payload).setProtectedHeader({ alg: algorithm, kid: signingKey.kid }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(signingKey.key);
}
async function verifyAccessToken(token, secret, jwtOptions) {
  try {
    const keyResolver = createKeyResolver(secret);
    const { payload } = await (0, import_jose.jwtVerify)(
      token,
      keyResolver,
      { algorithms: [getAlgorithm(jwtOptions?.alg)] }
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
  const algorithm = getAlgorithm(jwtOptions?.alg);
  const signingKey = resolveSigningKey(secret);
  let jwt = new import_jose.SignJWT(payload).setProtectedHeader({ alg: algorithm, kid: signingKey.kid }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(signingKey.key);
}
async function verifyRefreshToken(token, secret, jwtOptions) {
  try {
    const keyResolver = createKeyResolver(secret);
    const { payload } = await (0, import_jose.jwtVerify)(
      token,
      keyResolver,
      { algorithms: [getAlgorithm(jwtOptions?.alg)] }
    );
    return { payload };
  } catch {
    return null;
  }
}

// src/common/cookies.ts
var import_crypto = require("crypto");
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
var getCsrfCookie = (maxAge) => {
  const token = (0, import_crypto.randomBytes)(32).toString("hex");
  return {
    name: "csrf_token",
    value: token,
    secure: isProduction,
    sameSite: "strict",
    path: "/",
    maxAge,
    // httpOnly must be false so the client can read it.
    httpOnly: false
  };
};

// src/common/errors.ts
var AuthError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
  }
};
var InvalidCredentialsError = class extends AuthError {
  constructor(message) {
    super(message || "Invalid credentials provided.");
    this.name = "InvalidCredentialsError";
  }
};
var IdentityForbiddenError = class extends AuthError {
  constructor(message) {
    super(message || "This identity is forbidden from logging in.");
    this.name = "IdentityForbiddenError";
  }
};
var NotAuthenticatedError = class extends AuthError {
  constructor(message) {
    super(message || "Not authenticated.");
    this.name = "NotAuthenticatedError";
  }
};
var ForbiddenError = class extends AuthError {
  constructor(message = "Forbidden: You do not have the required permissions.") {
    super(message);
    this.name = "ForbiddenError";
  }
};
var RateLimitError = class extends AuthError {
  constructor(message = "Too many attempts. Try again later.") {
    super(message);
    this.name = "RateLimitError";
  }
};
var CsrfError = class extends AuthError {
  constructor(message = "Invalid CSRF token.") {
    super(message);
    this.name = "CsrfError";
  }
};

// src/server/authentication.ts
function log(config, level, message, ...args) {
  if (config.debug) {
    config.logger(level, message, ...args);
  }
}
async function validateAndRefreshSession(config, req) {
  log(config, "info", "Middleware: Validating session and handling refresh.");
  const refreshTokenValue = req.cookies.get(config.cookies.refresh.name)?.value;
  if (!refreshTokenValue) {
    return { session: null, failureReason: "NO_REFRESH_TOKEN" };
  }
  const verifiedRefresh = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret,
    { alg: config.jwt.alg }
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
  const tokenAge = iat !== void 0 ? nowInSeconds - iat : Number.POSITIVE_INFINITY;
  if (await config.dal.isTokenJtiUsed(jti)) {
    await config.dal.invalidateAllSessionsForIdentity(identifier);
    log(
      config,
      "warn",
      `SECURITY ALERT: Reused JTI detected for ${identifier}. All sessions invalidated.`
    );
    return {
      session: null,
      newTokens: null,
      failureReason: "JTI_REUSE_DETECTED"
    };
  }
  const identity = await config.dal.fetchIdentityForSession(identifier);
  if (!identity)
    return {
      session: null,
      newTokens: null,
      failureReason: "ACCOUNT_NOT_FOUND"
    };
  if (identity.isForbidden)
    return {
      session: null,
      newTokens: null,
      failureReason: "ACCOUNT_FORBIDDEN"
    };
  if (identity.version !== version)
    return {
      session: null,
      newTokens: null,
      failureReason: "VERSION_MISMATCH"
    };
  const shouldRotateRefresh = config.refreshTokenRotationIntervalSeconds > 0 && tokenAge >= config.refreshTokenRotationIntervalSeconds;
  const newAccessToken = await issueAccessToken(
    identity,
    config.secrets.accessTokenSecret,
    config.cookies.access.maxAge,
    config.jwt
  );
  const newTokens = { accessToken: newAccessToken };
  if (shouldRotateRefresh) {
    log(config, "info", `Rotating refresh token for ${identifier}.`);
    const reuseExpiration = config.cookies.refresh.maxAge + 60;
    await config.dal.markTokenJtiAsUsed(jti, reuseExpiration);
    newTokens.refreshToken = await issueRefreshToken(
      identity,
      config.secrets.refreshTokenSecret,
      config.cookies.refresh.maxAge,
      config.jwt
    );
  }
  const { version: _, isForbidden: __, ...publicIdentity } = identity;
  return {
    session: { identity: publicIdentity },
    newTokens
  };
}
async function validateSessionReadOnly(config) {
  log(
    config,
    "info",
    "Server Component: Performing read-only session validation."
  );
  const cookieStore = await (0, import_headers.cookies)();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  if (!refreshTokenValue) {
    return { session: null, failureReason: "NO_REFRESH_TOKEN" };
  }
  const verifiedRefresh = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret,
    { alg: config.jwt.alg }
  );
  if (!verifiedRefresh) {
    return { session: null, failureReason: "INVALID_REFRESH_TOKEN" };
  }
  const { identifier, version } = verifiedRefresh.payload;
  const identity = await config.dal.fetchIdentityForSession(identifier);
  if (!identity) return { session: null, failureReason: "ACCOUNT_NOT_FOUND" };
  if (identity.isForbidden)
    return { session: null, failureReason: "ACCOUNT_FORBIDDEN" };
  if (identity.version !== version)
    return { session: null, failureReason: "VERSION_MISMATCH" };
  const { version: _, isForbidden: __, ...publicIdentity } = identity;
  return { session: { identity: publicIdentity } };
}
async function signIn(signInIdentifier, secret, config, mfaCode, provider, authCode) {
  if (await config.rateLimit(signInIdentifier)) {
    throw new RateLimitError(config.errorMessages.RateLimitError);
  }
  let finalIdentifier = signInIdentifier;
  let finalSecret = secret;
  if (provider && config.providers[provider]) {
    const creds = await config.providers[provider](authCode || "");
    finalIdentifier = creds.signInIdentifier;
    finalSecret = creds.secret || "";
  }
  const identity = await config.dal.fetchIdentityByCredentials(
    finalIdentifier,
    finalSecret
  );
  if (!identity)
    throw new InvalidCredentialsError(
      config.errorMessages.InvalidCredentialsError
    );
  if (identity.isForbidden)
    throw new IdentityForbiddenError(
      config.errorMessages.IdentityForbiddenError
    );
  if (identity.hasMFA) {
    if (!mfaCode) throw new AuthError("MFA code required.");
    if (!config.dal.verifyMFA || !await config.dal.verifyMFA(identity.identifier, mfaCode)) {
      throw new AuthError("Invalid MFA code.");
    }
  }
  const accessToken = await issueAccessToken(
    identity,
    config.secrets.accessTokenSecret,
    config.cookies.access.maxAge,
    config.jwt
  );
  const refreshToken = await issueRefreshToken(
    identity,
    config.secrets.refreshTokenSecret,
    config.cookies.refresh.maxAge,
    config.jwt
  );
  const cookieStore = await (0, import_headers.cookies)();
  cookieStore.set(
    getAccessCookie(
      accessToken,
      config.cookies.access.name,
      config.cookies.access.maxAge
    )
  );
  cookieStore.set(
    getRefreshCookie(
      refreshToken,
      config.cookies.refresh.name,
      config.cookies.refresh.maxAge
    )
  );
  if (config.csrfEnabled) {
    cookieStore.set(getCsrfCookie(config.cookies.access.maxAge));
  }
  log(config, "info", `Successful sign-in for ${identity.identifier}`);
  const { version, isForbidden, ...publicIdentity } = identity;
  return publicIdentity;
}
async function signOut(config) {
  const cookieStore = await (0, import_headers.cookies)();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  cookieStore.delete(config.cookies.access.name);
  cookieStore.delete(config.cookies.refresh.name);
  if (config.csrfEnabled) {
    cookieStore.delete("csrf_token");
  }
  if (!refreshTokenValue) return;
  const verified = await verifyRefreshToken(
    refreshTokenValue,
    config.secrets.refreshTokenSecret,
    { alg: config.jwt.alg }
  );
  if (!verified) return;
  await config.dal.invalidateAllSessionsForIdentity(
    verified.payload.identifier
  );
  log(
    config,
    "info",
    `Successful sign-out and session invalidation for ${verified.payload.identifier}`
  );
}

// src/server/protection.ts
var import_navigation = require("next/navigation");
var import_server = require("next/server");
function buildRedirectUrl(config, targetPath, currentPath, params = {}, addCallbackUrl) {
  const safeCurrentPath = sanitizeRedirectPath(currentPath);
  const url = new URL(targetPath, config.baseUrl);
  if (addCallbackUrl) {
    url.searchParams.set("callbackUrl", safeCurrentPath);
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return `${url.pathname}${url.search}`;
}
async function protectPage(getSession, config, headers2, options) {
  const { session, failureReason } = await getSession();
  if (failureReason === "ACCOUNT_FORBIDDEN") {
    const redirectPath = buildRedirectUrl(
      config,
      options?.forbiddenRedirect || config.redirects.forbidden,
      headers2.get("x-next-pathname"),
      options?.redirectParams,
      false
      // Do not add callbackUrl for a forbidden redirect
    );
    (0, import_navigation.redirect)(redirectPath);
  }
  if (!session) {
    const targetPath = options?.unauthenticatedRedirect || config.redirects.unauthenticated;
    const redirectPath = buildRedirectUrl(
      config,
      targetPath,
      headers2.get("x-next-pathname"),
      options?.redirectParams,
      true
    );
    (0, import_navigation.redirect)(redirectPath);
  }
  if (options?.authorize) {
    const isAuthorized = await options.authorize({
      identity: session.identity,
      context: options.context
    });
    if (!isAuthorized) {
      const redirectPath = buildRedirectUrl(
        config,
        options?.unauthorizedRedirect || config.redirects.unauthorized,
        headers2.get("x-next-pathname"),
        options?.redirectParams,
        false
        // Do not add callbackUrl for an unauthorized redirect
      );
      (0, import_navigation.redirect)(redirectPath);
    }
  }
  return session;
}
async function protectAction(getSession, config, options) {
  const { session, failureReason } = await getSession();
  if (failureReason === "ACCOUNT_FORBIDDEN") {
    throw new IdentityForbiddenError(
      config.errorMessages.IdentityForbiddenError
    );
  }
  if (!session) {
    throw new NotAuthenticatedError(config.errorMessages.NotAuthenticatedError);
  }
  if (options?.authorize) {
    const isAuthorized = await options.authorize({
      identity: session.identity,
      context: options.context
    });
    if (!isAuthorized) {
      throw new ForbiddenError(config.errorMessages.ForbiddenError);
    }
  }
  return session;
}
async function protectApi(getSession, config, options) {
  const { session, failureReason } = await getSession();
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
    const isAuthorized = await options.authorize({
      identity: session.identity,
      context: options.context
    });
    if (!isAuthorized) {
      return {
        response: import_server.NextResponse.json({ error: "Forbidden" }, { status: 403 })
      };
    }
  }
  return { session };
}

// src/common/constants.ts
var AUTH_HEADER_KEY = "x-auth-identity";

// src/server/index.ts
function validateConfig(config) {
  const alg = config.jwt?.alg ?? "HS256";
  const validateSecret = (secret, secretName) => {
    const checkKey = (key, requiredType2) => {
      if (typeof key !== "string") {
        if (requiredType2 === "object") {
          throw new Error(
            `Auth configuration error: For ${alg}, keys in '${secretName}' should be PEM-encoded strings.`
          );
        }
      }
      if (requiredType2 === "string" && key.length < 32) {
        throw new Error(
          `Auth configuration error: For HS256, all string keys in '${secretName}' must be at least 32 characters long.`
        );
      }
    };
    const requiredType = alg === "HS256" ? "string" : "object";
    if (typeof secret === "string") {
      checkKey(secret, requiredType);
    } else if (Array.isArray(secret)) {
      if (secret.length === 0)
        throw new Error(
          `Auth configuration error: '${secretName}' array cannot be empty for key rotation.`
        );
      secret.forEach((s) => checkKey(s.key, requiredType));
    } else if (typeof secret === "object" && secret !== null) {
      checkKey(secret.key, requiredType);
    } else {
      throw new Error(
        `Auth configuration error: Invalid type for '${secretName}'.`
      );
    }
  };
  validateSecret(config.secrets.accessTokenSecret, "accessTokenSecret");
  validateSecret(config.secrets.refreshTokenSecret, "refreshTokenSecret");
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
  return {
    ...config,
    baseUrl: validateAndSanitizeBaseUrl(config.baseUrl)
  };
}
function createAuth(config) {
  const validatedConfig = validateConfig(config);
  const getEffectiveConfig = () => ({
    ...validatedConfig,
    debug: validatedConfig.debug ?? false,
    refreshTokenRotationIntervalSeconds: validatedConfig.refreshTokenRotationIntervalSeconds ?? 0,
    jwt: {
      alg: validatedConfig.jwt?.alg ?? "HS256",
      issuer: validatedConfig.jwt?.issuer ?? "",
      audience: validatedConfig.jwt?.audience ?? ""
    },
    rateLimit: validatedConfig.rateLimit ?? (async () => false),
    logger: validatedConfig.logger ?? ((level, message, ...args) => console[level](`[next-jwt-auth] ${message}`, ...args)),
    errorMessages: validatedConfig.errorMessages ?? {},
    providers: validatedConfig.providers ?? {},
    csrfEnabled: validatedConfig.csrfEnabled ?? false
  });
  const getSessionWithFailureReason = (0, import_react.cache)(
    async () => {
      const identityHeader = (await (0, import_headers2.headers)()).get(AUTH_HEADER_KEY);
      if (identityHeader) {
        try {
          const identity = JSON.parse(identityHeader);
          return { session: { identity } };
        } catch {
        }
      }
      return await validateSessionReadOnly(getEffectiveConfig());
    }
  );
  const getSession = async () => {
    return (await getSessionWithFailureReason()).session;
  };
  const createMiddleware = (matcher) => {
    return async (req) => {
      if (matcher && !matcher(req)) return import_server2.NextResponse.next();
      const effectiveConfig = getEffectiveConfig();
      const { session, newTokens } = await validateAndRefreshSession(
        effectiveConfig,
        req
      );
      const requestHeaders = new Headers(req.headers);
      requestHeaders.set("x-next-pathname", req.nextUrl.pathname);
      if (session) {
        requestHeaders.set(AUTH_HEADER_KEY, JSON.stringify(session.identity));
      }
      const response = import_server2.NextResponse.next({
        request: { headers: requestHeaders }
      });
      if (newTokens === null) {
        response.cookies.set(
          getClearAccessCookie(effectiveConfig.cookies.access.name)
        );
        response.cookies.set(
          getClearRefreshCookie(effectiveConfig.cookies.refresh.name)
        );
      } else if (newTokens?.accessToken) {
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
      if (session && effectiveConfig.csrfEnabled && !req.cookies.has("csrf_token")) {
        response.cookies.set(
          getCsrfCookie(effectiveConfig.cookies.access.maxAge)
        );
      }
      return response;
    };
  };
  const getCsrfToken = async () => {
    const cookieStore = await (0, import_headers2.cookies)();
    let token = cookieStore.get("csrf_token")?.value;
    if (!token) {
      const effectiveConfig = getEffectiveConfig();
      const newCookie = getCsrfCookie(effectiveConfig.cookies.access.maxAge);
      token = newCookie.value;
      cookieStore.set(newCookie);
    }
    return token;
  };
  const signIn2 = async (signInIdentifier, secret, mfaCode, provider, authCode) => {
    return signIn(
      signInIdentifier,
      secret,
      getEffectiveConfig(),
      mfaCode,
      provider,
      authCode
    );
  };
  const signOut2 = async () => {
    return signOut(getEffectiveConfig());
  };
  const protectPageWrapper = async (options) => {
    return protectPage(
      getSessionWithFailureReason,
      getEffectiveConfig(),
      await (0, import_headers2.headers)(),
      options
    );
  };
  const protectActionWrapper = async (options, formData) => {
    const effectiveConfig = getEffectiveConfig();
    if (effectiveConfig.csrfEnabled) {
      const cookieCsrf = (await (0, import_headers2.cookies)()).get("csrf_token")?.value;
      const formCsrf = formData?.get("csrf_token")?.toString();
      if (!formCsrf || !cookieCsrf || formCsrf !== cookieCsrf) {
        throw new CsrfError(effectiveConfig.errorMessages.CsrfError);
      }
    }
    return protectAction(getSessionWithFailureReason, effectiveConfig, options);
  };
  const protectApiWrapper = async (options) => {
    return protectApi(
      getSessionWithFailureReason,
      getEffectiveConfig(),
      options
    );
  };
  return {
    getSession,
    createMiddleware,
    signIn: signIn2,
    signOut: signOut2,
    getCsrfToken,
    protectPage: protectPageWrapper,
    protectAction: protectActionWrapper,
    protectApi: protectApiWrapper
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthError,
  CsrfError,
  ForbiddenError,
  IdentityForbiddenError,
  InvalidCredentialsError,
  NotAuthenticatedError,
  RateLimitError,
  createAuth,
  verifyAccessToken
});
