import {
  CsrfInput,
  CsrfProvider
} from "./chunk-2OP7KWVV.mjs";

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

// src/service.ts
import { NextResponse } from "next/server";
import { cookies as cookies2, headers as headers2 } from "next/headers";
import { redirect } from "next/navigation";

// src/authentication.ts
import { cookies, headers } from "next/headers";

// src/tokens.ts
import { SignJWT, jwtVerify } from "jose";
import { v4 as uuidv4 } from "uuid";
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
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: algorithm, kid: signingKey.kid }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(signingKey.key);
}
async function verifyAccessToken(token, secret, jwtOptions) {
  try {
    const keyResolver = createKeyResolver(secret);
    const { payload } = await jwtVerify(
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
    jti: uuidv4()
  };
  const algorithm = getAlgorithm(jwtOptions?.alg);
  const signingKey = resolveSigningKey(secret);
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: algorithm, kid: signingKey.kid }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(signingKey.key);
}
async function verifyRefreshToken(token, secret, jwtOptions) {
  try {
    const keyResolver = createKeyResolver(secret);
    const { payload } = await jwtVerify(
      token,
      keyResolver,
      { algorithms: [getAlgorithm(jwtOptions?.alg)] }
    );
    return { payload };
  } catch {
    return null;
  }
}

// src/cookies.ts
import { randomBytes } from "crypto";
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
  const token = randomBytes(32).toString("hex");
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

// src/errors.ts
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

// src/constants.ts
var AUTH_HEADER_KEY = "x-auth-identity";
var HEADER_PATHNAME_KEY = "x-auth-pathname";

// src/authentication.ts
function log(config, level, message, ...args) {
  if (config.debug) {
    config.logger(level, message, ...args);
  }
}
async function validateSessionFromCookies(config, req) {
  log(config, "info", "Performing full auth check from cookies.");
  const cookieStore = req ? req.cookies : await cookies();
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
    log(
      config,
      "warn",
      `SECURITY ALERT: Reused refresh token detected (JTI: ${jti}). All sessions invalidated.`
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
  const refreshTokenRotationInterval = config.refreshTokenRotationIntervalSeconds;
  const shouldRotateRefresh = refreshTokenRotationInterval > 0 && tokenAge >= refreshTokenRotationInterval;
  const newAccessToken = await issueAccessToken(
    identity,
    config.secrets.accessTokenSecret,
    config.cookies.access.maxAge,
    config.jwt
  );
  let newRefreshToken;
  if (shouldRotateRefresh) {
    log(
      config,
      "info",
      `Rotating refresh token (Age: ${tokenAge}s >= Interval: ${refreshTokenRotationInterval}s, JTI: ${jti}).`
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
async function getSessionAndRefresh(config, req) {
  if (!req) {
    const headersList = await headers();
    const identityHeader = headersList.get(AUTH_HEADER_KEY);
    if (identityHeader) {
      try {
        log(config, "info", "Using pre-validated identity from header.");
        const identity = JSON.parse(identityHeader);
        return { session: { identity }, newTokens: void 0 };
      } catch (e) {
        log(config, "error", `Malformed ${AUTH_HEADER_KEY} header.`, e);
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
  const cookieStore = await cookies();
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
  if (config.csrfEnabled) {
    cookieStore.set(getCsrfCookie(cookieConfig.access.maxAge));
  }
  return { accessToken, refreshToken };
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
  await issueAndSetTokens(identity, config);
  log(
    config,
    "info",
    `Successful sign-in for identifier: ${identity.identifier}`
  );
  const { version, isForbidden, ...publicIdentity } = identity;
  return publicIdentity;
}
async function signOut(config) {
  const cookieStore = await cookies();
  const refreshTokenValue = cookieStore.get(config.cookies.refresh.name)?.value;
  cookieStore.set(getClearAccessCookie(config.cookies.access.name));
  cookieStore.set(getClearRefreshCookie(config.cookies.refresh.name));
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
    `Successful sign-out for identifier: ${verified.payload.identifier}`
  );
}

// src/service.ts
var AuthService = class {
  constructor(config) {
    this.config = {
      ...config,
      dal: config.dal,
      secrets: config.secrets,
      cookies: config.cookies,
      baseUrl: config.baseUrl,
      redirects: config.redirects,
      debug: config.debug ?? false,
      refreshTokenRotationIntervalSeconds: config.refreshTokenRotationIntervalSeconds ?? 0,
      jwt: {
        alg: config.jwt?.alg ?? "HS256",
        issuer: config.jwt?.issuer ?? "",
        audience: config.jwt?.audience ?? ""
      },
      rateLimit: config.rateLimit ?? (async () => false),
      logger: config.logger ?? ((level, message, ...args) => console[level](`[next-jwt-auth] ${message}`, ...args)),
      errorMessages: config.errorMessages ?? {},
      providers: config.providers ?? {},
      csrfEnabled: config.csrfEnabled ?? false
    };
    this.CsrfProvider = CsrfProvider;
    this.CsrfInput = CsrfInput;
  }
  async getCsrfToken() {
    const cookieStore = await cookies2();
    let token = cookieStore.get("csrf_token")?.value;
    if (!token) {
      const csrfCookie = getCsrfCookie(this.config.cookies.access.maxAge);
      token = csrfCookie.value;
      cookieStore.set(csrfCookie);
    }
    return token;
  }
  async getSession() {
    const { session, newTokens } = await getSessionAndRefresh(this.config);
    await this.handleTokenRefreshInResponse(newTokens);
    return session;
  }
  async refreshSession() {
    const { newTokens } = await getSessionAndRefresh(this.config);
    await this.handleTokenRefreshInResponse(newTokens);
  }
  async signIn(signInIdentifier, secret, mfaCode, provider, authCode) {
    return signIn(
      signInIdentifier,
      secret,
      this.config,
      mfaCode,
      provider,
      authCode
    );
  }
  signOut() {
    return signOut(this.config);
  }
  createMiddleware(matcher = () => true) {
    return async (req) => {
      if (!matcher(req)) return NextResponse.next();
      const requestHeaders = new Headers(req.headers);
      requestHeaders.set(HEADER_PATHNAME_KEY, req.nextUrl.pathname);
      const { session, newTokens } = await getSessionAndRefresh(
        this.config,
        req
      );
      if (session) {
        requestHeaders.set(AUTH_HEADER_KEY, JSON.stringify(session.identity));
      }
      const response = NextResponse.next({
        request: { headers: requestHeaders }
      });
      this.handleTokenRefreshInMiddleware(response, newTokens);
      return response;
    };
  }
  async protectPage(options) {
    const { session, newTokens, failureReason } = await getSessionAndRefresh(
      this.config
    );
    await this.handleTokenRefreshInResponse(newTokens);
    if (failureReason === "ACCOUNT_FORBIDDEN") {
      const redirectPath = await this.buildRedirectUrl(
        options?.forbiddenRedirect || this.config.redirects.forbidden,
        { ...options?.redirectParams, error: "account_suspended" }
      );
      redirect(redirectPath);
    }
    if (!session) {
      const redirectPath = await this.buildRedirectUrl(
        options?.unauthenticatedRedirect || this.config.redirects.unauthenticated,
        options?.redirectParams
      );
      redirect(redirectPath);
    }
    if (options?.authorize) {
      const isAuthorized = await options.authorize(
        session.identity,
        options.context
      );
      if (!isAuthorized) {
        const redirectPath = await this.buildRedirectUrl(
          options?.unauthorizedRedirect || this.config.redirects.unauthorized,
          options?.redirectParams
        );
        redirect(redirectPath);
      }
    }
    return session;
  }
  createProtectedAction(action, options) {
    return async (formData) => {
      await this.protectAction(options, formData);
      return action(formData);
    };
  }
  async protectAction(options, formData) {
    const { session, newTokens, failureReason } = await getSessionAndRefresh(
      this.config
    );
    await this.handleTokenRefreshInResponse(newTokens);
    if (this.config.csrfEnabled) {
      const cookieStore = await cookies2();
      const cookieCsrf = cookieStore.get("csrf_token")?.value;
      const formCsrf = formData?.get("csrf_token")?.toString();
      if (formData) {
        if (!formCsrf || !cookieCsrf || formCsrf !== cookieCsrf) {
          throw new CsrfError(this.config.errorMessages.CsrfError);
        }
      } else {
        const headersList = await headers2();
        const headerCsrf = headersList.get("x-csrf-token");
        if (!headerCsrf || !cookieCsrf || headerCsrf !== cookieCsrf) {
          throw new CsrfError(this.config.errorMessages.CsrfError);
        }
      }
    }
    if (failureReason === "ACCOUNT_FORBIDDEN")
      throw new ForbiddenError("This account is suspended.");
    if (!session)
      throw new NotAuthenticatedError(
        this.config.errorMessages.NotAuthenticatedError
      );
    if (options?.authorize) {
      const isAuthorized = await options.authorize(
        session.identity,
        options.context
      );
      if (!isAuthorized)
        throw new ForbiddenError(this.config.errorMessages.ForbiddenError);
    }
    return session;
  }
  async protectApi(options) {
    const { session, newTokens, failureReason } = await getSessionAndRefresh(
      this.config
    );
    await this.handleTokenRefreshInResponse(newTokens);
    if (failureReason === "ACCOUNT_FORBIDDEN") {
      return {
        session: null,
        response: NextResponse.json(
          { error: "Account suspended" },
          { status: 403 }
        )
      };
    }
    if (!session) {
      return {
        session: null,
        response: NextResponse.json(
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
          session: null,
          response: NextResponse.json({ error: "Forbidden" }, { status: 403 })
        };
      }
    }
    return { session, response: null };
  }
  async handleTokenRefreshInResponse(newTokens) {
    if (!newTokens) return;
    const cookieStore = await cookies2();
    if (!newTokens.accessToken) {
      cookieStore.set(getClearAccessCookie(this.config.cookies.access.name));
      cookieStore.set(getClearRefreshCookie(this.config.cookies.refresh.name));
    } else {
      cookieStore.set(
        getAccessCookie(
          newTokens.accessToken,
          this.config.cookies.access.name,
          this.config.cookies.access.maxAge
        )
      );
      if (newTokens.refreshToken) {
        cookieStore.set(
          getRefreshCookie(
            newTokens.refreshToken,
            this.config.cookies.refresh.name,
            this.config.cookies.refresh.maxAge
          )
        );
      }
    }
  }
  handleTokenRefreshInMiddleware(response, newTokens) {
    if (!newTokens) return;
    if (!newTokens.accessToken) {
      response.cookies.set(
        getClearAccessCookie(this.config.cookies.access.name)
      );
      response.cookies.set(
        getClearRefreshCookie(this.config.cookies.refresh.name)
      );
    } else {
      response.cookies.set(
        getAccessCookie(
          newTokens.accessToken,
          this.config.cookies.access.name,
          this.config.cookies.access.maxAge
        )
      );
      if (newTokens.refreshToken) {
        response.cookies.set(
          getRefreshCookie(
            newTokens.refreshToken,
            this.config.cookies.refresh.name,
            this.config.cookies.refresh.maxAge
          )
        );
      }
    }
  }
  async buildRedirectUrl(targetPath, params = {}) {
    const headersList = await headers2();
    const rawPathname = headersList.get(HEADER_PATHNAME_KEY);
    const currentPath = sanitizeRedirectPath(rawPathname);
    const url = new URL(targetPath, this.config.baseUrl);
    if (targetPath === this.config.redirects.unauthenticated) {
      url.searchParams.set("callbackUrl", currentPath);
    }
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }
    return `${url.pathname}${url.search}`;
  }
};

// src/index.ts
function validateConfig(config) {
  const alg = config.jwt?.alg ?? "HS256";
  const validateSecret = (secret, secretName) => {
    const checkKey = (key, requiredType2) => {
      if (typeof key !== requiredType2) {
        throw new Error(
          `Auth configuration error: For ${alg}, all keys in '${secretName}' must be of type '${requiredType2}'.`
        );
      }
      if (requiredType2 === "string" && typeof key === "string" && key.length < 32) {
        throw new Error(
          `Auth configuration error: For HS256, all string keys in '${secretName}' must be at least 32 characters long.`
        );
      }
    };
    const requiredType = alg === "HS256" ? "string" : "object";
    if (typeof secret === "string" || typeof secret === "object" && !Array.isArray(secret)) {
      const key = typeof secret === "string" ? secret : secret.key;
      checkKey(key, requiredType);
    } else if (Array.isArray(secret)) {
      if (secret.length === 0)
        throw new Error(
          `Auth configuration error: '${secretName}' array cannot be empty for key rotation.`
        );
      secret.forEach((s) => checkKey(s.key, requiredType));
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
  const service = new AuthService(validatedConfig);
  return {
    getCsrfToken: service.getCsrfToken.bind(service),
    CsrfProvider: service.CsrfProvider,
    CsrfInput: service.CsrfInput,
    getSession: service.getSession.bind(service),
    refreshSession: service.refreshSession.bind(service),
    signIn: service.signIn.bind(service),
    signOut: service.signOut.bind(service),
    createMiddleware: service.createMiddleware.bind(service),
    // Protection methods
    protectPage: service.protectPage.bind(service),
    protectAction: service.protectAction.bind(service),
    // The manual method
    protectApi: service.protectApi.bind(service),
    createProtectedAction: service.createProtectedAction.bind(service)
  };
}
export {
  AuthError,
  CsrfError,
  ForbiddenError,
  IdentityForbiddenError,
  InvalidCredentialsError,
  NotAuthenticatedError,
  RateLimitError,
  createAuth,
  verifyAccessToken
};
