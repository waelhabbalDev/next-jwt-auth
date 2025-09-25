// src/index.ts
import { NextResponse } from "next/server";

// src/server/authentication.ts
import { cookies } from "next/headers";

// src/core/tokens.ts
import { SignJWT, jwtVerify } from "jose";
import { v4 as uuidv4 } from "uuid";
var getSecretKey = (secret) => new TextEncoder().encode(secret);
async function issueAccessToken(identity, secret, expiresIn, jwtOptions) {
  const { version, isForbidden, ...payload } = identity;
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(getSecretKey(secret));
}
async function verifyAccessToken(token, secret) {
  try {
    const { payload } = await jwtVerify(
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
    jti: uuidv4()
  };
  let jwt = new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setSubject(identity.identifier).setExpirationTime(`${expiresIn}s`);
  if (jwtOptions?.issuer) jwt = jwt.setIssuer(jwtOptions.issuer);
  if (jwtOptions?.audience) jwt = jwt.setAudience(jwtOptions.audience);
  return jwt.sign(getSecretKey(secret));
}
async function verifyRefreshToken(token, secret) {
  try {
    const { payload } = await jwtVerify(
      token,
      getSecretKey(secret)
    );
    return { payload };
  } catch {
    return null;
  }
}

// src/core/cookies.ts
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

// src/core/errors.ts
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

// src/server/authentication.ts
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
  const cookieStore = await cookies();
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
  const cookieStore = req ? req.cookies : await cookies();
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
import { cookies as cookies2 } from "next/headers";

// src/client/provider.tsx
import { createContext, useMemo, useCallback, useState } from "react";
import useSWR from "swr";
import { jsx } from "react/jsx-runtime";
var AuthContext = createContext(null);
function AuthProvider({
  children,
  initialSession,
  sessionFetcher,
  signInAction,
  signOutAction
}) {
  const {
    data: session,
    isLoading,
    mutate,
    error: swrError
  } = useSWR(
    "auth-session-key",
    sessionFetcher,
    {
      fallbackData: initialSession,
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      shouldRetryOnError: false
    }
  );
  const [actionError, setActionError] = useState(null);
  const handleSignIn = useCallback(
    async (signInIdentifier, secret) => {
      setActionError(null);
      try {
        const identity = await signInAction(signInIdentifier, secret);
        await mutate();
        return identity;
      } catch (err) {
        setActionError(err);
        return null;
      }
    },
    [signInAction, mutate]
  );
  const handleSignOut = useCallback(async () => {
    setActionError(null);
    try {
      await signOutAction();
      await mutate(null, { revalidate: true });
    } catch (err) {
      setActionError(err);
    }
  }, [signOutAction, mutate]);
  const contextValue = useMemo(
    () => ({
      session,
      identity: session?.identity ?? null,
      isAuthenticated: !!session?.identity,
      isLoading,
      error: actionError || swrError || null,
      signIn: handleSignIn,
      signOut: handleSignOut,
      mutate
    }),
    [
      session,
      isLoading,
      handleSignIn,
      handleSignOut,
      mutate,
      actionError,
      swrError
    ]
  );
  return /* @__PURE__ */ jsx(AuthContext.Provider, { value: contextValue, children });
}

// src/client/use-auth.ts
import { useContext } from "react";
function useAuth() {
  const context = useContext(AuthContext);
  if (context === null)
    throw new Error("useAuth must be used within an AuthProvider");
  return context;
}

// src/index.ts
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
      const cookieStore = await cookies2();
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
      if (!matcher(req)) return NextResponse.next();
      const { newTokens } = await getAuthSession(effectiveConfig, req);
      const response = NextResponse.next();
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
export {
  AuthError,
  AuthProvider,
  IdentityForbiddenError,
  InvalidCredentialsError,
  createAuth,
  useAuth,
  verifyAccessToken
};
