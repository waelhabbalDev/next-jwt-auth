"use client";

// src/index.client.tsx
import {
  createContext,
  useMemo,
  useCallback,
  useState,
  useContext
} from "react";
import useSWR from "swr";
import { jsx } from "react/jsx-runtime";
var CsrfContext = createContext(null);
function CsrfProvider({
  token,
  children
}) {
  return /* @__PURE__ */ jsx(CsrfContext.Provider, { value: token, children });
}
function useCsrf() {
  const token = useContext(CsrfContext);
  if (token === null) {
    console.warn(
      "[next-jwt-auth] useCsrf was called outside of a CsrfProvider. Token will be undefined."
    );
  }
  return token;
}
function CsrfInput({
  getTokenAction
}) {
  const contextToken = useContext(CsrfContext);
  const { data: swrToken, isLoading } = useSWR(
    !contextToken && getTokenAction ? "csrf-token" : null,
    getTokenAction || null
  );
  const token = contextToken || swrToken;
  if (!contextToken && isLoading) {
    return null;
  }
  if (!token) {
    console.warn(
      "[next-jwt-auth] CsrfInput could not find a token. Ensure it's within a CsrfProvider or the `getTokenAction` prop is provided."
    );
    return null;
  }
  return /* @__PURE__ */ jsx("input", { type: "hidden", name: "csrf_token", value: token });
}
var AuthContext = createContext(null);
function AuthProvider({
  children,
  initialSession,
  sessionFetcher,
  signInAction,
  signOutAction,
  refreshAction
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
    async (signInIdentifier, secret, mfaCode, provider, authCode) => {
      setActionError(null);
      try {
        const identity = await signInAction(
          signInIdentifier,
          secret,
          mfaCode,
          provider,
          authCode
        );
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
      await mutate(null, { revalidate: false });
    } catch (err) {
      setActionError(err);
    }
  }, [signOutAction, mutate]);
  const handleRefresh = useCallback(async () => {
    try {
      await refreshAction();
      await mutate();
    } catch (err) {
      setActionError(err);
    }
  }, [refreshAction, mutate]);
  const contextValue = useMemo(
    () => ({
      session,
      identity: session?.identity ?? null,
      isAuthenticated: !!session?.identity,
      isLoading,
      error: actionError || swrError || null,
      signIn: handleSignIn,
      signOut: handleSignOut,
      refresh: handleRefresh,
      mutate
    }),
    [
      session,
      isLoading,
      handleSignIn,
      handleSignOut,
      handleRefresh,
      mutate,
      actionError,
      swrError
    ]
  );
  return /* @__PURE__ */ jsx(AuthContext.Provider, { value: contextValue, children });
}
function useAuth() {
  const context = useContext(AuthContext);
  if (context === null)
    throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
export {
  AuthContext,
  AuthProvider,
  CsrfInput,
  CsrfProvider,
  useAuth,
  useCsrf
};
