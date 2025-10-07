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
function CsrfInput() {
  const token = useContext(CsrfContext);
  if (token === null) {
    console.warn(
      "[next-jwt-auth] CsrfInput component was rendered without a CsrfProvider parent. The CSRF token will not be included in form submissions."
    );
  }
  return /* @__PURE__ */ jsx("input", { type: "hidden", name: "csrf_token", value: token || "" });
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
  useAuth
};
