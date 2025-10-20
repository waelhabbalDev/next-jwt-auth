"use client";

// src/client/index.tsx
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
      "[next-jwt-auth] useCsrf was called outside of a CsrfProvider. Token will be null. Ensure the parent Server Component is passing the token."
    );
  }
  return token;
}
function CsrfInput() {
  const token = useContext(CsrfContext);
  if (!token) {
    console.warn(
      "[next-jwt-auth] CsrfInput could not find a token. Ensure it is wrapped in a <CsrfProvider> with a token passed from the server."
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
  const contextValue = useMemo(
    () => ({
      session,
      identity: session?.identity ?? null,
      isAuthenticated: !!session,
      isLoading,
      error: actionError || swrError || null,
      signIn: handleSignIn,
      signOut: handleSignOut,
      mutate
    }),
    [
      session,
      isLoading,
      actionError,
      swrError,
      handleSignIn,
      handleSignOut,
      mutate
    ]
  );
  return /* @__PURE__ */ jsx(AuthContext.Provider, { value: contextValue, children });
}
function useAuth() {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
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
