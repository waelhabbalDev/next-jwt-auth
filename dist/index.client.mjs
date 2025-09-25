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
export {
  AuthProvider,
  useAuth
};
