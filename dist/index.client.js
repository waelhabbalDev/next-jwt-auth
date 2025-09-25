"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
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
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.client.ts
var index_client_exports = {};
__export(index_client_exports, {
  AuthProvider: () => AuthProvider,
  useAuth: () => useAuth
});
module.exports = __toCommonJS(index_client_exports);

// src/client/provider.tsx
var import_react = require("react");
var import_swr = __toESM(require("swr"));
var import_jsx_runtime = require("react/jsx-runtime");
var AuthContext = (0, import_react.createContext)(null);
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
  } = (0, import_swr.default)(
    "auth-session-key",
    sessionFetcher,
    {
      fallbackData: initialSession,
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
      shouldRetryOnError: false
    }
  );
  const [actionError, setActionError] = (0, import_react.useState)(null);
  const handleSignIn = (0, import_react.useCallback)(
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
  const handleSignOut = (0, import_react.useCallback)(async () => {
    setActionError(null);
    try {
      await signOutAction();
      await mutate(null, { revalidate: true });
    } catch (err) {
      setActionError(err);
    }
  }, [signOutAction, mutate]);
  const contextValue = (0, import_react.useMemo)(
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
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AuthContext.Provider, { value: contextValue, children });
}

// src/client/use-auth.ts
var import_react2 = require("react");
function useAuth() {
  const context = (0, import_react2.useContext)(AuthContext);
  if (context === null)
    throw new Error("useAuth must be used within an AuthProvider");
  return context;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthProvider,
  useAuth
});
