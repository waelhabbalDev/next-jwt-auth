"use strict";
"use client";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = useAuth;
const react_1 = require("react");
const provider_1 = require("./provider");
function useAuth() {
    const context = (0, react_1.useContext)(provider_1.AuthContext);
    if (context === null)
        throw new Error("useAuth must be used within an AuthProvider");
    return context;
}
//# sourceMappingURL=use-auth.js.map