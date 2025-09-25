import { AuthContextType } from "./provider";
import { UserIdentity } from "../types";
export declare function useAuth<T extends UserIdentity>(): AuthContextType<T>;
