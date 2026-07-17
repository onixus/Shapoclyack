import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { fetchMe, login as apiLogin, type Role } from "./api";

type AuthState = {
  token: string | null;
  username: string | null;
  role: Role | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  canOperate: boolean;
};

const AuthContext = createContext<AuthState | null>(null);
const STORAGE_KEY = "shapoclyack_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY));
  const [username, setUsername] = useState<string | null>(null);
  const [role, setRole] = useState<Role | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function hydrate() {
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const me = await fetchMe(token);
        if (!cancelled) {
          setUsername(me.username);
          setRole(me.role);
        }
      } catch {
        if (!cancelled) {
          localStorage.removeItem(STORAGE_KEY);
          setToken(null);
          setUsername(null);
          setRole(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void hydrate();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const login = useCallback(async (user: string, password: string) => {
    const result = await apiLogin(user, password);
    localStorage.setItem(STORAGE_KEY, result.access_token);
    setToken(result.access_token);
    setUsername(result.username);
    setRole(result.role);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setToken(null);
    setUsername(null);
    setRole(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      token,
      username,
      role,
      loading,
      login,
      logout,
      canOperate: role === "operator" || role === "admin",
    }),
    [token, username, role, loading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
