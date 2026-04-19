import { create } from "zustand";
import { getMe, login, logout } from "./api";
export const useAuthStore = create((set) => ({
    user: null,
    isLoading: false,
    isInitialized: false,
    error: null,
    initialize: async () => {
        set({ isLoading: true, error: null });
        try {
            const me = await getMe();
            set({ user: me, isInitialized: true, isLoading: false });
        }
        catch {
            set({ user: null, isInitialized: true, isLoading: false });
        }
    },
    signIn: async (username, password) => {
        set({ isLoading: true, error: null });
        try {
            await login(username, password);
            const me = await getMe();
            set({ user: me, isLoading: false });
            return me;
        }
        catch {
            set({ error: "Не удалось выполнить вход", isLoading: false });
            throw new Error("login failed");
        }
    },
    signOut: async () => {
        await logout();
        set({ user: null });
    },
    setUser: (user) => set({ user }),
    refreshUser: async () => {
        try {
            const me = await getMe();
            set({ user: me });
            return me;
        }
        catch {
            set({ user: null });
            return null;
        }
    },
}));
