import { create } from "zustand";
import { getApiErrorMessage, getMe, login, logout } from "./api";
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
        catch (error) {
            const message = getApiErrorMessage(error, "Не удалось выполнить вход");
            set({ error: message, isLoading: false });
            throw new Error(message);
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
export const useToastStore = create((set) => ({
    nextId: 1,
    toasts: [],
    pushToast: (message, severity = "error") => set((state) => ({
        nextId: state.nextId + 1,
        toasts: [...state.toasts, { id: state.nextId, message, severity }],
    })),
    dismissToast: (id) => set((state) => ({
        toasts: state.toasts.filter((toast) => toast.id !== id),
    })),
}));
