import { create } from "zustand";
import { getApiErrorMessage, getMe, login, logout } from "./api";
import type { User } from "./types";

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;
  initialize: () => Promise<void>;
  signIn: (username: string, password: string) => Promise<User>;
  signOut: () => Promise<void>;
  setUser: (user: User | null) => void;
  refreshUser: () => Promise<User | null>;
}

type ToastSeverity = "error" | "warning" | "info" | "success";

interface ToastItem {
  id: number;
  message: string;
  severity: ToastSeverity;
}

interface ToastState {
  nextId: number;
  toasts: ToastItem[];
  pushToast: (message: string, severity?: ToastSeverity) => void;
  dismissToast: (id: number) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: false,
  isInitialized: false,
  error: null,
  initialize: async () => {
    // На странице логина смысла дёргать /users/me нет — пользователь явно
    // не авторизован, лишний 401 в DevTools только сбивает с толку.
    if (typeof window !== "undefined" && window.location.pathname === "/login") {
      set({ user: null, isInitialized: true, isLoading: false, error: null });
      return;
    }
    set({ isLoading: true, error: null });
    try {
      const me = await getMe();
      set({ user: me, isInitialized: true, isLoading: false });
    } catch {
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
    } catch (error) {
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
    } catch {
      set({ user: null });
      return null;
    }
  },
}));

export const useToastStore = create<ToastState>((set) => ({
  nextId: 1,
  toasts: [],
  pushToast: (message, severity = "error") =>
    set((state) => ({
      nextId: state.nextId + 1,
      toasts: [...state.toasts, { id: state.nextId, message, severity }],
    })),
  dismissToast: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((toast) => toast.id !== id),
    })),
}));
