import { useEffect } from "react";
import { useToastStore } from "./store";

export function useToastMessage(message: string | null | undefined, severity: "error" | "warning" | "info" | "success") {
  const pushToast = useToastStore((state) => state.pushToast);

  useEffect(() => {
    if (!message) {
      return;
    }
    pushToast(message, severity);
  }, [message, pushToast, severity]);
}

export function useErrorToast(error: string | null | undefined) {
  useToastMessage(error, "error");
}
