import { useEffect } from "react";
import { useToastStore } from "./store";
export function useToastMessage(message, severity) {
    const pushToast = useToastStore((state) => state.pushToast);
    useEffect(() => {
        if (!message) {
            return;
        }
        pushToast(message, severity);
    }, [message, pushToast, severity]);
}
export function useErrorToast(error) {
    useToastMessage(error, "error");
}
