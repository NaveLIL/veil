import { splitProps, type Component, type JSX } from "solid-js";
import { cn } from "@/lib/utils";

export interface InputProps extends JSX.InputHTMLAttributes<HTMLInputElement> {}

export const Input: Component<InputProps> = (props) => {
  const [local, rest] = splitProps(props, ["class"]);

  return (
    <input
      class={cn(
        "flex h-10 w-full rounded-md border border-input bg-muted px-3 py-2 text-sm",
        "text-foreground placeholder:text-muted-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "disabled:cursor-not-allowed disabled:opacity-50",
        local.class
      )}
      {...rest}
    />
  );
};
