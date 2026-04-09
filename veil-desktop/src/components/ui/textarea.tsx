import { splitProps, type Component, type JSX } from "solid-js";
import { cn } from "@/lib/utils";

export interface TextareaProps extends JSX.TextareaHTMLAttributes<HTMLTextAreaElement> {}

export const Textarea: Component<TextareaProps> = (props) => {
  const [local, rest] = splitProps(props, ["class"]);

  return (
    <textarea
      class={cn(
        "flex min-h-[40px] w-full rounded-md border border-input bg-muted px-3 py-2 text-sm",
        "text-foreground placeholder:text-muted-foreground resize-none",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "disabled:cursor-not-allowed disabled:opacity-50",
        local.class
      )}
      {...rest}
    />
  );
};
