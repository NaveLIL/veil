/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_VEIL_WS_URL?: string;
  readonly VITE_VEIL_HTTP_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
