// Until identity-bearing directories are paginated/virtualized, never let one
// authenticated remote response expand into an unbounded number of WebView
// DOM/SVG nodes. This is presentation-only: authorization, friendship state,
// and Sender-Key membership continue to use the complete native/store data.
export const IDENTITY_ROW_RENDER_BUDGET = 256;

export function boundedIdentityRows<T>(rows: readonly T[]): readonly T[] {
  return rows.length > IDENTITY_ROW_RENDER_BUDGET
    ? rows.slice(0, IDENTITY_ROW_RENDER_BUDGET)
    : rows;
}
