import { BaseURLConfig, DynamicBaseURLConfig } from "@better-auth/core";

//#region src/utils/url.d.ts
declare function getBaseURL(url?: string, path?: string, request?: Request, loadEnv?: boolean, trustedProxyHeaders?: boolean | undefined): string | undefined;
declare function getOrigin(url: string): string | null;
declare function getProtocol(url: string): string | null;
declare function getHost(url: string): string | null;
/**
 * Checks if the baseURL config is a dynamic config object
 */
declare function isDynamicBaseURLConfig(config: BaseURLConfig | undefined): config is DynamicBaseURLConfig;
/**
 * Check if a value is a `Request`
 * - `instanceof`: works for native Request instances
 * - `toString`: handles where instanceof check fails but the object is still a
 *   valid Request (e.g. cross-realm, polyfills). Paired with a shape check so
 *   an object that only spoofs `Symbol.toStringTag` without the real shape is
 *   rejected before downstream code tries to read `.headers` / `.url`.
 *
 * @param value The value to check
 * @returns `true` if the value is a Request instance
 */
declare function isRequestLike(value: unknown): value is Request;
/**
 * Extracts the host from a `Request` or `Headers`.
 * Honors `x-forwarded-host` only when `trustedProxyHeaders` is enabled,
 * then falls back to the `host` header and finally the request URL.
 */
declare function getHostFromSource(source: Request | Headers, trustedProxyHeaders?: boolean): string | null;
/**
 * Extracts the protocol from a `Request` or `Headers`.
 * Honors `x-forwarded-proto` only when `trustedProxyHeaders` is enabled,
 * then falls back to the request URL, then to "https".
 */
declare function getProtocolFromSource(source: Request | Headers, configProtocol?: "http" | "https" | "auto" | undefined, trustedProxyHeaders?: boolean): "http" | "https";
/**
 * Matches a hostname against a host pattern.
 * Supports wildcard patterns like `*.vercel.app` or `preview-*.myapp.com`.
 *
 * @param host The hostname to test (e.g., "myapp.com", "preview-123.vercel.app")
 * @param pattern The host pattern (e.g., "myapp.com", "*.vercel.app")
 * @returns {boolean} true if the host matches the pattern, false otherwise.
 *
 * @example
 * ```ts
 * matchesHostPattern("myapp.com", "myapp.com") // true
 * matchesHostPattern("preview-123.vercel.app", "*.vercel.app") // true
 * matchesHostPattern("preview-123.myapp.com", "preview-*.myapp.com") // true
 * matchesHostPattern("evil.com", "myapp.com") // false
 * ```
 */
declare const matchesHostPattern: (host: string, pattern: string) => boolean;
/**
 * Resolves the base URL from a dynamic config based on the incoming request.
 * Validates the derived host against the allowedHosts allowlist.
 *
 * @param config The dynamic base URL config
 * @param request The incoming request
 * @param basePath The base path to append
 * @returns The resolved base URL with path
 * @throws BetterAuthError if host is not in allowedHosts and no fallback is set
 */
declare function resolveDynamicBaseURL(config: DynamicBaseURLConfig, source: Request | Headers, basePath: string, trustedProxyHeaders?: boolean): string;
/**
 * Resolves the base URL from any config type (static string or dynamic object).
 * This is the main entry point for base URL resolution.
 *
 * @param config The base URL config (string or object)
 * @param basePath The base path to append
 * @param request Optional request for dynamic resolution
 * @param loadEnv Whether to load from environment variables
 * @param trustedProxyHeaders Whether to trust proxy headers (for legacy behavior)
 * @returns The resolved base URL with path
 */
declare function resolveBaseURL(config: BaseURLConfig | undefined, basePath: string, source?: Request | Headers, loadEnv?: boolean, trustedProxyHeaders?: boolean): string | undefined;
//#endregion
export { getBaseURL, getHost, getHostFromSource, getOrigin, getProtocol, getProtocolFromSource, isDynamicBaseURLConfig, isRequestLike, matchesHostPattern, resolveBaseURL, resolveDynamicBaseURL };