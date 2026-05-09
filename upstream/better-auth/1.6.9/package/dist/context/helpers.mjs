import { getBaseURL, getOrigin, isDynamicBaseURLConfig, isRequestLike, resolveBaseURL } from "../utils/url.mjs";
import { isPromise } from "../utils/is-promise.mjs";
import { createCookieGetter, getCookies } from "../cookies/index.mjs";
import { createInternalAdapter } from "../db/internal-adapter.mjs";
import { env } from "@better-auth/core/env";
import { BetterAuthError } from "@better-auth/core/error";
import { defu } from "defu";
import { isLoopbackHost } from "@better-auth/core/utils/host";
//#region src/context/helpers.ts
async function runPluginInit(context) {
	let options = context.options;
	const plugins = options.plugins || [];
	const pluginTrustedOrigins = [];
	const dbHooks = [];
	for (const plugin of plugins) if (plugin.init) {
		const initPromise = plugin.init(context);
		let result;
		if (isPromise(initPromise)) result = await initPromise;
		else result = initPromise;
		if (typeof result === "object") {
			if (result.options) {
				const { databaseHooks, trustedOrigins, ...restOpts } = result.options;
				if (databaseHooks) dbHooks.push({
					source: `plugin:${plugin.id}`,
					hooks: databaseHooks
				});
				if (trustedOrigins) pluginTrustedOrigins.push(trustedOrigins);
				options = defu(options, restOpts);
			}
			if (result.context) Object.assign(context, result.context);
		}
	}
	if (pluginTrustedOrigins.length > 0) {
		const allSources = [...options.trustedOrigins ? [options.trustedOrigins] : [], ...pluginTrustedOrigins];
		const staticOrigins = allSources.filter(Array.isArray).flat();
		const dynamicOrigins = allSources.filter((s) => typeof s === "function");
		if (dynamicOrigins.length > 0) options.trustedOrigins = async (request) => {
			const resolved = await Promise.all(dynamicOrigins.map((fn) => fn(request)));
			return [...staticOrigins, ...resolved.flat()].filter((v) => typeof v === "string" && v !== "");
		};
		else options.trustedOrigins = staticOrigins;
	}
	if (options.databaseHooks) dbHooks.push({
		source: "user",
		hooks: options.databaseHooks
	});
	context.internalAdapter = createInternalAdapter(context.adapter, {
		options,
		logger: context.logger,
		hooks: dbHooks,
		generateId: context.generateId
	});
	context.options = options;
}
function getInternalPlugins(options) {
	const plugins = [];
	if (options.advanced?.crossSubDomainCookies?.enabled) {}
	return plugins;
}
async function getTrustedOrigins(options, request) {
	const trustedOrigins = [];
	if (isDynamicBaseURLConfig(options.baseURL)) {
		const allowedHosts = options.baseURL.allowedHosts;
		for (const host of allowedHosts) if (!host.includes("://")) {
			trustedOrigins.push(`https://${host}`);
			if (isLoopbackHost(host)) trustedOrigins.push(`http://${host}`);
		} else trustedOrigins.push(host);
		if (options.baseURL.fallback) try {
			trustedOrigins.push(new URL(options.baseURL.fallback).origin);
		} catch {}
	} else {
		const baseURL = getBaseURL(typeof options.baseURL === "string" ? options.baseURL : void 0, options.basePath, request);
		if (baseURL) trustedOrigins.push(new URL(baseURL).origin);
	}
	if (options.trustedOrigins) {
		if (Array.isArray(options.trustedOrigins)) trustedOrigins.push(...options.trustedOrigins);
		if (typeof options.trustedOrigins === "function") {
			const validOrigins = await options.trustedOrigins(request);
			trustedOrigins.push(...validOrigins);
		}
	}
	const envTrustedOrigins = env.BETTER_AUTH_TRUSTED_ORIGINS;
	if (envTrustedOrigins) trustedOrigins.push(...envTrustedOrigins.split(","));
	return trustedOrigins.filter((v) => Boolean(v));
}
/**
* Picks a `Request`-like or `Headers` value from a direct `auth.api` call.
* Headers are only accepted when they carry a host: without one, host
* resolution would fall back to `null` and the caller should use `fallback`
* or pass a `Request` instead.
*/
function pickSource(input) {
	if (isRequestLike(input?.request)) return input.request;
	if (!input?.headers) return void 0;
	const headers = input.headers instanceof Headers ? input.headers : new Headers(input.headers);
	if (!headers.has("host") && !headers.has("x-forwarded-host")) return;
	return headers;
}
/**
* Returns the effective `trustedProxyHeaders` value for dynamic `baseURL`
* resolution. When the user hasn't set `advanced.trustedProxyHeaders`,
* proxy headers (`x-forwarded-host` / `x-forwarded-proto`) are trusted by
* default so deployments behind a reverse proxy work without extra config.
*/
function resolveDynamicTrustedProxyHeaders(options) {
	return options.advanced?.trustedProxyHeaders ?? true;
}
/**
* Per-request clone with `baseURL`, `trustedOrigins`, `trustedProviders`
* and cookies rehydrated for the resolved host. Throws `BetterAuthError`
* when the URL cannot be resolved; callers on the direct-API path convert
* this to `APIError`.
*/
async function resolveRequestContext(ctx, source, trustedProxyHeaders) {
	const dynamicBaseURLConfig = ctx.options.baseURL;
	const baseURL = resolveBaseURL(dynamicBaseURLConfig, ctx.options.basePath || "/api/auth", source, void 0, trustedProxyHeaders);
	if (!baseURL) throw new BetterAuthError("Could not resolve base URL from request. Check your allowedHosts config.");
	const resolved = Object.create(Object.getPrototypeOf(ctx), Object.getOwnPropertyDescriptors(ctx));
	resolved.baseURL = baseURL;
	resolved.options = {
		...ctx.options,
		baseURL: getOrigin(baseURL) || void 0
	};
	const trustedOriginOptions = {
		...resolved.options,
		baseURL: dynamicBaseURLConfig
	};
	const needsRequest = typeof ctx.options.trustedOrigins === "function" || typeof ctx.options.account?.accountLinking?.trustedProviders === "function";
	let callbackRequest;
	if (needsRequest) if (isRequestLike(source)) callbackRequest = source;
	else if (source) callbackRequest = new Request(baseURL, { headers: source });
	else callbackRequest = void 0;
	else callbackRequest = void 0;
	resolved.trustedOrigins = await getTrustedOrigins(trustedOriginOptions, callbackRequest);
	resolved.trustedProviders = await getTrustedProviders(resolved.options, callbackRequest);
	if (ctx.options.advanced?.crossSubDomainCookies?.enabled) {
		resolved.authCookies = getCookies(resolved.options);
		resolved.createAuthCookie = createCookieGetter(resolved.options);
	}
	return resolved;
}
async function getAwaitableValue(arr, item) {
	if (!arr) return void 0;
	for (const val of arr) {
		const value = typeof val === "function" ? await val() : val;
		if (value[item.field ?? "id"] === item.value) return value;
	}
}
async function getTrustedProviders(options, request) {
	const trustedProviders = options.account?.accountLinking?.trustedProviders;
	if (!trustedProviders) return [];
	if (Array.isArray(trustedProviders)) return trustedProviders.filter((v) => Boolean(v));
	return (await trustedProviders(request) ?? []).filter((v) => Boolean(v));
}
//#endregion
export { getAwaitableValue, getInternalPlugins, getTrustedOrigins, getTrustedProviders, pickSource, resolveDynamicTrustedProxyHeaders, resolveRequestContext, runPluginInit };
