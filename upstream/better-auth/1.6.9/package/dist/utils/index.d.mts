import { generateState, parseState } from "../oauth2/state.mjs";
import { StateData, generateGenericState, parseGenericState } from "../state.mjs";
import { HIDE_METADATA } from "./hide-metadata.mjs";
import { getBaseURL, getHost, getHostFromSource, getOrigin, getProtocol, getProtocolFromSource, isDynamicBaseURLConfig, isRequestLike, matchesHostPattern, resolveBaseURL, resolveDynamicBaseURL } from "./url.mjs";