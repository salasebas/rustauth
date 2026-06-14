export interface DocsVersion {
	label: string;
	version: string;
	branch: string;
	slug: string | null;
	badge: string | null;
}

export const docsVersions: DocsVersion[] = [
	{
		label: "v0.2.0 (Latest)",
		version: "0.2.0",
		branch: "main",
		slug: null,
		badge: null,
	},
];

export const latestVersion = docsVersions[0]!;

export function getVersionBySlug(slug: string): DocsVersion | undefined {
	return docsVersions.find((v) => v.slug === slug);
}

export function versionedDocsHref(path: string, version: DocsVersion): string {
	if (!version.slug) return path;
	const stripped = path.replace(/^\/docs/, "");
	return `/docs/${version.slug}${stripped}`;
}

export function getVersionFromPathname(pathname: string): DocsVersion {
	for (const v of docsVersions) {
		if (!v.slug) continue;
		const prefix = `/docs/${v.slug}`;
		if (pathname === prefix || pathname.startsWith(`${prefix}/`)) {
			return v;
		}
	}
	return latestVersion;
}

export function stripVersionPrefix(
	pathname: string,
	version: DocsVersion,
): string {
	if (!version.slug) return pathname;
	const prefix = `/docs/${version.slug}`;
	if (pathname === prefix || pathname === `${prefix}/`) return "/docs";
	if (pathname.startsWith(`${prefix}/`)) {
		return `/docs${pathname.slice(prefix.length)}`;
	}
	return pathname;
}

export function scopeDocsHref(
	href: string | undefined,
	version: DocsVersion,
): string | undefined {
	if (!href || !version.slug) return href;
	if (!/^\/docs(?:\/|$|[?#])/.test(href)) return href;
	const pathOnly = href.split(/[?#]/, 1)[0];
	const segment = pathOnly.split("/")[2];
	if (segment && docsVersions.some((v) => v.slug === segment)) return href;
	return versionedDocsHref(href, version);
}

export function resolveVersionFromSlug(slug: string[]): {
	version: DocsVersion;
	relSlug: string[];
} {
	const [head, ...rest] = slug;
	const match = head ? getVersionBySlug(head) : undefined;
	if (match) return { version: match, relSlug: rest };

	return { version: latestVersion, relSlug: slug };
}
