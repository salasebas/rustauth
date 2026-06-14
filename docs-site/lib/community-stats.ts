import { unstable_cache } from "next/cache";
import staticContributors from "./contributors-data.json";
import { isBotContributor } from "./contributor-filters";

const GITHUB_REPO = "salasebas/rustauth";
const CRATE_NAME = "rustauth";
const CRATES_USER_AGENT = "rustauth-docs-site (https://github.com/salasebas/rustauth)";

export interface CommunityStats {
	crateRecentDownloads: number;
	crateDownloadHistory: number[];
	githubStars: number;
	contributors: number;
	discordMembers: number;
}

/** @deprecated Use crateRecentDownloads — kept for gradual UI migration */
export type LegacyCommunityStats = CommunityStats & {
	npmDownloads: number;
	npmWeeklyHistory: number[];
};

export interface ContributorInfo {
	login: string;
	avatar_url: string;
	html_url: string;
}

export function getContributors(): ContributorInfo[] {
	return (staticContributors as ContributorInfo[]).filter(
		(c) => !isBotContributor(c.login),
	);
}

const staticContributorsCount = staticContributors.length;

const cratesHeaders = {
	Accept: "application/json",
	"User-Agent": CRATES_USER_AGENT,
};

async function fetchCrateRecentDownloads(): Promise<number> {
	try {
		const response = await fetch(
			`https://crates.io/api/v1/crates/${CRATE_NAME}`,
			{ next: { revalidate: 3600 }, headers: cratesHeaders },
		);

		if (!response.ok) {
			console.error("Failed to fetch crates.io stats:", response.status);
			return 0;
		}

		const data = await response.json();
		return data.crate?.recent_downloads ?? data.crate?.downloads ?? 0;
	} catch (error) {
		console.error("Error fetching crates.io stats:", error);
		return 0;
	}
}

async function fetchCrateDownloadHistory(): Promise<number[]> {
	try {
		const response = await fetch(
			`https://crates.io/api/v1/crates/${CRATE_NAME}/downloads`,
			{ next: { revalidate: 3600 }, headers: cratesHeaders },
		);
		if (!response.ok) return [];

		const data = await response.json();
		const byDate = new Map<string, number>();
		for (const row of data.version_downloads ?? []) {
			byDate.set(row.date, (byDate.get(row.date) ?? 0) + row.downloads);
		}

		const sorted = [...byDate.entries()].sort(([a], [b]) => a.localeCompare(b));
		const daily = sorted.map(([, count]) => count);

		// Aggregate into weekly buckets for charts (if used later).
		const weeks: number[] = [];
		for (let i = 0; i < daily.length; i += 7) {
			weeks.push(daily.slice(i, i + 7).reduce((sum, n) => sum + n, 0));
		}
		return weeks;
	} catch {
		return [];
	}
}

const githubHeaders = {
	Accept: "application/vnd.github.v3+json",
	...(process.env.GITHUB_TOKEN && {
		Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
	}),
};

async function fetchGitHubStats(): Promise<{
	stars: number;
	contributors: number;
}> {
	try {
		const [repoResponse, contributorsResponse] = await Promise.all([
			fetch(`https://api.github.com/repos/${GITHUB_REPO}`, {
				next: { revalidate: 3600 },
				headers: githubHeaders,
			}),
			fetch(
				`https://api.github.com/repos/${GITHUB_REPO}/contributors?per_page=1&anon=true`,
				{
					next: { revalidate: 3600 },
					headers: githubHeaders,
				},
			),
		]);

		let stars = 0;
		if (repoResponse.ok) {
			const data = await repoResponse.json();
			stars = data.stargazers_count ?? 0;
		} else {
			console.error("Failed to fetch GitHub repo stats:", repoResponse.status);
		}

		let contributorsCount = staticContributorsCount;
		if (contributorsResponse.ok) {
			const linkHeader = contributorsResponse.headers.get("Link");
			if (linkHeader) {
				const match = linkHeader.match(/page=(\d+)>; rel="last"/);
				if (match) {
					contributorsCount = parseInt(match[1], 10);
				}
			} else {
				contributorsCount = staticContributorsCount;
			}
		} else {
			console.error(
				"Failed to fetch contributors:",
				contributorsResponse.status,
			);
		}

		return { stars, contributors: contributorsCount };
	} catch (error) {
		console.error("Error fetching GitHub stats:", error);
		return { stars: 0, contributors: staticContributorsCount };
	}
}

export const getCommunityStats = unstable_cache(
	async (): Promise<CommunityStats> => {
		const [crateRecentDownloads, crateDownloadHistory, githubStats] =
			await Promise.all([
				fetchCrateRecentDownloads(),
				fetchCrateDownloadHistory(),
				fetchGitHubStats(),
			]);

		return {
			crateRecentDownloads,
			crateDownloadHistory,
			githubStars: githubStats.stars,
			contributors: githubStats.contributors,
			discordMembers: 0,
		};
	},
	["community-stats", GITHUB_REPO, CRATE_NAME],
	{
		revalidate: 3600,
		tags: ["community-stats"],
	},
);
