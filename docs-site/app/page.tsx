import { HeroReadMe } from "@/components/landing/hero-readme";
import { HeroTitle } from "@/components/landing/hero-title";
import { HalftoneBackground } from "@/components/landing/halftone-bg";
import { SignatureMark } from "@/components/landing/signature-mark";
import { getCommunityStats, getContributors } from "@/lib/community-stats";

export default async function HomePage() {
	const contributors = getContributors();
	const communityStats = await getCommunityStats();

	return (
		<div id="hero" className="relative pt-[45px] lg:pt-0">
			<div className="relative text-foreground" data-v="1">
				<div className="flex flex-col lg:flex-row">
					{/* Left side — Hero title */}
					<div className="relative w-full lg:w-[40%] lg:h-dvh border-b lg:border-b-0 lg:border-r border-foreground/[0.06] px-5 sm:px-6 lg:px-7 lg:sticky lg:top-0 z-10 bg-background lg:overflow-clip">
						<HalftoneBackground />
						<HeroTitle />
						<div className="hidden lg:block absolute left-5 right-5 lg:left-7 lg:right-3 bottom-4 z-[3]">
							<SignatureMark />
						</div>
					</div>

					{/* Right side — Sign in */}
					<div className="relative z-0 w-full lg:w-[60%] overflow-x-hidden">
						<div className="flex items-start lg:items-center justify-center">
							<HeroReadMe
								contributors={contributors}
								stats={{
									crateRecentDownloads: communityStats.crateRecentDownloads,
									crateDownloadHistory: communityStats.crateDownloadHistory,
									githubStars: communityStats.githubStars,
									contributors: communityStats.contributors,
								}}
							/>
						</div>
					</div>
				</div>
			</div>
		</div>
	);
}
