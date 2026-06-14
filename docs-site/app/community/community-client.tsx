"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { useEffect, useState } from "react";
import Footer from "@/components/landing/footer";
import { HalftoneBackground } from "@/components/landing/halftone-bg";
import type { CommunityStats } from "@/lib/community-stats";

// Icons - using text-foreground for theme support
const GitHubIcon = ({ className }: { className?: string }) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		width="20"
		height="20"
		viewBox="0 0 256 250"
		className={className}
	>
		<path
			fill="currentColor"
			d="M128.001 0C57.317 0 0 57.307 0 128.001c0 56.554 36.676 104.535 87.535 121.46c6.397 1.185 8.746-2.777 8.746-6.158c0-3.052-.12-13.135-.174-23.83c-35.61 7.742-43.124-15.103-43.124-15.103c-5.823-14.795-14.213-18.73-14.213-18.73c-11.613-7.944.876-7.78.876-7.78c12.853.902 19.621 13.19 19.621 13.19c11.417 19.568 29.945 13.911 37.249 10.64c1.149-8.272 4.466-13.92 8.127-17.116c-28.431-3.236-58.318-14.212-58.318-63.258c0-13.975 5-25.394 13.188-34.358c-1.329-3.224-5.71-16.242 1.24-33.874c0 0 10.749-3.44 35.21 13.121c10.21-2.836 21.16-4.258 32.038-4.307c10.878.049 21.837 1.47 32.066 4.307c24.431-16.56 35.165-13.12 35.165-13.12c6.967 17.63 2.584 30.65 1.255 33.873c8.207 8.964 13.173 20.383 13.173 34.358c0 49.163-29.944 59.988-58.447 63.157c4.591 3.972 8.682 11.762 8.682 23.704c0 17.126-.148 30.91-.148 35.126c0 3.407 2.304 7.398 8.792 6.14C219.37 232.5 256 184.537 256 128.002C256 57.307 198.691 0 128.001 0"
		/>
	</svg>
);

const StarIcon = ({ className }: { className?: string }) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="currentColor"
		className={className}
	>
		<path d="M12 2l3.09 6.26L22 9.27l-5 4.87l1.18 6.88L12 17.77l-6.18 3.25L7 14.14L2 9.27l6.91-1.01L12 2z" />
	</svg>
);

const DownloadIcon = ({ className }: { className?: string }) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		strokeLinecap="round"
		strokeLinejoin="round"
		className={className}
	>
		<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
		<polyline points="7 10 12 15 17 10" />
		<line x1="12" y1="15" x2="12" y2="3" />
	</svg>
);

const UsersIcon = ({ className }: { className?: string }) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		width="16"
		height="16"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		strokeWidth="2"
		strokeLinecap="round"
		strokeLinejoin="round"
		className={className}
	>
		<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
		<circle cx="9" cy="7" r="4" />
		<path d="M22 21v-2a4 4 0 0 0-3-3.87" />
		<path d="M16 3.13a4 4 0 0 1 0 7.75" />
	</svg>
);

// Format large numbers
function formatNumber(num: number): string {
	if (num >= 1000000) {
		return (num / 1000000).toFixed(1).replace(/\.0$/, "") + "M";
	}
	if (num >= 1000) {
		return (num / 1000).toFixed(1).replace(/\.0$/, "") + "K";
	}
	return num.toString();
}

// Animated counter component
function AnimatedCounter({
	value,
	duration = 2000,
}: {
	value: number;
	duration?: number;
}) {
	const [count, setCount] = useState(0);

	useEffect(() => {
		let startTime: number;
		let animationFrame: number;

		const animate = (timestamp: number) => {
			if (!startTime) startTime = timestamp;
			const progress = Math.min((timestamp - startTime) / duration, 1);

			// Easing function for smooth animation
			const easeOut = 1 - Math.pow(1 - progress, 3);
			setCount(Math.floor(easeOut * value));

			if (progress < 1) {
				animationFrame = requestAnimationFrame(animate);
			}
		};

		animationFrame = requestAnimationFrame(animate);
		return () => cancelAnimationFrame(animationFrame);
	}, [value, duration]);

	return <span>{formatNumber(count)}</span>;
}

// Community platforms
const platforms = [
	{
		name: "GitHub",
		icon: GitHubIcon,
		href: "https://github.com/salasebas/rustauth",
		cta: "View on GitHub",
		members: "Open Source",
		label: "repository",
	},
];

function CommunityHero({ stats }: { stats: CommunityStats }) {
	return (
		<motion.div
			initial={false}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.5, ease: "easeOut" }}
			className="relative w-full pt-6 md:pt-10 pb-6 lg:pb-0 flex flex-col justify-center lg:h-full"
		>
			<div className="space-y-6">
				<div className="space-y-2">
					<div className="flex items-center gap-1.5">
						<UsersIcon className="w-4 h-4 text-foreground/60" />
						<span className="text-sm text-foreground/60">Community</span>
					</div>
					<h1 className="text-2xl md:text-3xl xl:text-4xl text-neutral-800 dark:text-neutral-200 tracking-tight leading-tight">
						Join the community,
						<br />
						<span className="text-foreground/50">build together.</span>
					</h1>
					<p className="text-sm text-foreground/70 dark:text-foreground/50 leading-relaxed max-w-[260px]">
						Connect with developers building with RustAuth.
					</p>
				</div>

				{/* Quick stats summary */}
				<div className="flex items-stretch gap-0 border border-foreground/[0.08]">
					<div className="flex-1 px-3 py-2.5 text-center border-r border-foreground/[0.08]">
						<p className="text-[9px] font-mono uppercase tracking-widest text-foreground/50 dark:text-foreground/45 mb-1">
							Crates
						</p>
						<p className="text-sm font-light text-foreground/80 tabular-nums">
							{formatNumber(stats.crateRecentDownloads)}
							<span className="text-[9px] text-foreground/50 font-mono">
								/week
							</span>
						</p>
					</div>
					<div className="flex-1 px-3 py-2.5 text-center bg-foreground/[0.03]">
						<p className="text-[9px] font-mono uppercase tracking-widest text-foreground/50 dark:text-foreground/45 mb-1">
							Stars
						</p>
						<p className="text-sm font-light text-foreground/80 tabular-nums">
							{formatNumber(stats.githubStars)}
						</p>
					</div>
				</div>

				{/* Principles list */}
				<div className="border-t border-foreground/10 pt-4 space-y-0">
					{[
						{ label: "Framework", value: "Open source" },
						{ label: "Contributors", value: `${stats.contributors}+` },
						{ label: "License", value: "MIT" },
					].map((item, i) => (
						<motion.div
							key={item.label}
							initial={false}
							animate={{ opacity: 1, x: 0 }}
							transition={{
								duration: 0.25,
								delay: 0.3 + i * 0.06,
								ease: "easeOut",
							}}
							className="flex items-baseline justify-between py-1.5 border-b border-dashed border-foreground/[0.06] last:border-0"
						>
							<span className="text-xs text-foreground/70 dark:text-foreground/50 uppercase tracking-wider">
								{item.label}
							</span>
							<span className="text-xs text-foreground/85 dark:text-foreground/75 font-mono">
								{item.value}
							</span>
						</motion.div>
					))}
				</div>
			</div>
		</motion.div>
	);
}

function StatCard({
	icon: Icon,
	label,
	value,
	subtext,
	index,
}: {
	icon: React.ComponentType<{ className?: string }>;
	label: string;
	value: number;
	subtext: string;
	index: number;
}) {
	return (
		<motion.div
			initial={false}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.3, delay: 0.1 + index * 0.06, ease: "easeOut" }}
			className="relative border border-dashed border-foreground/[0.08] hover:border-foreground/[0.14] transition-all duration-300 group"
		>
			<div className="p-5">
				<div className="flex items-center gap-2 mb-3">
					<Icon className="w-4 h-4 text-foreground/40" />
					<span className="text-[10px] font-mono uppercase tracking-widest text-foreground/40">
						{label}
					</span>
				</div>
				<div>
					<span className="text-4xl font-light text-foreground tabular-nums">
						<AnimatedCounter value={value} />
					</span>
					<p className="text-[10px] text-foreground/40 font-mono mt-1">
						{subtext}
					</p>
				</div>
			</div>
		</motion.div>
	);
}

function PlatformCard({
	platform,
	index,
}: {
	platform: (typeof platforms)[number];
	index: number;
}) {
	const Icon = platform.icon;

	return (
		<motion.div
			initial={false}
			animate={{ opacity: 1, y: 0 }}
			transition={{ duration: 0.3, delay: 0.2 + index * 0.06, ease: "easeOut" }}
			className="relative border border-dashed border-foreground/[0.08] hover:border-foreground/[0.14] transition-all duration-300 group"
		>
			<div className="flex flex-col h-full p-5">
				{/* Header */}
				<div className="flex flex-col items-center gap-2 mb-3">
					<div className="bg-muted/20 border border-foreground/[0.06] p-2 rounded-full">
						<Icon className="size-8 text-foreground/50" />
					</div>
					<h3 className="text-base font-mono uppercase tracking-widest text-foreground/40">
						{platform.name}
					</h3>
				</div>

				{/* Stats */}
				<div className="border-t border-dashed border-foreground/[0.06] pt-3 mb-4">
					<div className="flex items-baseline justify-between">
						<span className="text-[9px] text-foreground/30 uppercase tracking-widest font-mono">
							{platform.label}
						</span>
						<span className="text-xs text-foreground/60 font-mono">
							{platform.members}
						</span>
					</div>
				</div>

				{/* CTA */}
				<Link
					href={platform.href}
					target="_blank"
					rel="noreferrer"
					className="block"
				>
					<div className="w-full py-2.5 text-center border flex items-center justify-center border-dashed border-foreground/20 text-foreground/70 hover:text-foreground/90 hover:border-foreground/30 hover:bg-foreground/5 transition-all cursor-pointer">
						<span className="font-mono text-[10px] uppercase tracking-widest">
							{platform.cta}
						</span>
					</div>
				</Link>
			</div>
		</motion.div>
	);
}

export function CommunityPageClient({ stats }: { stats: CommunityStats }) {
	return (
		<div className="relative min-h-dvh pt-14 lg:pt-0">
			<div className="relative text-foreground">
				<div className="flex flex-col lg:flex-row">
					{/* Left side — Community hero */}
					<div className="hidden lg:block relative w-full shrink-0 lg:w-[30%] lg:h-dvh border-b lg:border-b-0 lg:border-r border-foreground/[0.06] overflow-clip px-5 sm:px-6 lg:px-10 lg:sticky lg:top-0 bg-background">
						<div className="hidden lg:block">
							<HalftoneBackground />
						</div>
						<CommunityHero stats={stats} />
					</div>

					{/* Right side — Stats & platforms */}
					<div className="relative w-full lg:w-[70%] overflow-x-hidden no-scrollbar">
						<div className="px-5 lg:p-8 lg:pt-20 space-y-8">
							{/* Mobile header */}
							<div className="lg:hidden relative border-b border-foreground/[0.06] overflow-hidden -mx-5 sm:-mx-6 px-5 sm:px-6 mb-5 bg-background">
								<HalftoneBackground />
								<div className="relative space-y-2 py-16">
									<div className="flex items-center gap-1.5">
										<UsersIcon className="w-4 h-4 text-foreground/60" />
										<span className="text-sm text-foreground/60">
											Community
										</span>
									</div>
									<h1 className="text-2xl md:text-3xl xl:text-4xl text-neutral-800 dark:text-neutral-200 tracking-tight leading-tight">
										Join the community,
										<br />
										<span className="text-foreground/50">build together.</span>
									</h1>
									<p className="text-sm text-foreground/70 dark:text-foreground/50 leading-relaxed">
										Connect with developers building with RustAuth.
									</p>
								</div>
							</div>

							<h2 className="flex items-center gap-3 text-sm sm:text-[15px] font-mono text-neutral-900 dark:text-neutral-100 mb-4 sm:mb-5">
								COMMUNITY
								<span className="flex-1 h-px bg-foreground/15" />
							</h2>

							{/* Section: Statistics */}
							<motion.div
								initial={false}
								animate={{ opacity: 1, y: 0 }}
								transition={{ duration: 0.3, delay: 0.05 }}
							>
								<p className="text-[10px] uppercase tracking-widest text-foreground/60 font-mono mb-5">
									# In Numbers
								</p>

								<div className="grid grid-cols-2 gap-0">
									<StatCard
										icon={DownloadIcon}
										label="Crates.io Downloads"
										value={stats.crateRecentDownloads}
										subtext="/ 90d"
										index={0}
									/>
									<StatCard
										icon={StarIcon}
										label="GitHub Stars"
										value={stats.githubStars}
										subtext="stars"
										index={1}
									/>
									<StatCard
										icon={UsersIcon}
										label="Contributors"
										value={stats.contributors}
										subtext="people"
										index={2}
									/>
								</div>
							</motion.div>

							{/* Section: Platforms */}
							<motion.div
								initial={false}
								animate={{ opacity: 1 }}
								transition={{ duration: 0.4, delay: 0.25 }}
							>
								<p className="text-[10px] uppercase tracking-widest text-foreground/60 font-mono mb-5">
									# Join Us On
								</p>

								<div className="grid grid-cols-1 sm:grid-cols-2 gap-0">
									{platforms.map((platform, index) => (
										<PlatformCard
											key={platform.name}
											platform={platform}
											index={index}
										/>
									))}
								</div>
							</motion.div>
						</div>
						<Footer />
					</div>
				</div>
			</div>
		</div>
	);
}
