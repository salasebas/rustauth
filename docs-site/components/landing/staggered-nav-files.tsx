"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
	ChevronDownIcon,
	History,
	PencilLine,
	Scale,
	Search,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { ThemeToggle } from "@/components/theme-toggle";
import { getVersionFromPathname, versionedDocsHref } from "@/lib/docs-versions";
import { cn } from "@/lib/utils";
import DarkPng from "../../public/branding/rustauth-logo-dark.png";
import WhitePng from "../../public/branding/rustauth-logo-light.png";
import { logoAssets as rustauthLogoAssets } from "@/lib/branding/rustauth-mark";
import { Logo } from "../icons/logo";
import { contents } from "../sidebar-content";
import {
	Accordion,
	AccordionContent,
	AccordionItem,
	AccordionTrigger,
} from "../ui/accordion";
import { Badge } from "../ui/badge";
import LogoContextMenu from "./logo-context-menu";

interface NavFileItem {
	name: string;
	href: string;
	path?: string;
	external?: boolean;
}

const navFiles: NavFileItem[] = [
	{ name: "readme", href: "/" },
	{ name: "docs", href: "/docs" },
];

interface ProductItem {
	title: string;
	tagline: string;
	description: string;
	href: string;
	Icon: React.ComponentType<{ className?: string }>;
	Pattern?: React.FC<{ className?: string }>;
	patternClassName?: string;
	BgPattern?: React.FC<{ className?: string }>;
	bgPatternClassName?: string;
}

const CommunityIcon: React.FC<{ className?: string }> = ({ className }) => (
	<svg
		xmlns="http://www.w3.org/2000/svg"
		width="1em"
		height="1em"
		viewBox="0 0 20 20"
		className={className}
		aria-hidden="true"
	>
		<path
			fill="currentColor"
			d="M10 3a2 2 0 1 0 0 4a2 2 0 0 0 0-4M7 5a3 3 0 1 1 6 0a3 3 0 0 1-6 0M5.053 9.996q-.051.244-.051.504v.545l-2.631.705a.5.5 0 0 0-.354.612l.647 2.415A3 3 0 0 0 5.98 16.97c.23.31.495.594.789.843l-.171.05a4 4 0 0 1-4.9-2.828l-.647-2.415a1.5 1.5 0 0 1 1.061-1.837zm9.949 1.049V10.5q-.001-.26-.05-.504l2.94.788a1.5 1.5 0 0 1 1.06 1.837l-.647 2.415a4 4 0 0 1-5.07 2.778q.443-.376.789-.843a3 3 0 0 0 3.315-2.194l.648-2.415a.5.5 0 0 0-.354-.612zM15 6.5a1.5 1.5 0 1 1 3 0a1.5 1.5 0 0 1-3 0M16.5 4a2.5 2.5 0 1 0 0 5a2.5 2.5 0 0 0 0-5m-13 1a1.5 1.5 0 1 0 0 3a1.5 1.5 0 0 0 0-3M1 6.5a2.5 2.5 0 1 1 5 0a2.5 2.5 0 0 1-5 0M7.5 9A1.5 1.5 0 0 0 6 10.5V14a4 4 0 0 0 8 0v-3.5A1.5 1.5 0 0 0 12.5 9zM7 10.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 .5.5V14a3 3 0 1 1-6 0z"
		/>
	</svg>
);

const TimelinePattern: React.FC<{ className?: string }> = ({ className }) => (
	<svg
		width="56"
		height="56"
		viewBox="0 0 56 56"
		fill="none"
		shapeRendering="geometricPrecision"
		className={className}
		aria-hidden="true"
	>
		<line x1="6" y1="6" x2="6" y2="50" stroke="currentColor" strokeWidth="1" />
		<circle cx="6" cy="10" r="1.75" fill="currentColor" />
		<circle cx="6" cy="28" r="1.75" fill="currentColor" />
		<circle cx="6" cy="46" r="1.75" fill="currentColor" />
		<line
			x1="14"
			y1="10"
			x2="50"
			y2="10"
			stroke="currentColor"
			strokeWidth="1"
		/>
		<line
			x1="14"
			y1="28"
			x2="40"
			y2="28"
			stroke="currentColor"
			strokeWidth="1"
		/>
		<line
			x1="14"
			y1="46"
			x2="32"
			y2="46"
			stroke="currentColor"
			strokeWidth="1"
		/>
	</svg>
);

const ScribblePattern: React.FC<{ className?: string }> = ({ className }) => (
	<svg
		width="64"
		height="34"
		viewBox="0 0 64 34"
		fill="none"
		className={className}
		aria-hidden="true"
	>
		<path
			d="M2 14 C 8 2, 14 2, 18 14 S 28 26, 34 14 S 48 2, 54 14 S 62 20, 62 20"
			stroke="currentColor"
			strokeWidth="1.4"
			strokeLinecap="round"
			fill="none"
		/>
		<path
			d="M4 26 C 10 22, 20 28, 28 24 S 44 28, 52 24"
			stroke="currentColor"
			strokeWidth="1.1"
			strokeLinecap="round"
			fill="none"
			opacity="0.7"
		/>
	</svg>
);

const _HorizontalLinesPattern: React.FC<{ className?: string }> = ({
	className,
}) => {
	const rows = 40;
	const width = 100;
	const height = rows * 3;
	const lines: React.ReactElement[] = [];
	for (let i = 0; i < rows; i++) {
		const y = i * 3 + 1;
		lines.push(
			<line
				key={i}
				x1={0}
				y1={y}
				x2={width}
				y2={y}
				stroke="currentColor"
				strokeWidth="0.75"
			/>,
		);
	}
	return (
		<svg
			width="100%"
			height="100%"
			viewBox={`0 0 ${width} ${height}`}
			preserveAspectRatio="none"
			className={className}
			aria-hidden="true"
		>
			{lines}
		</svg>
	);
};

const featuredResources: ProductItem[] = [
	{
		title: "Blog",
		tagline: "Writing",
		description: "Engineering, product, and updates",
		href: "/blog",
		Icon: PencilLine,
		Pattern: ScribblePattern,
		patternClassName:
			"absolute right-3 top-3 text-foreground/30 group-hover/p:text-foreground/60 transition-colors duration-200 pointer-events-none",
	},
	{
		title: "Changelog",
		tagline: "Shipped",
		description: "Latest releases and improvements",
		href: "/changelog",
		Icon: History,
		Pattern: TimelinePattern,
		patternClassName:
			"absolute right-3 top-3 text-foreground/30 group-hover/p:text-foreground/60 transition-colors duration-200 pointer-events-none",
	},
];

interface LinkResource {
	title: string;
	href: string;
	Icon: React.ComponentType<{ className?: string }>;
}

const linkResources: LinkResource[] = [
	{ title: "Community", href: "/community", Icon: CommunityIcon },
];

const resourceFiles: NavFileItem[] = [
	...featuredResources.map((r) => ({
		name: r.title.toLowerCase(),
		href: r.href,
	})),
	...linkResources.map((r) => ({
		name: r.title.toLowerCase(),
		href: r.href,
	})),
];

interface MobileMenuSection {
	name: string;
	href?: string;
	children?: NavFileItem[];
}

const mobileMenuSections: MobileMenuSection[] = [
	{ name: "resources", children: resourceFiles },
];

const logoAssets = {
	...rustauthLogoAssets,
	darkPng: DarkPng,
	whitePng: WhitePng,
};

export function StaggeredNavFiles() {
	const pathname = usePathname() || "/";
	const currentVersion = getVersionFromPathname(pathname);
	const prefixHref = (href: string) => versionedDocsHref(href, currentVersion);
	const [resourcesOpen, setResourcesOpen] = useState(false);
	const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
	const [mobileView, setMobileView] = useState<"docs" | "nav">("docs");
	const [mobileDocSection, setMobileDocSection] = useState(-1);
	const resourcesTimeout = useRef<NodeJS.Timeout>(undefined);

	useEffect(() => {
		document.body.style.overflow = mobileMenuOpen ? "hidden" : "";
		return () => {
			document.body.style.overflow = "";
		};
	}, [mobileMenuOpen]);

	useEffect(() => {
		const mql = window.matchMedia("(min-width: 1024px)");
		const handler = () => {
			if (mql.matches) {
				setMobileMenuOpen(false);
			}
		};
		mql.addEventListener("change", handler);
		return () => mql.removeEventListener("change", handler);
	}, []);

	const openResources = () => {
		clearTimeout(resourcesTimeout.current);
		setResourcesOpen(true);
	};
	const closeResources = () => {
		resourcesTimeout.current = setTimeout(() => setResourcesOpen(false), 150);
	};
	const isActive = useCallback((href: string) => pathname === href, [pathname]);
	const isActivePrefix = useCallback(
		(href: string) => pathname === href || pathname.startsWith(`${href}/`),
		[pathname],
	);
	const isDocs = pathname.startsWith("/docs");
	const isResourcePage = resourceFiles.some((r) => {
		const matchPath = r.path || r.href;
		return pathname === matchPath || pathname.startsWith(`${matchPath}/`);
	});
	const isKnownPage = isActive("/") || isDocs || isResourcePage;
	const isNarrowLeft = isDocs;
	const leftPaneWidthClass = isNarrowLeft
		? "w-[22vw] max-w-[300px]"
		: isResourcePage
			? "w-[30%]"
			: "w-[40%]";
	const navBottomBorderClass = isNarrowLeft ? "border-foreground/5" : "";
	const tabDividerClass = isNarrowLeft
		? "border-foreground/4"
		: "border-foreground/[0.06]";
	const activeTabBorderClass = isNarrowLeft
		? "border-b-foreground/50"
		: "border-b-foreground/60";
	const dropdownBorderClass = isNarrowLeft
		? "border-foreground/6"
		: "border-foreground/[0.08]";
	const _router = useRouter();
	return (
		<>
			<div className="fixed top-0 left-0 right-0 z-[99] flex items-start pointer-events-none">
				{/* Left — Logo */}
				<motion.div
					initial={{ x: -20, opacity: 0 }}
					animate={{ x: 0, opacity: 1 }}
					transition={{ duration: 0.28, ease: "easeOut" }}
					className={`${leftPaneWidthClass} hidden ${isKnownPage ? "lg:flex" : "lg:hidden"} h-(--landing-topbar-height) items-stretch shrink-0 pointer-events-auto transition-[width] duration-300 ease-out`}
				>
					<Link
						href="/"
						className="flex h-full items-center gap-1 px-4 py-3 transition-colors duration-150"
					>
						<div className="flex flex-col gap-2 w-full">
							<LogoContextMenu
								logo={
									<div className="flex items-center gap-1">
										<Logo className="h-3 w-auto shrink-0" />
										<p className="select-none font-mono text-base uppercase leading-none">
											RUSTAUTH.
										</p>
									</div>
								}
								logoAssets={logoAssets}
							/>
						</div>
					</Link>
				</motion.div>

				{/* Mobile — Logo + hamburger */}
				<motion.div
					initial={{ opacity: 0 }}
					animate={{ opacity: 1 }}
					transition={{ duration: 0.28, ease: "easeOut" }}
					className="lg:hidden flex items-center justify-between w-full h-(--landing-topbar-height) pointer-events-auto bg-background border-b border-foreground/[0.06]"
				>
					<Link
						href="/"
						className="flex h-full items-center gap-1 px-4 transition-colors duration-150"
					>
						<Logo className="h-3 w-auto shrink-0" />
						<p className="select-none font-mono text-sm uppercase leading-none">
							RUSTAUTH.
						</p>
					</Link>
					<div className="flex items-center gap-1 pr-2">
						{isDocs && (
							<button
								type="button"
								onClick={() => {
									window.dispatchEvent(
										new KeyboardEvent("keydown", {
											key: "k",
											metaKey: true,
											bubbles: true,
										}),
									);
								}}
								className="flex items-center justify-center size-8 text-foreground/50 hover:text-foreground/80 transition-colors"
								aria-label="Search"
							>
								<Search className="size-4" />
							</button>
						)}
						<div className="flex items-center justify-center size-8 text-foreground/50 [&_button]:text-foreground/50 [&_button:hover]:text-foreground/80">
							<ThemeToggle />
						</div>
						<button
							type="button"
							onClick={() => {
								const opening = !mobileMenuOpen;
								setMobileMenuOpen(opening);
								if (opening) {
									setMobileView(isDocs ? "docs" : "nav");
									if (isDocs) {
										const idx = contents.findIndex((s) => {
											const prefix = s.expandSectionForPathPrefix;
											if (
												prefix &&
												(pathname === prefix ||
													pathname.startsWith(`${prefix}/`))
											) {
												return true;
											}
											return s.list.some(
												(l) =>
													l.href === pathname ||
													(l.subpages?.length &&
														pathname.startsWith(`${l.href}/`)),
											);
										});
										setMobileDocSection(idx === -1 ? 0 : idx);
									}
								}
							}}
							className="flex items-center justify-center size-8 text-foreground/75 dark:text-foreground/60 hover:text-foreground/85 transition-colors"
						>
							{mobileMenuOpen ? (
								<svg
									xmlns="http://www.w3.org/2000/svg"
									width="18"
									height="18"
									viewBox="0 0 24 24"
								>
									<path
										fill="currentColor"
										d="M19 6.41L17.59 5L12 10.59L6.41 5L5 6.41L10.59 12L5 17.59L6.41 19L12 13.41L17.59 19L19 17.59L13.41 12z"
									/>
								</svg>
							) : (
								<svg
									xmlns="http://www.w3.org/2000/svg"
									width="18"
									height="18"
									viewBox="0 0 24 24"
								>
									<path
										fill="currentColor"
										d="M3 18h18v-2H3zm0-5h18v-2H3zm0-7v2h18V6z"
									/>
								</svg>
							)}
						</button>
					</div>
				</motion.div>

				{/* Right — Nav tabs (desktop) */}
				<motion.div
					initial={{ y: -10, opacity: 0 }}
					animate={{ y: 0, opacity: 1 }}
					transition={{ duration: 0.28, delay: 0.04, ease: "easeOut" }}
					className={`flex-1 hidden lg:flex h-[calc(var(--landing-topbar-height)+1px)] items-stretch border-b bg-background pointer-events-auto min-w-0 ${navBottomBorderClass}`}
				>
					{/* Inline logo when left pane is hidden */}
					{!isKnownPage && (
						<Link
							href="/"
							className={`flex h-full items-center gap-1 shrink-0 px-4 lg:px-7 py-3 border-r ${tabDividerClass} transition-colors duration-150`}
						>
							<LogoContextMenu
								logo={
									<div className="flex items-center gap-1">
										<Logo className="h-3 w-auto shrink-0" />
										<p className="select-none font-mono text-base uppercase leading-none">
											RUSTAUTH.
										</p>
									</div>
								}
								logoAssets={logoAssets}
							/>
						</Link>
					)}
					{/* File tabs */}
					{navFiles.map((item, index) => {
						const active =
							isActive(item.path || item.href) ||
							(item.href === "/docs" && isDocs);
						return (
							<motion.div
								key={item.name}
								initial={{ opacity: 0, y: -4 }}
								animate={{ opacity: 1, y: 0 }}
								transition={{
									duration: 0.2,
									delay: 0.05 + index * 0.03,
									ease: "easeOut",
								}}
								className="flex-1"
							>
								<Link
									href={item.href}
									target={item.external ? "_blank" : undefined}
									rel={item.external ? "noreferrer" : undefined}
									className={`group/tab relative flex items-center justify-center gap-1.5 px-2 xl:px-4 py-3 h-full border-r ${tabDividerClass} transition-colors duration-150 ${
										active
											? `bg-background border-b-2 ${activeTabBorderClass}`
											: "bg-transparent hover:bg-foreground/[0.03]"
									}`}
								>
									<span
										className={`font-mono text-xs uppercase tracking-wider transition-colors duration-150 whitespace-nowrap ${
											active
												? "text-foreground"
												: "text-foreground/65 dark:text-foreground/50 group-hover/tab:text-foreground/75"
										}`}
									>
										{item.name}
									</span>
								</Link>
							</motion.div>
						);
					})}

					{/* Resources folder tab */}
					<motion.div
						initial={{ opacity: 0, y: -4 }}
						animate={{ opacity: 1, y: 0 }}
						transition={{ duration: 0.2, delay: 0.17, ease: "easeOut" }}
						className="relative flex-1"
						onMouseEnter={openResources}
						onMouseLeave={closeResources}
					>
						<div
							className={`group/tab flex items-center justify-center gap-1.5 px-2 xl:px-4 py-3 h-full cursor-pointer transition-colors duration-150 ${
								isResourcePage
									? `bg-background border-b-2 ${activeTabBorderClass}`
									: resourcesOpen
										? "bg-foreground/[0.04]"
										: "hover:bg-foreground/[0.03]"
							}`}
						>
							<span
								className={`font-mono text-xs uppercase tracking-wider transition-colors duration-150 whitespace-nowrap ${
									isResourcePage
										? "text-foreground"
										: resourcesOpen
											? "text-foreground/80"
											: "text-foreground/65 dark:text-foreground/50 group-hover/tab:text-foreground/75"
								}`}
							>
								resources
							</span>
							<svg
								className={`h-2 w-2 text-foreground/55 dark:text-foreground/40 transition-transform duration-200 ${
									resourcesOpen ? "rotate-180" : ""
								}`}
								viewBox="0 0 10 6"
								fill="none"
							>
								<path
									d="M1 1L5 5L9 1"
									stroke="currentColor"
									strokeWidth="1.2"
								/>
							</svg>
						</div>

						<AnimatePresence>
							{resourcesOpen && (
								<motion.div
									initial={{ opacity: 0, y: -4 }}
									animate={{ opacity: 1, y: 0 }}
									exit={{ opacity: 0, y: -4 }}
									transition={{ duration: 0.12, ease: "easeOut" }}
									className={`absolute top-full right-0 z-50 w-[480px] max-w-[calc(100vw-2rem)] border ${dropdownBorderClass} bg-background shadow-2xl shadow-black/20 dark:shadow-black/60`}
								>
									<div className="grid grid-cols-2 divide-x divide-foreground/[0.06]">
										{featuredResources.map((r) => (
											<Link
												key={r.title}
												href={r.href}
												onClick={() => setResourcesOpen(false)}
												className="group/p relative flex h-full flex-col gap-2.5 p-4 overflow-hidden hover:bg-foreground/[0.03] transition-colors"
											>
												{r.BgPattern && (
													<r.BgPattern className={r.bgPatternClassName ?? ""} />
												)}
												{r.Pattern && (
													<r.Pattern
														className={
															r.patternClassName ??
															"absolute right-0 top-0 text-foreground/[0.09] group-hover/p:text-foreground/25 transition-colors duration-200 pointer-events-none"
														}
													/>
												)}
												<div className="relative flex items-center">
													<span className="flex size-8 items-center justify-center border border-foreground/[0.1] text-foreground/70 group-hover/p:text-foreground group-hover/p:border-foreground/25 transition-colors bg-background">
														<r.Icon className="size-4" />
													</span>
												</div>
												<div className="relative flex flex-col gap-0.5">
													<span className="text-[13px] font-medium text-foreground/90 group-hover/p:text-foreground transition-colors">
														{r.title}
													</span>
													<span className="text-[11px] leading-relaxed text-foreground/55 dark:text-foreground/45">
														{r.description}
													</span>
												</div>
											</Link>
										))}
									</div>
									<div className="grid grid-cols-4 divide-x divide-foreground/[0.06] border-t border-foreground/[0.06]">
										{linkResources.map((r) => (
											<Link
												key={r.title}
												href={r.href}
												onClick={() => setResourcesOpen(false)}
												className="group/p relative flex items-center gap-2 px-3 py-3 hover:bg-foreground/[0.03] transition-colors"
											>
												<r.Icon className="size-3.5 text-foreground/55 group-hover/p:text-foreground/80 transition-colors" />
												<span className="text-[12px] font-medium text-foreground/75 group-hover/p:text-foreground transition-colors">
													{r.title}
												</span>
											</Link>
										))}
									</div>
									<div className="grid w-full grid-cols-2 items-center justify-items-center gap-y-0.5 border-t border-foreground/[0.06] px-2 py-2">
										<a
											href="https://github.com/salasebas/rustauth"
											target="_blank"
											rel="noreferrer"
											className="flex items-center justify-center p-1 text-foreground/55 dark:text-foreground/40 hover:text-foreground/75 transition-colors"
											aria-label="GitHub"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												width="14"
												height="14"
												viewBox="0 0 256 250"
											>
												<path
													fill="currentColor"
													d="M128.001 0C57.317 0 0 57.307 0 128.001c0 56.554 36.676 104.535 87.535 121.46c6.397 1.185 8.746-2.777 8.746-6.158c0-3.052-.12-13.135-.174-23.83c-35.61 7.742-43.124-15.103-43.124-15.103c-5.823-14.795-14.213-18.73-14.213-18.73c-11.613-7.944.876-7.78.876-7.78c12.853.902 19.621 13.19 19.621 13.19c11.417 19.568 29.945 13.911 37.249 10.64c1.149-8.272 4.466-13.92 8.127-17.116c-28.431-3.236-58.318-14.212-58.318-63.258c0-13.975 5-25.394 13.188-34.358c-1.329-3.224-5.71-16.242 1.24-33.874c0 0 10.749-3.44 35.21 13.121c10.21-2.836 21.16-4.258 32.038-4.307c10.878.049 21.837 1.47 32.066 4.307c24.431-16.56 35.165-13.12 35.165-13.12c6.967 17.63 2.584 30.65 1.255 33.873c8.207 8.964 13.173 20.383 13.173 34.358c0 49.163-29.944 59.988-58.447 63.157c4.591 3.972 8.682 11.762 8.682 23.704c0 17.126-.148 30.91-.148 35.126c0 3.407 2.304 7.398 8.792 6.14C219.37 232.5 256 184.537 256 128.002C256 57.307 198.691 0 128.001 0"
												/>
											</svg>
										</a>
										<a
											href="https://crates.io/crates/rustauth"
											target="_blank"
											rel="noreferrer"
											className="flex items-center justify-center p-1 hover:opacity-80 transition-opacity"
											aria-label="crates.io"
										>
											<picture>
												<source
													srcSet="/branding/cargo.avif"
													type="image/avif"
												/>
												<img
													src="/branding/cargo.png"
													alt=""
													width={14}
													height={14}
													className="size-3.5"
													aria-hidden="true"
												/>
											</picture>
										</a>
									</div>
								</motion.div>
							)}
						</AnimatePresence>
					</motion.div>
					{/* Get Started CTA — always visible */}
					<motion.div
						initial={{ opacity: 0 }}
						animate={{ opacity: 1 }}
						transition={{ duration: 0.2, delay: 0.2, ease: "easeOut" }}
						className="flex items-stretch shrink-0"
					>
						<a
							href="/docs/introduction"
							className="flex items-center cursor-pointer gap-1.5 px-5 py-3 bg-foreground text-background hover:opacity-90 transition-colors duration-150"
						>
							<span className="font-mono text-xs uppercase tracking-wider">
								get started
							</span>
							<svg
								className="h-2.5 w-2.5 opacity-50"
								viewBox="0 0 10 10"
								fill="none"
							>
								<path
									d="M1 9L9 1M9 1H3M9 1V7"
									stroke="currentColor"
									strokeWidth="1.2"
								/>
							</svg>
						</a>
					</motion.div>
				</motion.div>
			</div>

			{/* Mobile menu overlay */}
			<AnimatePresence>
				{mobileMenuOpen && (
					<motion.div
						initial={{ opacity: 0 }}
						animate={{ opacity: 1 }}
						exit={{ opacity: 0 }}
						transition={{ duration: 0.15 }}
						className="lg:hidden fixed inset-0 z-[98] w-full bg-background/95 backdrop-blur-sm pointer-events-auto"
					>
						<div className="flex h-full flex-col pt-(--landing-topbar-height)">
							<div className="flex-1 min-h-0 overflow-y-auto">
								{isDocs && mobileView === "docs" ? (
									<>
										{/* Subtle back to nav button */}
										<button
											type="button"
											onClick={() => setMobileView("nav")}
											className="flex items-center gap-2 w-full px-5 py-2.5 text-foreground/65 dark:text-foreground/45 hover:text-foreground/70 transition-colors border-b border-foreground/6"
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												width="12"
												height="12"
												viewBox="0 0 24 24"
											>
												<path
													fill="currentColor"
													d="M3 18h18v-2H3zm0-5h18v-2H3zm0-7v2h18V6z"
												/>
											</svg>
											<span className="font-mono text-[10px] uppercase tracking-wider">
												Menu
											</span>
										</button>

										{/* Doc sidebar sections */}

										<div className="flex flex-col">
											{contents.map((section, index) => (
												<div key={section.title}>
													<button
														type="button"
														className={cn(
															"border-b border-foreground/6 w-full text-left flex gap-2 items-center px-5 py-3 transition-colors",
															"font-medium text-sm tracking-wider",
															mobileDocSection === index
																? "text-foreground bg-foreground/3"
																: "text-foreground/70 hover:text-foreground hover:bg-foreground/3",
														)}
														onClick={() =>
															setMobileDocSection((prev) =>
																prev === index ? -1 : index,
															)
														}
													>
														<section.Icon className="size-4.5" />
														<span className="grow">{section.title}</span>
														<ChevronDownIcon
															className={cn(
																"h-4 w-4 shrink-0 text-muted-foreground transition-transform duration-200",
																mobileDocSection === index ? "rotate-180" : "",
															)}
														/>
													</button>
													{mobileDocSection === index && (
														<div className="relative overflow-hidden">
															<div className="text-sm pt-0 pb-1">
																{section.href && (
																	<Link
																		href={prefixHref(section.href)}
																		onClick={() => setMobileMenuOpen(false)}
																		data-active={
																			pathname === section.href || undefined
																		}
																		className={cn(
																			"relative flex items-center gap-2.5 px-5 py-1.5 text-[14px] transition-all duration-150",
																			pathname === section.href
																				? "text-foreground bg-foreground/6"
																				: "text-foreground/75 dark:text-foreground/60 hover:text-foreground/90 hover:bg-foreground/3",
																		)}
																	>
																		<span className="truncate">Overview</span>
																	</Link>
																)}
																{section.list.map((item, i) => {
																	if (item.separator || item.group) {
																		return (
																			<div
																				key={`sep-${item.title}-${i}`}
																				className="flex flex-row items-center gap-2 mx-5 my-2"
																			>
																				<p className="text-[10px] text-foreground/65 dark:text-foreground/45 uppercase tracking-wider">
																					{item.title}
																				</p>
																				<div className="grow h-px bg-border" />
																			</div>
																		);
																	}
																	if (item.external && item.href) {
																		return (
																			<Link
																				key={item.href}
																				href={item.href}
																				onClick={() => setMobileMenuOpen(false)}
																				className={cn(
																					"relative flex w-full items-center gap-2.5 px-5 py-1.5 text-[14px] transition-all duration-150",
																					"text-foreground/75 dark:text-foreground/60 hover:text-foreground/90 hover:bg-foreground/3",
																				)}
																			>
																				<span className="text-foreground/75 transition-colors duration-150 dark:text-foreground/60">
																					<span className="flex size-5 shrink-0 items-center justify-center [&>svg]:size-[14px]">
																						<item.icon className="text-foreground/75" />
																					</span>
																				</span>
																				<span className="min-w-0 grow truncate">
																					{item.title}
																				</span>
																				{item.isNew && (
																					<Badge
																						className="pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider text-foreground/70 dark:text-foreground/55 border-foreground/25"
																						variant="outline"
																					>
																						New
																					</Badge>
																				)}
																				{item.isUnderDevelopment && (
																					<Badge
																						className="pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider text-foreground/70 dark:text-foreground/55 border-foreground/25"
																						variant="outline"
																					>
																						Under development
																					</Badge>
																				)}
																				{item.isExperimental && (
																					<Badge
																						className="pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider text-foreground/70 dark:text-foreground/55 border-foreground/25"
																						variant="outline"
																					>
																						Experimental
																					</Badge>
																				)}
																			</Link>
																		);
																	}
																	if (!item.href) return null;
																	const active =
																		pathname === item.href ||
																		(!!item.subpages?.length &&
																			pathname.startsWith(`${item.href}/`));
																	return (
																		<Link
																			key={item.href}
																			href={prefixHref(item.href)}
																			onClick={() => setMobileMenuOpen(false)}
																			data-active={active || undefined}
																			className={cn(
																				"relative flex w-full items-center gap-2.5 px-5 py-1.5 text-[14px] transition-all duration-150",
																				active
																					? "text-foreground bg-foreground/6"
																					: "text-foreground/75 dark:text-foreground/60 hover:text-foreground/90 hover:bg-foreground/3",
																			)}
																		>
																			<span
																				className={cn(
																					"transition-colors duration-150",
																					active
																						? "text-foreground"
																						: "text-foreground/75 dark:text-foreground/60",
																				)}
																			>
																				<span className="flex size-5 shrink-0 items-center justify-center [&>svg]:size-[14px]">
																					<item.icon className="text-foreground/75" />
																				</span>
																			</span>
																			<span className="min-w-0 grow truncate">
																				{item.title}
																			</span>
																			{item.isNew && (
																				<Badge
																					className={cn(
																						"pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider",
																						active
																							? "border-solid bg-foreground/10 text-foreground"
																							: "text-foreground/70 dark:text-foreground/55 border-foreground/25",
																					)}
																					variant="outline"
																				>
																					New
																				</Badge>
																			)}
																			{item.isUnderDevelopment && (
																				<Badge
																					className={cn(
																						"pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider",
																						active
																							? "border-solid bg-foreground/10 text-foreground"
																							: "text-foreground/70 dark:text-foreground/55 border-foreground/25",
																					)}
																					variant="outline"
																				>
																					Under development
																				</Badge>
																			)}
																			{item.isExperimental && (
																				<Badge
																					className={cn(
																						"pointer-events-none border-dashed rounded-none px-1.5 py-0 text-[9px] uppercase tracking-wider",
																						active
																							? "border-solid bg-foreground/10 text-foreground"
																							: "text-foreground/70 dark:text-foreground/55 border-foreground/25",
																					)}
																					variant="outline"
																				>
																					Experimental
																				</Badge>
																			)}
																		</Link>
																	);
																})}
															</div>
														</div>
													)}
												</div>
											))}
										</div>
									</>
								) : (
									<>
										{/* Back to docs button (when on docs page and switched to nav view) */}
										{isDocs && mobileView === "nav" && (
											<button
												type="button"
												onClick={() => setMobileView("docs")}
												className="flex items-center gap-2 w-full px-5 py-2.5 text-foreground/65 dark:text-foreground/45 hover:text-foreground/70 transition-colors border-b border-foreground/6"
											>
												<svg
													xmlns="http://www.w3.org/2000/svg"
													width="12"
													height="12"
													viewBox="0 0 24 24"
												>
													<path
														fill="currentColor"
														d="M20 11H7.83l5.59-5.59L12 4l-8 8l8 8l1.41-1.41L7.83 13H20z"
													/>
												</svg>
												<span className="font-mono text-[10px] uppercase tracking-wider">
													Docs
												</span>
											</button>
										)}

										{/* Nav items */}
										{navFiles.map((item) => (
											<Link
												key={item.name}
												href={item.href}
												onClick={() => setMobileMenuOpen(false)}
												className={cn(
													"flex items-center gap-2.5 px-5 py-3.5 border-b border-foreground/6 transition-colors font-mono text-base uppercase tracking-wider",
													isActive(item.path || item.href) ||
														(item.href === "/docs" && isDocs)
														? "text-foreground bg-foreground/4"
														: "text-foreground/75 dark:text-foreground/60 hover:bg-foreground/3",
												)}
											>
												{item.name}
											</Link>
										))}

										{/* Accordion groups */}
										<Accordion
											type="multiple"
											defaultValue={[
												...mobileMenuSections
													.filter((s) =>
														s.children?.some((item) =>
															isActivePrefix(item.path || item.href),
														),
													)
													.map((s) => s.name),
											]}
											className="w-full"
										>
											{mobileMenuSections.map((section) => (
												<AccordionItem
													key={section.name}
													value={section.name}
													className="border-foreground/6"
												>
													{section.children ? (
														<>
															<AccordionTrigger className="px-5 py-3.5 font-mono text-base uppercase tracking-wider text-foreground/75 dark:text-foreground/60 hover:text-foreground hover:no-underline">
																{section.name}
															</AccordionTrigger>
															<AccordionContent className="pb-0">
																{section.children.map((item) => (
																	<Link
																		key={item.name}
																		href={item.href}
																		target={
																			item.external ? "_blank" : undefined
																		}
																		rel={
																			item.external ? "noreferrer" : undefined
																		}
																		onClick={() => setMobileMenuOpen(false)}
																		className={cn(
																			"flex items-center gap-2.5 pl-9 pr-5 py-2.5 transition-colors font-mono text-sm uppercase tracking-wider",
																			isActivePrefix(item.path || item.href)
																				? "text-foreground bg-foreground/4"
																				: "text-foreground/60 dark:text-foreground/45 hover:text-foreground hover:bg-foreground/3",
																		)}
																	>
																		{item.name}
																	</Link>
																))}
															</AccordionContent>
														</>
													) : (
														<Link
															href={section.href!}
															onClick={() => setMobileMenuOpen(false)}
															className={cn(
																"flex items-center gap-2.5 px-5 py-3.5 transition-colors font-mono text-base uppercase tracking-wider",
																isActive(section.href!)
																	? "text-foreground bg-foreground/4"
																	: "text-foreground/75 dark:text-foreground/60 hover:text-foreground",
															)}
														>
															{section.name}
														</Link>
													)}
												</AccordionItem>
											))}
										</Accordion>
									</>
								)}
							</div>

							{/* Sticky footer with get started CTA */}
							{!(isDocs && mobileView === "docs") && (
								<div className="shrink-0 border-t border-foreground/[0.06] bg-background px-5 py-4">
									<a
										href="/docs/introduction"
										onClick={() => setMobileMenuOpen(false)}
										className="flex items-center justify-center gap-1.5 w-full py-3 bg-foreground text-background font-mono text-sm uppercase tracking-wider transition-opacity hover:opacity-90"
									>
										get started
										<svg
											className="h-2.5 w-2.5 opacity-50"
											viewBox="0 0 10 10"
											fill="none"
										>
											<path
												d="M1 9L9 1M9 1H3M9 1V7"
												stroke="currentColor"
												strokeWidth="1.2"
											/>
										</svg>
									</a>
								</div>
							)}
						</div>
					</motion.div>
				)}
			</AnimatePresence>
		</>
	);
}
