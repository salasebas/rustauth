import { GeistPixelSquare } from "geist/font/pixel";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Analytics } from "@vercel/analytics/next";
import type { Metadata } from "next";
import Script from "next/script";
import type { ReactNode } from "react";
import { StaggeredNavFiles } from "@/components/landing/staggered-nav-files";
import { Providers } from "@/components/providers";
import { createMetadata } from "@/lib/metadata";

const fontSans = Geist({
	subsets: ["latin"],
	variable: "--font-sans",
});

const fontMono = Geist_Mono({
	subsets: ["latin"],
	variable: "--font-mono",
});

export const metadata: Metadata = createMetadata({
	title: {
		template: "%s | RustAuth",
		default: "RustAuth",
	},
	description:
		"Server-first authentication framework for Rust with Axum, plugins, and SQL adapters.",
});

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html lang="en" suppressHydrationWarning data-scroll-behavior="smooth">
			<body
				className={`${fontSans.variable} ${fontMono.variable} ${GeistPixelSquare.variable} font-sans antialiased`}
				suppressHydrationWarning
			>
				<Script id="theme-color-init" strategy="beforeInteractive">
					{`try {
  if (localStorage.theme === 'dark' || ((!('theme' in localStorage) || localStorage.theme === 'system') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', '#141413')
  }
} catch (_) {}`}
				</Script>
				{process.env.NODE_ENV === "development" && (
					<Script
						src="//unpkg.com/react-grab/dist/index.global.js"
						crossOrigin="anonymous"
						strategy="lazyOnload"
						data-options={JSON.stringify({
							activationKey: " ",
							activationMode: "toggle",
							allowActivationInsideInput: false,
							maxContextLines: 3,
						})}
					/>
				)}
				{process.env.NODE_ENV === "development" && (
					<Script
						src="//unpkg.com/@react-grab/mcp/dist/client.global.js"
						strategy="lazyOnload"
					/>
				)}
				<Providers>
					<div className="relative min-h-dvh">
						<StaggeredNavFiles />
						{children}
					</div>
				</Providers>
				<Analytics />
			</body>
		</html>
	);
}
