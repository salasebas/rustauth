import Link from "next/link";
import { cn } from "@/lib/utils";

const BETTER_AUTH_DOCS_URL = "https://www.better-auth.com/docs";

type DocsAttributionProps = {
	className?: string;
	compact?: boolean;
};

export function DocsAttribution({
	className,
	compact = false,
}: DocsAttributionProps) {
	return (
		<p
			className={cn(
				"text-foreground/45 font-mono leading-relaxed",
				compact ? "text-[10px]" : "text-[11px]",
				className,
			)}
		>
			RustAuth is an independent project and is not affiliated with Better Auth.
			Documentation structure and pages were adapted from the{" "}
			<Link
				href={BETTER_AUTH_DOCS_URL}
				target="_blank"
				rel="noopener noreferrer"
				className="underline underline-offset-2 hover:text-foreground/70 transition-colors"
			>
				Better Auth documentation
			</Link>{" "}
			under its MIT license.
		</p>
	);
}
