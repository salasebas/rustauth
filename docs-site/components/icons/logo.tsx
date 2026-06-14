import type { SVGProps } from "react";
import { cn } from "@/lib/utils";
import {
	RUSTAUTH_ACCENT,
	RUSTAUTH_MARK_VIEWBOX,
} from "@/lib/branding/rustauth-mark";

type LogoProps = {
	className?: string;
	showAccent?: boolean;
};

export const Logo = ({ className, showAccent = true }: LogoProps) => {
	return (
		<svg
			className={className || "h-5 w-5"}
			viewBox={RUSTAUTH_MARK_VIEWBOX}
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			aria-hidden="true"
		>
			<rect
				x="9"
				y="8.5"
				width="4.5"
				height="15"
				rx="1.2"
				className="fill-foreground"
			/>
			<rect
				x="12.8"
				y="8.5"
				width="11.5"
				height="7.5"
				rx="1.2"
				className="fill-foreground"
			/>
			<rect
				x="14.8"
				y="10.8"
				width="7.2"
				height="3.2"
				rx="0.8"
				className="fill-background"
			/>
			<rect
				x="13.2"
				y="15.5"
				width="5.5"
				height="8"
				rx="1.1"
				className="fill-foreground"
			/>
			{showAccent ? (
				<circle cx="25" cy="9.5" r="1.8" fill={RUSTAUTH_ACCENT} />
			) : null}
		</svg>
	);
};

export const LogoMark = ({
	className,
	showAccent = true,
	...props
}: SVGProps<SVGSVGElement> & { showAccent?: boolean }) => {
	return (
		<svg
			{...props}
			viewBox={RUSTAUTH_MARK_VIEWBOX}
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			className={cn("h-5 w-5", className)}
			aria-hidden="true"
		>
			<rect
				x="9"
				y="8.5"
				width="4.5"
				height="15"
				rx="1.2"
				className="fill-foreground"
			/>
			<rect
				x="12.8"
				y="8.5"
				width="11.5"
				height="7.5"
				rx="1.2"
				className="fill-foreground"
			/>
			<rect
				x="14.8"
				y="10.8"
				width="7.2"
				height="3.2"
				rx="0.8"
				className="fill-background"
			/>
			<rect
				x="13.2"
				y="15.5"
				width="5.5"
				height="8"
				rx="1.1"
				className="fill-foreground"
			/>
			{showAccent ? (
				<circle cx="25" cy="9.5" r="1.8" fill={RUSTAUTH_ACCENT} />
			) : null}
		</svg>
	);
};
