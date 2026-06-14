import type { SVGProps } from "react";
import { cn } from "@/lib/utils";
import { AdapterIcons } from "./adapter-icons";

type IconProps = SVGProps<SVGSVGElement>;

function BrandIcon({ className, children, ...props }: IconProps) {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			width="16px"
			height="16px"
			viewBox="0 0 24 24"
			fill="currentColor"
			className={cn(className)}
			{...props}
		>
			{children}
		</svg>
	);
}

/** Framework integration marks (Simple Icons where available). */
export const IntegrationIcons = {
	/** Axum has no Simple Icons entry; Hyper is its HTTP stack. */
	axum: (props?: IconProps) => (
		<BrandIcon {...props}>
			<path d="M13.565 17.91H24v1.964H13.565zm-3.201-5.09l-9.187 8.003 2.86-7.004L0 11.179l9.187-8.002-3.11 7.451z" />
		</BrandIcon>
	),
	rust: AdapterIcons.rust,
};
