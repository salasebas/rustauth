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
	/** Actix Web has no Simple Icons entry; stylized gear mark. */
	actixWeb: (props?: IconProps) => (
		<BrandIcon {...props}>
			<path d="M12 2a1 1 0 0 1 .894.553l1.618 3.236 3.236 1.618a1 1 0 0 1 0 1.788l-3.236 1.618L12.894 14.05a1 1 0 0 1-1.788 0l-1.618-3.235-3.236-1.618a1 1 0 0 1 0-1.789l3.236-1.618 1.618-3.236A1 1 0 0 1 12 2Zm0 4.236L11.09 8.09 8.09 9.236 11.09 10.382 12 12.236l.91-1.854 3-1.146-3-1.146L12 6.236Z" />
		</BrandIcon>
	),
	rust: AdapterIcons.rust,
};
