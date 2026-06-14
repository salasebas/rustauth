import type { SVGProps } from "react";
import { cn } from "@/lib/utils";

const R_MARK_PATHS = [
	"M69 121H155.988V380H69V121Z",
	"M337.575 121H430V380H337.575V121Z",
	"M427.282 121H510.738V295.52H427.282V121Z",
	"M430 296.544H607.238V473.782H430V296.544Z",
	"M252.762 204.455H349.536V301.229H252.762V204.455Z",
];

export const Logo = ({ className }: { className?: string }) => {
	return (
		<svg
			className={className || "h-5 w-5"}
			viewBox="60 115 360 270"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			aria-hidden="true"
		>
			{R_MARK_PATHS.map((d) => (
				<path key={d} d={d} className="fill-foreground" />
			))}
		</svg>
	);
};

export const LogoMark = ({
	className,
	...props
}: SVGProps<SVGSVGElement>) => {
	return (
		<svg
			{...props}
			viewBox="60 115 360 270"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			className={cn("h-5 w-5", className)}
			aria-hidden="true"
		>
			{R_MARK_PATHS.map((d) => (
				<path key={d} d={d} className="fill-foreground" />
			))}
		</svg>
	);
};
