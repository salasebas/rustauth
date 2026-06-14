import { Callout } from "@/components/ui/callout";

export function UnderDevelopment() {
	return (
		<Callout type="warn" title="Under development">
			This page documents a feature that is still being ported to RustAuth.
			Behavior, routes, and configuration may change. See the migration matrix
			for current disposition.
		</Callout>
	);
}
