import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerSecurityReview } from "./command.ts";

export default function securityReview(pi: ExtensionAPI) {
	registerSecurityReview(pi);
}
