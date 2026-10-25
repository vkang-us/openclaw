import type { ApplicationGateway } from "./gateway.ts";
import { readGatewayOperatorAccess } from "./operator-access.ts";

export function readOverlayOperatorAccessTransition(
  previous: ReturnType<typeof readGatewayOperatorAccess>,
  snapshot: ApplicationGateway["snapshot"],
) {
  const access = snapshot.phase === "connected" ? readGatewayOperatorAccess(snapshot) : previous;
  return {
    access,
    reviewChanged: previous.canReviewApprovals !== access.canReviewApprovals,
    grantChanged: previous.canGrantApprovals !== access.canGrantApprovals,
    grantRevoked: previous.canGrantApprovals && !access.canGrantApprovals,
    adminRevoked: previous.canAdmin && !access.canAdmin,
    pairingChanged: previous.canPair !== access.canPair,
  };
}
