import type { ProtectedAction } from "./types.js";

/**
 * The GitHub deployment profile, v1.
 *
 * This is the canonicalization contract the published Copilot reference already
 * demonstrates, named so a receipt can say which contract produced its request
 * hash. The five inputs below are what the agent signs; changing how any of them
 * is derived is a new version, never a revision of this one.
 *
 *   resource   github:{owner}/{repo}
 *   path       /services/{service}/environments/{environment}
 *   payload    { artifact_digest }
 *   action     github.deploy
 *   scope      custom:github:deploy
 */
export const GITHUB_DEPLOY_V1 = "github.deploy/v1";

export interface GithubDeployRequest {
  owner: string;
  repo: string;
  service: string;
  environment: string;
  artifactDigest: string;
  agentId: string;
  sessionId: string;
  invocationId: string;
}

/**
 * Builds the action for a GitHub deployment under `github.deploy/v1`.
 *
 * Offered as a function rather than documentation because the value of a
 * versioned profile is that two receivers on the same version produce byte-identical
 * bindings. Hand-assembly with a shared prose spec does not give that.
 */
export function githubDeployV1(request: GithubDeployRequest): ProtectedAction {
  return {
    action: "github.deploy",
    requiredScope: "custom:github:deploy",
    resourceId: `github:${request.owner}/${request.repo}`,
    requestedPath: `/services/${request.service}/environments/${request.environment}`,
    payload: { artifact_digest: request.artifactDigest },
    agentId: request.agentId,
    sessionId: request.sessionId,
    invocationId: request.invocationId,
    actionProfile: GITHUB_DEPLOY_V1,
  };
}
