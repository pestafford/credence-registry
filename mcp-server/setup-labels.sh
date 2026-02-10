#!/usr/bin/env bash
# Create required Credence labels in the credence-registry repo.
# Run once: ./setup-labels.sh
# Requires: gh CLI authenticated

REPO="pestafford/credence-registry"

declare -A LABELS=(
  ["submission"]="0e8a16:New server submission for Credence scanning"
  ["scan-complete"]="1d76db:Pipeline scan has completed"
  ["risk-low"]="4ade80:Trust score ≥80 — low risk"
  ["risk-medium"]="D06030:Trust score 50-79 — medium risk"
  ["risk-high"]="ef4444:Trust score <50 — high risk"
  ["verified-maintainer"]="6f42c1:Submitter verified as repo owner/collaborator/contributor"
  ["third-party"]="808080:Submitter is not affiliated with the repo"
  ["attestation-published"]="0075ca:Signed attestation added to registry"
  ["disclosure-pending"]="fbca04:Findings under remediation window"
  ["pending-review"]="c2e0c6:Submission awaiting maintainer review before scanning"
)

echo "Creating labels in $REPO..."
for label in "${!LABELS[@]}"; do
  IFS=":" read -r color desc <<< "${LABELS[$label]}"
  echo "  $label ($color)"
  gh label create "$label" --repo "$REPO" --color "$color" --description "$desc" --force 2>/dev/null
done

echo "Done. Labels created."
