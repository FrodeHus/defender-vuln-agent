#!/usr/bin/env bash
# setup/create-app.sh — create the Entra app registration for defender-vuln-agent.
# Usage: setup/create-app.sh [--name NAME] [--tenant TENANT] [--dry-run]
#   --tenant TENANT  also write the credentials to tenants/TENANT/.env (created if missing, mode 600)
set -euo pipefail
NAME="defender-vuln-agent"; DRY=0; TENANT_NAME=""
while [[ $# -gt 0 ]]; do case "$1" in --name) NAME="$2"; shift 2;; --tenant) TENANT_NAME="$2"; shift 2;; --dry-run) DRY=1; shift;; *) echo "unknown arg $1" >&2; exit 2;; esac; done
MDE_APP="fc780465-2017-40d4-a0c5-307022471b92"
GRAPH_APP="00000003-0000-0000-c000-000000000000"
GRAPH_THREATHUNTING="dd98c7f5-2d42-42d3-a0e4-633161547251"
GRAPH_CROSSTENANT_BASIC="cac88765-0581-4025-9725-5ebc13f729ee"   # CrossTenantInformation.ReadBasic.All (optional: tenant display name in reports)
MDE_PERMS=(Machine.Read.All Vulnerability.Read.All Software.Read.All SecurityRecommendation.Read.All Score.Read.All)
run() { if [[ $DRY -eq 1 ]]; then echo "+ $*"; else "$@"; fi; }
echo "Creating app registration '$NAME'"
if [[ $DRY -eq 1 ]]; then echo "+ az ad app create --display-name $NAME --sign-in-audience AzureADMyOrg --query appId -o tsv"; APP_ID="<app-id>"; TENANT="<tenant-id>"
else APP_ID=$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv); TENANT=$(az account show --query tenantId -o tsv); fi
run az ad sp create --id "$APP_ID"
for p in "${MDE_PERMS[@]}"; do
  if [[ $DRY -eq 1 ]]; then echo "+ ROLE=\$(az ad sp show --id $MDE_APP --query \"appRoles[?value=='$p'].id\" -o tsv)"; echo "+ az ad app permission add --id $APP_ID --api $MDE_APP --api-permissions \$ROLE=Role   # $p"
  else ROLE=$(az ad sp show --id "$MDE_APP" --query "appRoles[?value=='$p'].id" -o tsv); [[ -n "$ROLE" ]] || { echo "role $p not found on WindowsDefenderATP" >&2; exit 1; }
       az ad app permission add --id "$APP_ID" --api "$MDE_APP" --api-permissions "$ROLE=Role"; fi
done
run az ad app permission add --id "$APP_ID" --api "$GRAPH_APP" --api-permissions "$GRAPH_THREATHUNTING=Role"   # ThreatHunting.Read.All
run az ad app permission add --id "$APP_ID" --api "$GRAPH_APP" --api-permissions "$GRAPH_CROSSTENANT_BASIC=Role"   # CrossTenantInformation.ReadBasic.All
if [[ $DRY -eq 1 ]]; then echo "+ az ad app credential reset --id $APP_ID --years 1 --query password -o tsv"; SECRET="<client-secret>"
else SECRET=$(az ad app credential reset --id "$APP_ID" --years 1 --query password -o tsv); fi
if [[ -n "$TENANT_NAME" && $DRY -eq 0 ]]; then
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  TDIR="${DVA_TENANTS_DIR:-$HERE/tenants}/$TENANT_NAME"
  mkdir -p "$TDIR/runs" "$TDIR/.cache"; chmod 700 "$TDIR/.cache"
  ( umask 077; printf 'DVA_TENANT_ID=%s\nDVA_CLIENT_ID=%s\nDVA_CLIENT_SECRET=%s\n' "$TENANT" "$APP_ID" "$SECRET" > "$TDIR/.env" )
  echo "Wrote credentials to $TDIR/.env (mode 600). Select this tenant with: --tenant $TENANT_NAME"
elif [[ -n "$TENANT_NAME" ]]; then
  echo "+ (would write tenants/$TENANT_NAME/.env)"
fi
cat <<EOT

Set these in your shell (or a gitignored .env; per tenant: tenants/NAME/.env):
export DVA_TENANT_ID=$TENANT
export DVA_CLIENT_ID=$APP_ID
export DVA_CLIENT_SECRET=$SECRET

Manual steps remaining:
1. Grant admin consent: az ad app permission admin-consent --id $APP_ID   (needs a Global or Privileged Role Administrator)
2. For Defender for Cloud (optional): assign Reader on each subscription:
   az role assignment create --assignee $APP_ID --role Reader --scope /subscriptions/<sub-id>
3. Verify: python3 -m dva doctor${TENANT_NAME:+ --tenant $TENANT_NAME}
EOT
