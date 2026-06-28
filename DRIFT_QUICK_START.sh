#!/bin/bash
#
# Bicep Drift Detection - Quick Start & Deployment Script
#
# Usage:
#   ./DRIFT_QUICK_START.sh setup       # Install & configure locally
#   ./DRIFT_QUICK_START.sh check       # Run drift check
#   ./DRIFT_QUICK_START.sh function    # Deploy as Azure Function
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIFT_DIR="${SCRIPT_DIR}/drift-detection"
DEFAULT_RG="rg-prod"
DEFAULT_LOCATION="australiaeast"

echo_info() {
    echo -e "${BLUE}ℹ  ${1}${NC}"
}

echo_success() {
    echo -e "${GREEN}✓  ${1}${NC}"
}

echo_error() {
    echo -e "${RED}✗  ${1}${NC}"
}

echo_warning() {
    echo -e "${YELLOW}⚠  ${1}${NC}"
}

# ============================================================================
# SETUP
# ============================================================================

setup_local() {
    echo_info "Setting up local environment..."

    # Check prerequisites
    echo_info "Checking prerequisites..."

    command -v python3 >/dev/null 2>&1 || { echo_error "Python 3 not found"; exit 1; }
    echo_success "Python 3 found: $(python3 --version)"

    command -v az >/dev/null 2>&1 || { echo_error "Azure CLI not found"; exit 1; }
    echo_success "Azure CLI found: $(az --version | head -1)"

    # Create virtual environment
    echo_info "Creating Python virtual environment..."
    cd "${DRIFT_DIR}"
    python3 -m venv .venv
    source .venv/bin/activate
    echo_success "Virtual environment created"

    # Install dependencies
    echo_info "Installing Python dependencies..."
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    echo_success "Dependencies installed"

    # Create .env template
    if [ ! -f "${DRIFT_DIR}/.env" ]; then
        echo_info "Creating .env template..."
        cat > "${DRIFT_DIR}/.env" << 'EOF'
# Azure
AZURE_SUBSCRIPTION_ID=<your-subscription-id>
AZURE_TENANT_ID=<your-tenant-id>

# Claude AI (https://console.anthropic.com)
ANTHROPIC_API_KEY=sk-<your-api-key>
EOF
        echo_warning "Created .env template - edit with your credentials:"
        echo "  $DRIFT_DIR/.env"
    else
        echo_success ".env file exists"
    fi

    # Verify Azure login
    echo_info "Checking Azure login..."
    if ! az account show >/dev/null 2>&1; then
        echo_warning "Not logged into Azure. Run: az login"
    else
        ACCOUNT=$(az account show --query name -o tsv)
        echo_success "Logged in as: $ACCOUNT"
    fi

    echo_success "Local setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Edit drift-detection/.env with your credentials"
    echo "  2. Run: source drift-detection/.venv/bin/activate"
    echo "  3. Run: ./DRIFT_QUICK_START.sh check"
}

# ============================================================================
# RUN DRIFT CHECK
# ============================================================================

run_drift_check() {
    local bicep_file="${1:-./bicep/main.bicep}"
    local resource_group="${2:-$DEFAULT_RG}"

    echo_info "Starting drift check..."
    echo_info "  Bicep: $bicep_file"
    echo_info "  RG:    $resource_group"

    cd "${DRIFT_DIR}"

    # Activate venv if not already activated
    if [ -z "${VIRTUAL_ENV:-}" ]; then
        if [ ! -d ".venv" ]; then
            echo_error "Virtual environment not found. Run: ./DRIFT_QUICK_START.sh setup"
            exit 1
        fi
        source .venv/bin/activate
    fi

    # Load .env if it exists
    if [ -f ".env" ]; then
        export $(cat .env | grep -v '^#' | xargs)
    fi

    # Check for required env vars
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        echo_error "ANTHROPIC_API_KEY not set. Edit .env or export it."
        exit 1
    fi

    # Run analysis
    python analyze_drift.py "../${bicep_file}" "$resource_group"

    echo_success "Drift check complete!"
    echo ""
    echo "Reports generated:"
    echo "  - HTML:  reports/${resource_group}-drift.html"
    echo "  - JSON:  reports/${resource_group}-drift.json"
    echo "  - MD:    reports/${resource_group}-analysis.md"
    echo ""
    echo "💡 Tip: Open the HTML report in your browser for a detailed dashboard"
}

# ============================================================================
# DEPLOY AS AZURE FUNCTION
# ============================================================================

deploy_function() {
    local resource_group="${1:-$DEFAULT_RG}"
    local location="${2:-$DEFAULT_LOCATION}"

    echo_info "Deploying drift check as Azure Function..."

    # Validate resource group exists
    if ! az group show --name "$resource_group" >/dev/null 2>&1; then
        echo_info "Creating resource group: $resource_group"
        az group create --name "$resource_group" --location "$location"
    fi
    echo_success "Resource group: $resource_group"

    # Generate unique name
    TIMESTAMP=$(date +%s)
    FUNCTION_APP_NAME="drift-check-${TIMESTAMP}"
    STORAGE_ACCOUNT="drift$(echo $TIMESTAMP | tail -c 9)"

    echo_info "Creating storage account: $STORAGE_ACCOUNT"
    az storage account create \
        --name "$STORAGE_ACCOUNT" \
        --resource-group "$resource_group" \
        --location "$location" \
        --sku Standard_LRS \
        --output none
    echo_success "Storage account created"

    echo_info "Creating Function App: $FUNCTION_APP_NAME"
    az functionapp create \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$resource_group" \
        --storage-account "$STORAGE_ACCOUNT" \
        --runtime python \
        --runtime-version 3.11 \
        --functions-version 4 \
        --os-type Linux \
        --output none
    echo_success "Function App created"

    echo_info "Enabling managed identity..."
    az functionapp identity assign \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$resource_group" \
        --identities [system] \
        --output none
    echo_success "Managed identity enabled"

    echo_info "Configuring RBAC..."
    PRINCIPAL_ID=$(az functionapp identity show \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$resource_group" \
        --query principalId -o tsv)

    SUBSCRIPTION_ID=$(az account show --query id -o tsv)

    az role assignment create \
        --assignee "$PRINCIPAL_ID" \
        --role Reader \
        --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$resource_group" \
        --output none
    echo_success "Reader role assigned"

    echo_info "Configuring application settings..."
    az functionapp config appsettings set \
        --name "$FUNCTION_APP_NAME" \
        --resource-group "$resource_group" \
        --settings \
            AZURE_SUBSCRIPTION_ID="$SUBSCRIPTION_ID" \
            TARGET_RG="$resource_group" \
            --output none

    # Prompt for API key
    echo ""
    echo_warning "Set ANTHROPIC_API_KEY:"
    echo "  az functionapp config appsettings set \\"
    echo "    --name $FUNCTION_APP_NAME \\"
    echo "    --resource-group $resource_group \\"
    echo "    --settings ANTHROPIC_API_KEY=sk-..."
    echo ""

    echo_success "Function App deployment summary:"
    echo "  Name:          $FUNCTION_APP_NAME"
    echo "  RG:            $resource_group"
    echo "  Storage:       $STORAGE_ACCOUNT"
    echo "  Subscription:  $SUBSCRIPTION_ID"
    echo ""
    echo "Next steps:"
    echo "  1. Set ANTHROPIC_API_KEY (see command above)"
    echo "  2. Deploy code: func azure functionapp publish $FUNCTION_APP_NAME"
    echo "  3. View logs:   az functionapp log tail --name $FUNCTION_APP_NAME --resource-group $resource_group"
}

# ============================================================================
# GITHUB ACTIONS SETUP
# ============================================================================

setup_github_actions() {
    echo_info "Setting up GitHub Actions..."

    echo_warning "Required GitHub Secrets:"
    echo "  AZURE_CLIENT_ID        (Service Principal)"
    echo "  AZURE_TENANT_ID        (Azure Tenant ID)"
    echo "  AZURE_SUBSCRIPTION_ID  (Subscription ID)"
    echo "  ANTHROPIC_API_KEY      (Claude API Key)"
    echo ""
    echo "To set secrets:"
    echo "  gh secret set AZURE_CLIENT_ID --body '...'"
    echo "  gh secret set AZURE_TENANT_ID --body '...'"
    echo "  gh secret set AZURE_SUBSCRIPTION_ID --body '...'"
    echo "  gh secret set ANTHROPIC_API_KEY --body 'sk-...'"
    echo ""

    # Check if repo is GitHub
    if git remote get-url origin | grep -q github.com; then
        echo_success "GitHub repository detected"
        echo ""
        echo "Workflow file: .github/workflows/bicep-drift-check.yml"
        echo "Triggers:"
        echo "  - Push to main/develop (changes to bicep/)"
        echo "  - Manual workflow_dispatch"
        echo "  - Pull requests to main"
    fi
}

# ============================================================================
# HELP
# ============================================================================

show_help() {
    cat << 'EOF'
Bicep Drift Detection - Quick Start & Deployment

USAGE:
  ./DRIFT_QUICK_START.sh [COMMAND] [OPTIONS]

COMMANDS:
  setup                  Install & configure locally
  check [FILE] [RG]      Run drift check (default: ./bicep/main.bicep, rg-prod)
  function [RG] [LOC]    Deploy as Azure Function
  github                 Show GitHub Actions setup
  help                   Show this help message

EXAMPLES:
  # Setup local environment
  ./DRIFT_QUICK_START.sh setup

  # Run drift check on prod
  ./DRIFT_QUICK_START.sh check

  # Run drift check on specific resources
  ./DRIFT_QUICK_START.sh check ./infra/network.bicep rg-network

  # Deploy function to Azure
  ./DRIFT_QUICK_START.sh function rg-prod australiaeast

  # Setup GitHub Actions secrets
  ./DRIFT_QUICK_START.sh github

ENVIRONMENT:
  ANTHROPIC_API_KEY    Claude API key (required)
  AZURE_SUBSCRIPTION_ID Subscription ID (required)
  ARM_PARAMETERS       JSON parameters (optional, default: dev)

FILES:
  drift-detection/.env           Configuration (.gitignored)
  drift-detection/.drift-ignore  Ignore patterns (version controlled)
  reports/                       Generated reports (HTML, JSON, MD)

DOCUMENTATION:
  See DRIFT_DETECTION_GUIDE.md for detailed documentation

EOF
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    local command="${1:-help}"

    case "$command" in
        setup)
            setup_local
            ;;
        check)
            shift
            run_drift_check "$@"
            ;;
        function)
            shift
            deploy_function "$@"
            ;;
        github)
            setup_github_actions
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
