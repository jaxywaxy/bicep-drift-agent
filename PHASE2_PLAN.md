# Phase 2: Agent-Based Analysis

## Overview

Phase 1 gives you structured drift data. Phase 2 adds an AI agent to reason about what it means and suggest fixes.

## What the agent should do

1. **Infer intent from unresolved expressions**
   - When you see a resource named `st-parameters('environment')` but Azure has `st-prod`
   - The agent should understand the pattern and match them
   - Even if the parameter was never resolved at compile time

2. **Classify drift severity**
   - **Critical**: Infrastructure is missing (missing VMs, networks, etc.)
   - **Warning**: Configuration might differ (tags, SKUs, properties)
   - **Info**: Metadata resources that don't affect functionality

3. **Understand context**
   - When a resource group is "missing" in the Bicep file but exists in Azure
   - It might mean the RG is deployed separately (expected)
   - Or it could mean the template changed (drift)

4. **Suggest remediation**
   - "Deploy the missing resource group with: `az group create ...`"
   - "Delete the extra storage account that's not in the template"
   - "Update the Bicep file if this resource should be deployed"

5. **Generate a human-readable report**
   - Summary of what's different
   - Why it happened
   - What to do about it
   - Estimated effort/risk

## Input to the agent

The agent receives a `DriftReport` (from `tools/models.py`):

```python
{
    "bicep_file": "./main.bicep",
    "resource_group": "rg-prod",
    "parameters": {"environment": "prod"},
    
    "arm_resources": [
        {
            "type": "Microsoft.Network/virtualNetworks",
            "name": "vnet-prod",
            "location": "australiaeast",
            ...
        }
    ],
    
    "live_resources": [
        {
            "type": "Microsoft.Network/virtualNetworks",
            "name": "vnet-prod",
            "location": "australiaeast",
            ...
        }
    ],
    
    "drifts": [
        {
            "resource_type": "Microsoft.Storage/storageAccounts",
            "resource_name": "stprod...",
            "drift_type": "extra",
            "severity": "warning"
        }
    ]
}
```

## Output from the agent

A structured analysis:

```markdown
# Drift Analysis: rg-prod

## Summary
- 1 missing resource (resource group)
- 8 extra resources (VMs, disks, NICs)
- 0 modified resources

## Critical Issues
(none)

## Resources Out of Sync

### Missing in Azure (in Bicep)
- **Microsoft.Resources/resourceGroups/rg-app-prod**
  - Status: Should be deployed
  - Action: Create resource group if landing zone mode
  
### Extra in Azure (not in Bicep)
- **Microsoft.Compute/virtualMachines/vm-prod-001**
  - Status: Deployed but not in template
  - Action: Verify this should exist, or update template

### Modified Resources
(none detected)

## Recommendations
1. Verify that rg-app-prod exists and is the intended target
2. Check if the VMs are expected (might be deployed by different template)
3. Consider updating the Bicep template to match actual deployment

## Confidence
- Low (many unresolved expressions in Bicep)
- Recommend manual review of the bicep file
```

## Implementation approach

1. Create `agent/drift_agent.py` with an `AnalyzeDrift` tool that:
   - Takes the drift report as input
   - Calls Claude API with drift context
   - Returns structured analysis

2. Create a tool definition for the agent to use the drift data

3. Add confidence scoring based on:
   - How many expressions were resolved
   - How close resource names match
   - Whether resources are deployed vs. defined

## Key challenges the agent handles

- **Unresolved names**: `stparameters('env')uniqueString()` should be understood as "a storage account"
- **Nested deployments**: Resources inside module deployments aren't in the main template
- **Landing zones**: Complex templates with many conditional resources
- **False positives**: System-managed resources (like managed disks) that always appear extra

## Next steps

1. Define the agent tool for drift analysis
2. Wire up the Anthropic API
3. Test with various templates
4. Improve the confidence scoring
