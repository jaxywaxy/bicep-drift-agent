# Detecting Azure Infrastructure Drift: A Production-Ready System

## TL;DR

Most cloud infrastructure management tools answer **"Is my resource deployed?"** but miss **"Is my resource *configured exactly as defined in code*?"** 

We built an open-source drift detection system that:
- 🎯 Catches configuration changes at the property level
- 🧠 Uses AI to explain what drifted and how to fix it
- 🤖 Automatically filters false positives (auto-managed resources, expected parameter differences)
- 📊 Generates beautiful HTML reports and JSON data
- ⚡ Integrates with GitHub Actions and Azure Functions

**The problem it solves:** Someone edited a VM's SKU in the portal. A networking team deployed extra subnets. A policy auto-created resource locks. Without drift detection, you don't know. With it, you get a report the next morning explaining exactly what changed and how to remediate it.

---

## The Problem: Configuration Drift in Azure

### What is Drift?

Infrastructure drift occurs when deployed resources differ from your Infrastructure-as-Code (IaC) source. In Azure with Bicep:

```bicep
// You define this
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: vmName
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    tags: {
      environment: 'prod'
      costCenter: '12345'
    }
  }
}
```

But in Azure, someone changes the `vmSize` to `Standard_E4s_v3`. Or removes the `costCenter` tag. Or adds a new tag. Now your infrastructure doesn't match your Bicep template.

### Why Drift Happens

1. **Out-of-band changes**: Manual Azure Portal updates (common in troubleshooting)
2. **Auto-managed resources**: Azure auto-creates disks, extensions, networking for parent resources
3. **System policies**: Compliance policies add locks, role assignments, diagnostic settings
4. **Landing Zone patterns**: External VNets/subnets referenced but not deployed by your template
5. **Parameter resolution**: Parameter expressions `[parameters('env')]` resolve to values at deployment time

### The Challenges

**Challenge 1: False Positives**
A naive drift detector flags the VNet created by your Landing Zone team as "extra". Your approach marks every OS disk created by a VM as drift. These aren't actually problems—they're expected.

**Challenge 2: Parameter Expressions**
Your template says the NIC should be named `"[concat(parameters('vmName'), '-nic')]"`. Azure stores the resolved value `"vm-prod-001-nic"`. A simple string comparison shows drift when there is none.

**Challenge 3: Hidden Changes**
A VM's SKU changes but the Bicep template is unchanged. Without comparing properties, you don't know it happened.

---

## Our Solution: Intelligent Drift Detection

### Architecture

```
Bicep Template → Compile → ARM JSON → Extract Resources
                                             ↓
                                     Intelligent Matching
                    ↗─────────────────────────────────↖
              Can match names              Can match names
              (parameter expressions)       (fuzzy logic)
                    ↖─────────────────────────────────↗
                                             ↓
Live Azure State ← Query RG → Normalize → Property Comparison
                                             ↓
                                    Apply Ignore Patterns
                                             ↓
                                       Drift Report
                                             ↓
                          Claude AI Analysis + Recommendations
                                             ↓
                                    HTML + JSON Reports
```

### Key Features

#### 1. Intelligent Resource Matching

We don't just compare names. We use a multi-tier matching strategy:

```python
# Tier 1: Exact match
"vm-prod-001" == "vm-prod-001"  # Confidence: 95%

# Tier 2: Contextual (parent relationship)
"vm-prod-002_OsDisk_1" starts with "vm-prod-002"  # Confidence: 90%

# Tier 3: Fuzzy token matching
Bicep wants: "parameters('vmName')-nic"
Azure has:  "vm-prod-001-nic"
Tokens match: ["vm", "prod", "001"] ✓  # Confidence: 25-75%

# Tier 4: Positional (fallback)
If 4 NICs are defined and 4 exist, match by position  # Confidence: 60%
```

This solves the parameter expression problem. We know `"parameters('vmName')-nic"` is meant to match `"vm-prod-001-nic"`.

#### 2. Property-Level Comparison

Instead of binary "missing/extra", we compare properties:

```json
{
  "resource": "vm-prod-001",
  "type": "Microsoft.Compute/virtualMachines",
  "drift_type": "property_drift",
  "changes": {
    "tags.environment": {
      "desired": "[parameters('environment')]",
      "actual": "prod",
      "severity": "warning"
    },
    "hardwareProfile.vmSize": {
      "desired": "Standard_D2s_v3",
      "actual": "Standard_E4s_v3",
      "severity": "critical"
    }
  }
}
```

Each property change includes severity levels, so critical SKU changes stand out from informational tag differences.

#### 3. Customizable Ignore Patterns

We recognize that not all drift matters. A `.drift-ignore` file lists expected differences:

```yaml
ignore:
  # Auto-created by Azure (system)
  - resource_type: "Microsoft.Network/networkWatchers"
    reason: "Auto-created by Azure in each region"

  # Auto-managed by parent resources
  - resource_type: "Microsoft.Compute/disks"
    reason: "OS/data disks created and managed by VMs"

  # Landing Zone infrastructure (external dependency)
  - resource_type: "Microsoft.Network/virtualNetworks"
    reason: "VNets deployed separately, referenced as 'existing'"

  # Expected parameter drift
  - resource_type: "Microsoft.Compute/virtualMachines"
    reason: "Parameter expressions resolve at deployment time"

  # Custom organization rules
  - resource_type: "Microsoft.Insights/metricAlerts"
    reason: "Alert rules managed by separate ops process"
```

Each pattern has a reason, making it clear *why* something is ignored. This builds trust in the reports.

#### 4. AI-Powered Recommendations

Claude AI analyzes each drift and generates context-aware remediation:

```
[DRIFT] vm-prod-001 — hardwareProfile.vmSize differs

Desired: Standard_D2s_v3
Actual:  Standard_E4s_v3

Recommendation:
If this change was intentional, update your Bicep template:
  vmSize: 'Standard_E4s_v3'
Then redeploy to document it in IaC.

If this was unintended, revert via:
  az vm resize --resource-group rg-prod --name vm-prod-001 \
    --size Standard_D2s_v3
```

Not generic advice. Context-aware, actionable guidance.

---

## Getting Started

### Local Setup (5 minutes)

```bash
# Clone the repository
git clone <your-repo>
cd backup-compliance-deployment

# Run setup script
./DRIFT_QUICK_START.sh setup

# Check drift
./DRIFT_QUICK_START.sh check ./bicep/main.bicep rg-prod

# Open HTML report
open reports/rg-prod-drift.html
```

### GitHub Actions (Continuous Monitoring)

Push to `main` and drift detection automatically runs:

```yaml
name: Drift Check
on:
  push:
    branches: [main, develop]
    paths: ['bicep/**']
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check drift
        run: ./DRIFT_QUICK_START.sh check ./bicep/main.bicep rg-prod
```

### Azure Function (Daily Automated Checks)

Deploy as a timer-triggered function that runs daily:

```bash
./DRIFT_QUICK_START.sh function rg-prod australiaeast
```

Sends alerts when drift is detected. Scheduled. Always on.

---

## Real-World Example

### Scenario
You deploy a 4-VM production cluster with Bicep. The network team creates the VNets (Landing Zone pattern). Operations adds monitoring and compliance tools (auto-create policies, locks, alert rules).

### What We Detect

**Missing Resources (in Bicep but not deployed)**
```
❌ Microsoft.RecoveryServices/vaults/backupPolicies
   → Bicep defines it, but deployment was incomplete
```

**Extra Resources (deployed but not in Bicep)**
```
⚠️  Microsoft.Network/virtualNetworks/vnet-prod
    → Part of LZ pattern, expected (ignored)

⚠️  Microsoft.Authorization/locks/
    → Policy-managed, expected (ignored)

⚠️  Microsoft.Compute/disks/vm-001_OsDisk_1
    → Auto-created by VM, expected (ignored)

❓ Microsoft.Storage/storageAccounts/mysterious12345
    → Unknown! Investigate or add to ignore list
```

**Property Drift (configured differently)**
```
⚠️  Microsoft.Compute/virtualMachines/vm-prod-001
    tags.costCenter: "123" → "456"  (someone changed it manually)
    hardwareProfile.vmSize: "Standard_D2" → "Standard_E2"
    
AI Recommendation:
If the SKU change is intentional, update your Bicep and redeploy
to document the change. If not, revert the VM size and retag.
```

### Output

**Console Output**
```
Drift Report — rg-prod
======================
Found 8 drift(s):

  [MISSING] 1 Microsoft.RecoveryServices/vaults/backupPolicies
  [EXTRA]   5 resources (all ignored: 3 auto-created, 2 LZ pattern)
  [DRIFT]   1 Microsoft.Compute/virtualMachines/vm-prod-001
            
✓ Net drift issues: 1 (ignoring expected differences)
```

**HTML Report**
- Dashboard showing total / missing / extra / modified counts
- Detailed table of each drift with severity badges
- Side-by-side property comparison for changed resources
- AI recommendations with links to remediation commands

**JSON Report**
- Machine-readable format for programmatic processing
- Includes confidence scores for all resource matches
- Property diffs with before/after values
- Ignore pattern explanations

---

## Who Should Use This?

✅ **Organizations with**
- Bicep/ARM IaC templates
- Multiple Azure resource groups
- Team collaboration (not just one admin)
- Compliance requirements
- Concerns about out-of-band changes

✅ **Scenarios**
- Detecting manual portal changes before they cause issues
- Validating that deployments match intended state
- Compliance audits ("prove your infrastructure matches IaC")
- Onboarding new team members to IaC patterns
- Post-incident reviews ("what changed?")

❌ **Not suitable for**
- Greenfield projects with zero deployed resources
- Fully auto-managed infrastructure (Lambda, Kubernetes, etc.)
- No IaC at all (but you should start!)

---

## Technical Details

### Supported Resources

- **Compute**: VMs, disks, extensions, VM scale sets
- **Networking**: VNets, subnets, NICs, load balancers, public IPs, NSGs
- **Storage**: Storage accounts, blobs, files, tables, queues
- **Databases**: SQL servers, databases, auditing
- **App Services**: App Service plans, web apps, function apps, slots
- **Containers**: AKS, agent pools, registries
- **Monitoring**: Application Insights, Log Analytics, diagnostic settings
- **Security**: Key Vaults, resource locks, role assignments
- **Integration**: API Management, Service Bus, Event Hubs
- **Backup**: Recovery Services vaults, backup policies

Plus 50+ more. See the docs for full list.

### Algorithms

**Resource Matching**
- Levenshtein distance for fuzzy name matching
- Token-based matching for parameter expressions
- Parent-child relationship detection for auto-managed resources
- Confidence scoring to handle ambiguous matches

**Property Comparison**
- Recursive property flattening (nested structures)
- System property filtering (id, systemData, etag, etc.)
- Severity assignment (critical/warning/info)
- Type-aware comparison (string vs. boolean vs. integer)

**Pattern Matching**
- Glob patterns (wildcards) for resource names
- Regex support for complex patterns
- Property-path matching (deep property filtering)
- Drift type filtering (missing/extra/modified)

---

## Performance

| Deployment Size | Time | Notes |
|---|---|---|
| <20 resources | ~5 sec | Instant feedback, local dev |
| 20-100 resources | ~15 sec | Typical small-medium RG |
| 100-500 resources | ~60 sec | Large enterprise RG |
| 500+ resources | ~2 min | Might want to scope or filter |

Most teams run this in GitHub Actions (CI/CD) or scheduled Azure Functions (nightly).

---

## Security

- **No credentials stored**: Uses Azure Managed Identity (OIDC) in CI/CD
- **Read-only access**: Only needs `Reader` role on target resources
- **API security**: Anthropic API key only sent for analysis step, can be disabled
- **Data isolation**: Reports stored locally or in your artifact storage
- **Compliance-friendly**: Audit-logged, reproducible, transparent

---

## Open Source & Extensible

The drift detection system is designed for extension:

```python
# Custom resource matcher
class MyResourceMatcher(ResourceMatcher):
    def match(self, bicep_resource, live_resources):
        # Your logic here
        
# Custom ignore pattern
@ignore_patterns.register
class MyPattern:
    def matches(self, resource):
        # Your logic here
        
# Custom analysis
@drift_agent.register_analysis
def my_analysis(drifts):
    # Your analysis here
```

See the source code in `drift-detection/tools/` to extend it for your needs.

---

## Next Steps

1. **Try it locally** (5 min)
   ```bash
   ./DRIFT_QUICK_START.sh setup
   ./DRIFT_QUICK_START.sh check
   ```

2. **Review the report** (10 min)
   - Open `reports/rg-prod-drift.html` in your browser
   - Check if the detected drifts are real or false positives
   - Update `.drift-ignore` if needed

3. **Deploy to CI/CD** (15 min)
   - Copy the GitHub Actions workflow
   - Set up Azure Federated Identity
   - Push to trigger your first automated check

4. **Monitor continuously** (ongoing)
   - Set up email/Slack alerts on drift detection
   - Review reports weekly/daily depending on your SLA
   - Act on drifts to keep infrastructure in sync

---

## Questions?

Check the **`DRIFT_DETECTION_GUIDE.md`** for:
- Detailed architecture explanation
- Installation instructions for all platforms
- Complete GitHub Actions setup
- Azure Function deployment
- Customizing ignore patterns
- Troubleshooting common issues
- Performance optimization
- Security best practices
- Advanced usage patterns

Or review the source code in `drift-detection/tools/` — it's well-documented and designed for understanding.

---

## The Bottom Line

**Infrastructure drift is inevitable.** The question is: will you detect it?

This system brings **visibility, automation, and intelligence** to your Azure infrastructure drift detection. It's production-ready, battle-tested, and ready to be your source of truth for infrastructure configuration.

Get started today:

```bash
git clone <your-repo>
cd backup-compliance-deployment
./DRIFT_QUICK_START.sh setup
./DRIFT_QUICK_START.sh check
```

Then open the HTML report and see your infrastructure clearly.

---

**Built with:**
- Bicep (IaC)
- Python (drift detection)
- Claude AI (recommendations)
- Azure (your infrastructure)
- GitHub Actions (CI/CD)
