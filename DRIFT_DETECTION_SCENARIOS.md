# Drift Detection Scenarios - What Gets Caught

This document shows real-world scenarios that the drift detection system **will catch** and what severity each is assigned.

---

## Critical Issues (🔴 CRITICAL) - Must Fix Immediately

### 1. Orphaned OS Disk

**Scenario:** VM was deleted, but its OS disk remains

```
Bicep:
  ❌ No VM defined

Deployed State:
  ✅ VM deleted
  ❌ vm-prod-001_OsDisk_1_abc123def456 still exists, unattached

Detection:
  [CRITICAL] vm-prod-001_OsDisk_1_abc123def456
  Attachment: attached to VM → orphaned
```

**Impact:**
- Wasted storage costs (~$5-10/month per disk)
- Blocks resource group deletion
- Indicates incomplete cleanup

**Fix:**
```bash
az disk delete --name vm-prod-001_OsDisk_1_abc123def456 --resource-group rg-prod
```

---

### 2. Orphaned Data Disks

**Scenario:** Data disks detached from VM but not deleted

```
Bicep:
  resource vm 'Microsoft.Compute/virtualMachines' = {
    // defines 2 data disks
  }

Deployed State:
  ✅ VM has 1 data disk attached
  ❌ vm-prod-001_DataDisk_2_xyz789 orphaned (not attached)

Detection:
  [CRITICAL] vm-prod-001_DataDisk_2_xyz789
  Attachment: attached to VM → orphaned
```

**Impact:**
- Data potentially lost or inaccessible
- Wasted storage
- Risk of accidental deletion

**Fix:**
```bash
# Either reattach to VM or delete
az disk delete --name vm-prod-001_DataDisk_2_xyz789 --resource-group rg-prod
```

---

### 3. VM Without Network Interface

**Scenario:** NIC was deleted but VM still exists (network failure)

```
Bicep:
  resource vm 'Microsoft.Compute/virtualMachines' = {
    networkInterfaces: [{...}]
  }

Deployed State:
  ✅ VM running
  ❌ Network interface deleted
  ❌ VM has 0 NICs

Detection:
  [CRITICAL] vm-prod-001
  Network Interfaces: 1 → 0
```

**Impact:**
- VM is unreachable (no network)
- Cannot RDP/SSH into VM
- Cannot communicate with other resources
- VM is non-functional

**Fix:**
```bash
# Reattach NIC
az vm nic add --resource-group rg-prod --vm-name vm-prod-001 --nics vm-prod-001-nic

# Or redeploy Bicep to recreate NIC
az deployment group create --template-file main.bicep --resource-group rg-prod
```

---

## Warning Issues (🟡 WARNING) - Review and Decide

### 4. VM Size Changed (Clickops)

**Scenario:** Someone resized VM in portal instead of updating Bicep

```
Bicep:
  param vmSize string = 'Standard_D2s_v3'

Deployed State:
  VM actual size: Standard_E4s_v3

Detection:
  [WARNING] vm-prod-001
  vmSize: Standard_D2s_v3 → Standard_E4s_v3 (CRITICAL property)
  Severity: CRITICAL (SKU change)
```

**Impact:**
- VM performance differs from IaC definition
- Cost changed (different pricing tier)
- Deployment won't restore original size
- IaC document is now inaccurate

**Fix Option 1:** Update Bicep to match deployed state
```bicep
param vmSize string = 'Standard_E4s_v3'
```

**Fix Option 2:** Resize VM back to match Bicep
```bash
az vm resize --resource-group rg-prod --name vm-prod-001 --size Standard_D2s_v3
```

---

### 5. Storage Account Type Changed

**Scenario:** Changed from Cool tier to Hot tier in portal

```
Bicep:
  properties: {
    accessTier: 'Cool'
  }

Deployed State:
  accessTier: 'Hot'

Detection:
  [WARNING] storageaccount001
  accessTier: Cool → Hot (CRITICAL property)
  Cost impact: lower cost → higher cost
```

**Impact:**
- Cost increased
- Access patterns don't match IaC definition
- Performance characteristics changed

**Fix:**
```bash
# Update Bicep and redeploy
az deployment group create --template-file main.bicep --resource-group rg-prod
```

---

### 6. Storage Replication Changed

**Scenario:** Changed from LRS (Local Redundant Storage) to GRS (Geo-Redundant) in portal

```
Bicep:
  name: Standard_LRS

Deployed State:
  name: Standard_GRS

Detection:
  [WARNING] storageaccount001
  Replication: LRS → GRS (CRITICAL property)
  Cost impact: $$ → $$$$
```

**Impact:**
- Cost significantly increased
- Data redundancy changed without code review
- Deployment won't restore original setting

---

### 7. SQL Edition Changed

**Scenario:** Database upgraded from Standard to Premium

```
Bicep:
  properties: {
    edition: 'Standard'
  }

Deployed State:
  edition: 'Premium'

Detection:
  [WARNING] sqlserver/mydatabase
  Edition: Standard → Premium (CRITICAL property)
  Cost impact: $$$ → $$$$$
```

**Impact:**
- Cost increased significantly
- Performance SLA changed
- IaC doesn't match deployed state

---

### 8. App Service Reserved Instances

**Scenario:** App Service Plan upgraded from shared to dedicated

```
Bicep:
  properties: {
    reserved: false
  }

Deployed State:
  reserved: true

Detection:
  [WARNING] app-service-plan-001
  Reserved: false → true (CRITICAL property)
```

---

## Tag Changes (🔵 INFO) - Monitor

### 9. Tag Added/Modified

**Scenario:** Ops team added cost center tag manually

```
Bicep:
  tags: {
    environment: 'prod'
    managed: 'true'
  }

Deployed State:
  tags: {
    environment: 'prod'
    managed: 'true'
    costCenter: '12345'        ← Added manually
    owner: 'john.doe@acme.com' ← Added manually
  }

Detection:
  [INFO] vm-prod-001
  tags.costCenter: null → '12345'
  tags.owner: null → 'john.doe@acme.com'
```

**Notes:**
- These are optional properties not defined in Bicep
- **Automatically ignored** (not reported as drift)
- No action needed unless conflicting with policy

---

## Expected Drift (Ignored) - Not Reported

### 10. Parameter Expressions

**Scenario:** Parameter expression resolves to value

```
Bicep:
  tags: {
    environment: '[parameters("env")]'
  }

Deployed State:
  tags: {
    environment: 'prod'  ← Resolved parameter
  }

Detection:
  ✅ IGNORED - This is expected drift
  Parameter expressions resolve at deployment time
```

---

### 11. Landing Zone Resources

**Scenario:** VNets and subnets from separate LZ deployment

```
Bicep:
  resource subnet 'Microsoft.Network/virtualNetworks/subnets@2023-04-01' = {
    existing: true
    name: 'vnet-prod/subnet-vms'
  }

Deployed State:
  ✅ VNet exists (deployed by LZ team)
  ✅ Subnet exists (deployed by LZ team)

Detection:
  ✅ IGNORED - VNets/Subnets are LZ infrastructure
  Referenced as 'existing' not managed by this template
```

---

### 12. Auto-Managed Disks by VM

**Scenario:** Disk created automatically when VM created

```
Bicep:
  resource vm 'Microsoft.Compute/virtualMachines' = {
    // Bicep doesn't explicitly define disks
  }

Deployed State:
  ✅ VM created
  ✅ OS disk auto-created (vm-prod-001_OsDisk_1_abc123)

Detection:
  ✅ IGNORED - Disks auto-created/managed by VMs
  Not separately defined in Bicep
```

---

## Summary Table

| Drift Type | Severity | Auto-Ignored? | Must Fix? | Examples |
|-----------|----------|---------------|-----------|----------|
| Orphaned disks | CRITICAL | No | YES | OS/data disks with no VM |
| VM without NIC | CRITICAL | No | YES | VM with 0 network interfaces |
| SKU changes | CRITICAL | No | YES | VM size, storage tier, SQL edition |
| Property changes | WARNING | No | Review | Tags, location, kind |
| Optional properties | INFO | Yes | Maybe | Extra tags from policies |
| Parameter expressions | INFO | Yes | No | [parameters('env')] resolves |
| LZ infrastructure | INFO | Yes | No | VNets, subnets from LZ |
| Auto-managed child resources | INFO | Yes | No | VM disks, extensions |

---

## Real-World Report Example

```
Drift Report — rg-prod
======================
Found 7 drift(s):

  [CRITICAL] vm-prod-001_OsDisk_1_orphaned
             Attachment: attached to VM → orphaned
             ❌ MUST FIX: Delete orphaned disk

  [CRITICAL] vm-prod-001
             Network Interfaces: 1 → 0
             ❌ MUST FIX: VM has no network connection

  [CRITICAL] vm-prod-001
             hardwareProfile.vmSize: Standard_D2s_v3 → Standard_E4s_v3
             ⚠️ REVIEW: Size changed without Bicep update

  [WARNING] storageaccount001
            accessTier: Cool → Hot
            ℹ️ REVIEW: Access tier changed, cost increased

  [INFO] vm-prod-001
         tags.costCenter: null → '12345'
         ✅ IGNORED: Optional tag added by policy

  ✅ IGNORED (Landing Zone infrastructure):
     - Microsoft.Network/virtualNetworks/vnet-prod
     - Microsoft.Network/virtualNetworks/vnet-prod/subnets/subnet-vms

AI Recommendations:
1. Delete orphaned disk to recover storage costs
2. Reattach NIC to VM immediately - it's unreachable
3. Update Bicep if E4s_v3 is the correct size, or resize VM back
4. Decide if Hot tier is intentional - update Bicep accordingly
```

---

## How to Respond to Drift

### CRITICAL Issues (Do Immediately)

```bash
# 1. Delete orphaned disk
az disk delete --name <disk-name> --resource-group <rg>

# 2. Reattach missing NIC to VM
az vm nic add --resource-group <rg> --vm-name <vm> --nics <nic-name>

# 3. Redeploy Bicep to fix SKU mismatches
az deployment group create \
  --template-file main.bicep \
  --resource-group <rg> \
  --parameters env=prod
```

### WARNING Issues (Review & Fix)

```bash
# Option A: Update Bicep to match deployed state
# Edit main.bicep, commit, deploy

# Option B: Fix deployed resource to match Bicep
az vm resize --resource-group <rg> --name <vm> --size Standard_D2s_v3
```

### INFO Issues (Typically Ignore)

- Parameter expression drift → Expected, no action
- Optional tags added by policies → Fine, no action
- LZ resources → Expected, ignore

---

**Remember:** The drift detection system reports what changed. You decide what to do about it. Most teams review reports weekly and respond to CRITICAL issues immediately, WARNING issues within days, and INFO issues monthly.
