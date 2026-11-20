import { hash } from "bcryptjs";
import { prisma } from "../src/lib/prisma.js";

async function main() {
  console.log("Seeding GraphOps demo data...");

  // ─── Demo users ─────────────────────────────────────────────────────────────
  const analystHash = await hash("analyst-demo-2026!", 12);
  const responderHash = await hash("responder-demo-2026!", 12);
  const managerHash = await hash("manager-demo-2026!", 12);

  const analyst = await prisma.user.upsert({
    where: { email: "analyst@graphops.demo" },
    update: {},
    create: {
      name: "Alex Analyst",
      email: "analyst@graphops.demo",
      passwordHash: analystHash,
      role: "ANALYST",
    },
  });

  const responder = await prisma.user.upsert({
    where: { email: "responder@graphops.demo" },
    update: {},
    create: {
      name: "Riley Responder",
      email: "responder@graphops.demo",
      passwordHash: responderHash,
      role: "RESPONDER",
    },
  });

  const manager = await prisma.user.upsert({
    where: { email: "manager@graphops.demo" },
    update: {},
    create: {
      name: "Morgan Manager",
      email: "manager@graphops.demo",
      passwordHash: managerHash,
      role: "SOC_MANAGER",
    },
  });

  console.log(`  Users: ${analyst.email}, ${responder.email}, ${manager.email}`);

  // ─── Demo detection policy ───────────────────────────────────────────────────
  const policy = await prisma.detectionPolicy.upsert({
    where: { id: "demo-policy-001" },
    update: {},
    create: {
      id: "demo-policy-001",
      name: "SOC Default Policy",
      description: "Default detection policy for the GraphOps demo environment.",
    },
  });

  // ─── Demo hunt rules (ATT&CK mapped) ────────────────────────────────────────
  const huntRules = [
    {
      ruleCode: "HUNT-LM-001",
      attackId: "T1021.001",
      tactic: "lateral-movement",
      title: "Lateral Movement via Remote Desktop",
      description: "Detects chains of LOGGED_IN edges across hosts that form a lateral movement path.",
      severity: "HIGH" as const,
      policyId: policy.id,
    },
    {
      ruleCode: "HUNT-CR-001",
      attackId: "T1078",
      tactic: "initial-access",
      title: "Credential Reuse Across Unusual Hosts",
      description: "Detects when the same credentials are used on hosts outside the normal peer group.",
      severity: "HIGH" as const,
      policyId: policy.id,
    },
    {
      ruleCode: "HUNT-RP-001",
      attackId: "T1059",
      tactic: "execution",
      title: "Rare Parent-Child Process",
      description: "Detects anomalous SPAWNED edges that have never been observed in baseline traffic.",
      severity: "MEDIUM" as const,
      policyId: policy.id,
    },
    {
      ruleCode: "HUNT-BC-001",
      attackId: "T1071",
      tactic: "command-and-control",
      title: "Periodic Beaconing",
      description: "Detects hosts with highly regular outbound connection intervals (C2 beaconing).",
      severity: "HIGH" as const,
      policyId: policy.id,
    },
    {
      ruleCode: "HUNT-FO-001",
      attackId: "T1046",
      tactic: "discovery",
      title: "Fan-Out Spike",
      description: "Detects hosts that suddenly connect to an unusually high number of unique targets.",
      severity: "MEDIUM" as const,
      policyId: policy.id,
    },
    {
      ruleCode: "HUNT-CC-001",
      attackId: "T1484",
      tactic: "lateral-movement",
      title: "Cross-Community Edges",
      description: "Detects edges between Louvain community clusters, indicating unusual inter-segment traffic.",
      severity: "LOW" as const,
      policyId: policy.id,
    },
  ];

  for (const rule of huntRules) {
    await prisma.huntRule.upsert({
      where: { policyId_ruleCode: { policyId: rule.policyId, ruleCode: rule.ruleCode } },
      update: {},
      create: rule,
    });
  }

  console.log(`  Hunt rules: ${huntRules.length} created`);

  // ─── Demo crown jewels ───────────────────────────────────────────────────────
  const crownJewels = [
    { nodeId: "host-dc01", label: "DC-01 (Domain Controller)", nodeType: "Host", criticality: 10, isCrownJewel: true, policyId: policy.id },
    { nodeId: "host-db01", label: "DB-01 (Primary Database)", nodeType: "Host", criticality: 9, isCrownJewel: true, policyId: policy.id },
    { nodeId: "cloud-s3-prod", label: "S3-Prod (Production Bucket)", nodeType: "CloudResource", criticality: 9, isCrownJewel: true, policyId: policy.id },
  ];

  for (const cj of crownJewels) {
    await prisma.assetNode.upsert({
      where: { id: `demo-cj-${cj.nodeId}` },
      update: {},
      create: { id: `demo-cj-${cj.nodeId}`, ...cj },
    });
  }

  console.log(`  Crown jewels: ${crownJewels.length} registered`);
  console.log("Seed complete.");
  console.log("\nDemo credentials:");
  console.log("  Analyst:   analyst@graphops.demo / analyst-demo-2026!");
  console.log("  Responder: responder@graphops.demo / responder-demo-2026!");
  console.log("  Manager:   manager@graphops.demo / manager-demo-2026!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
