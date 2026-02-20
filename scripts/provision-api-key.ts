// scripts/provision-api-key.ts
// Provision a tenant API key for Solace Adapter
// - Generates a high-entropy raw API key (shown ONCE)
// - Stores only SHA-256 hash in Supabase (solace_api_keys.key_hash)
// - Binds key to organization_id and status=active
//
// Usage:
//   node --loader ts-node/esm scripts/provision-api-key.ts --org <ORG_UUID> [--label "Customer A"] [--status active|revoked]
//
// Required env:
//   SUPABASE_URL
//   SUPABASE_SERVICE_ROLE_KEY  (or SUPABASE_SERVICE_ROLE / SUPABASE_SERVICE_KEY)

import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

type Args = {
  org?: string;
  label?: string;
  status?: string;
};

function parseArgs(argv: string[]): Args {
  const out: Args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];

    if (a === "--org") out.org = argv[++i];
    else if (a === "--label") out.label = argv[++i];
    else if (a === "--status") out.status = argv[++i];
    else if (a === "-h" || a === "--help") {
      printHelpAndExit(0);
    }
  }
  return out;
}

function printHelpAndExit(code: number): never {
  // eslint-disable-next-line no-console
  console.log(`
Provision a tenant API key (stored hashed) for Solace Adapter.

Usage:
  node --loader ts-node/esm scripts/provision-api-key.ts --org <ORG_UUID> [--label "Customer A"] [--status active|revoked]

Env required:
  SUPABASE_URL
  SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SERVICE_ROLE / SUPABASE_SERVICE_KEY)

Notes:
- The raw API key is printed ONCE. Store it securely.
- Only SHA-256 hash is stored in Supabase.
`);
  process.exit(code);
}

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v || !String(v).trim()) throw new Error(`missing_env_${name}`);
  return String(v).trim();
}

function pickServiceRoleKey(): string {
  return (
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_SERVICE_ROLE ||
    process.env.SUPABASE_SERVICE_KEY ||
    ""
  ).trim();
}

function isLikelyUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    v
  );
}

function generateRawApiKey(): string {
  // 32 bytes = 256-bit; base64url is safe for headers.
  return crypto.randomBytes(32).toString("base64url");
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args.org) {
    // eslint-disable-next-line no-console
    console.error("Error: --org is required.");
    printHelpAndExit(1);
  }

  const orgId = String(args.org).trim();
  if (!isLikelyUuid(orgId)) {
    // eslint-disable-next-line no-console
    console.error(`Error: --org must be a UUID. Received: ${orgId}`);
    process.exit(1);
  }

  const SUPABASE_URL = mustEnv("SUPABASE_URL");
  const SUPABASE_SERVICE_ROLE_KEY = pickServiceRoleKey();
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    // eslint-disable-next-line no-console
    console.error(
      "Error: missing SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SERVICE_ROLE / SUPABASE_SERVICE_KEY)."
    );
    process.exit(1);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  const rawKey = generateRawApiKey();
  const keyHash = sha256Hex(rawKey);

  const status = (args.status || "active").trim();
  const label = args.label ? String(args.label).trim() : null;

  // Insert minimal fields to avoid schema assumptions:
  // - organization_id
  // - key_hash
  // - status
  //
  // If your table has additional NOT NULL fields, add them here explicitly.
  const payload: Record<string, unknown> = {
    organization_id: orgId,
    key_hash: keyHash,
    status,
  };

  // If your table includes a label/notes column, we attempt it without requiring it.
  // This is safe only if the column exists; if it doesn't, Supabase will error.
  // To avoid that, we only include it when provided AND you confirm the column exists.
  if (label) payload["label"] = label;

  const { data, error } = await supabase
    .from("solace_api_keys")
    .insert(payload)
    .select("id, organization_id, status")
    .single();

  if (error) {
    // eslint-disable-next-line no-console
    console.error("Supabase insert error:", error);
    process.exit(1);
  }

  // eslint-disable-next-line no-console
  console.log("✅ Provisioned Solace Adapter API Key");
  // eslint-disable-next-line no-console
  console.log("organization_id:", data.organization_id);
  // eslint-disable-next-line no-console
  console.log("api_key_id:", data.id);
  // eslint-disable-next-line no-console
  console.log("status:", data.status);
  // eslint-disable-next-line no-console
  console.log("");
  // eslint-disable-next-line no-console
  console.log("⚠️  RAW API KEY (store securely; shown once):");
  // eslint-disable-next-line no-console
  console.log(rawKey);
  // eslint-disable-next-line no-console
  console.log("");
  // eslint-disable-next-line no-console
  console.log("Client headers:");
  // eslint-disable-next-line no-console
  console.log(`x-solace-org-id: ${orgId}`);
  // eslint-disable-next-line no-console
  console.log(`x-solace-api-key: ${rawKey}`);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error("Fatal error:", e);
  process.exit(1);
});
