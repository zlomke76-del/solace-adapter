// scripts/provision-client.ts
// Full client provisioning for Solace Adapter
// - Generates org API key (hashed)
// - Generates Ed25519 keypair
// - Stores public key in solace_authority_keys
// - Outputs private key ONCE
//
// Usage:
// node --loader ts-node/esm scripts/provision-client.ts --org <ORG_UUID> --label "Customer A"

import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

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

function parseArgs(argv: string[]) {
  const out: { org?: string; label?: string } = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--org") out.org = argv[++i];
    else if (argv[i] === "--label") out.label = argv[++i];
  }
  return out;
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function generateApiKey(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function generateEd25519Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const publicPem = publicKey.export({
    type: "spki",
    format: "pem",
  }).toString();

  const privatePem = privateKey.export({
    type: "pkcs8",
    format: "pem",
  }).toString();

  return { publicPem, privatePem };
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.org) throw new Error("--org is required");

  const orgId = args.org;

  const SUPABASE_URL = mustEnv("SUPABASE_URL");
  const SERVICE_ROLE = pickServiceRoleKey();
  if (!SERVICE_ROLE) throw new Error("missing_service_role_key");

  const supabase = createClient(SUPABASE_URL, SERVICE_ROLE, {
    auth: { persistSession: false },
  });

  /**
   * ------------------------------------------------------------
   * 1️⃣ Generate API Key
   * ------------------------------------------------------------
   */
  const rawApiKey = generateApiKey();
  const apiKeyHash = sha256Hex(rawApiKey);

  const { data: apiKeyRow, error: apiKeyError } = await supabase
    .from("solace_api_keys")
    .insert({
      organization_id: orgId,
      key_hash: apiKeyHash,
      status: "active",
    })
    .select("id")
    .single();

  if (apiKeyError) {
    console.error(apiKeyError);
    process.exit(1);
  }

  /**
   * ------------------------------------------------------------
   * 2️⃣ Generate Ed25519 Keypair
   * ------------------------------------------------------------
   */
  const { publicPem, privatePem } = generateEd25519Keypair();

  const authorityKeyId = crypto.randomUUID();

  const { error: authorityError } = await supabase
    .from("solace_authority_keys")
    .insert({
      id: authorityKeyId,
      organization_id: orgId,
      public_key: publicPem,
      status: "active",
      valid_from: new Date().toISOString(),
      valid_until: null,
    });

  if (authorityError) {
    console.error(authorityError);
    process.exit(1);
  }

  /**
   * ------------------------------------------------------------
   * Output onboarding bundle
   * ------------------------------------------------------------
   */
  console.log("\n✅ Client Provisioned Successfully\n");

  console.log("organization_id:", orgId);
  console.log("api_key_id:", apiKeyRow.id);
  console.log("authorityKeyId:", authorityKeyId);

  console.log("\n⚠️ STORE SECURELY — PRIVATE KEY (shown once)\n");
  console.log(privatePem);

  console.log("\nClient Headers:");
  console.log(`x-solace-org-id: ${orgId}`);
  console.log(`x-solace-api-key: ${rawApiKey}`);

  console.log("\nAuthority Key Usage:");
  console.log("authorityKeyId:", authorityKeyId);
  console.log("Use private key to sign acceptance payloads.");
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
