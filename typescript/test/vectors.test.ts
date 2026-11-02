// SPDX-License-Identifier: Apache-2.0
// Validate the TypeScript reference verifier against the deterministic vectors.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tally, OrganVerdict } from "../src/index.js";

const VEC = join(__dirname, "..", "..", "testdata", "vectors.json");
const BOUNDARY_VEC = join(__dirname, "..", "..", "testdata", "domain-identity-binding.json");

function run(path: string): number {
  const v = JSON.parse(readFileSync(path, "utf-8"));
  const pubkeys: Record<string, string> = v.pubkeys;
  let failures = 0;
  for (const c of v.cases) {
    const sigs: (OrganVerdict | null)[] = c.signatures;
    const r = tally(v.action_hash, sigs, pubkeys, v.threshold, v.n);
    const ok = r.decision === c.expect.decision && r.consensusCount === c.expect.consensus_count;
    console.log(`[${ok ? "PASS" : "FAIL"}] ${c.name}: ${r.khipuConsensus} -> ${r.decision}`);
    if (!ok) failures++;
  }
  return failures;
}

const failures = run(VEC) + run(BOUNDARY_VEC);
if (failures > 0) {
  console.error(`${failures} TS vector cases failed`);
  process.exit(1);
}
console.log("ALL TYPESCRIPT VECTOR TESTS PASSED");

// Count admission uses the same integer vectors as the Python and Go ports.
const quorum = JSON.parse(readFileSync(join(__dirname, '../../testdata/quorum-counts.json'), 'utf-8'));
const source = JSON.parse(readFileSync(VEC, 'utf-8'));
for (const c of quorum.cases) {
  const result = tally(source.action_hash, c.signatures === 'all' ? source.cases[0].signatures : [], source.pubkeys, c.threshold, c.n);
  if (result.decision !== c.decision || result.consensusCount !== c.count || (c.signatures === 'all' && c.decision === 'rejected' && result.checks.length !== 0)) {
    throw new Error(`quorum count vector failed: ${c.name}`);
  }
}
for (const value of [true, false, 1.5, NaN, Infinity, '1', null]) {
  for (const field of ['threshold', 'n']) {
    const threshold = field === 'threshold' ? value : 3;
    const n = field === 'n' ? value : 4;
    const result = tally(source.action_hash, source.cases[0].signatures, source.pubkeys, threshold as number, n as number);
    if (result.decision !== 'rejected' || result.consensusCount !== 0 || result.checks.length !== 0) {
      throw new Error(`invalid ${field} accepted: ${String(value)}`);
    }
  }
}
console.log('ALL QUORUM COUNT TESTS PASSED');
