import assert from "node:assert/strict";
import test from "node:test";
import { mergeExternalClients, mergeExternalAliases, type IdentityDevice } from "./identity-provider";

const device: IdentityDevice = { mac: "AA:BB:CC:DD:EE:01", ips: ["172.16.0.50"], name: "laptop",
  network: "users", isStatic: false, active: true };
const baseline = { instanceId: "one", instanceName: "Pi-hole 1" };
test("DHCP-only clients are visible without invented Pi-hole activity", () => {
  const [row] = mergeExternalClients([], [device], new Map(), baseline, false);
  assert.equal(row?.alias, "laptop");
  assert.deepEqual(row?.visibleInInstances, []);
  assert.equal(row?.lastQuery, null);
  assert.ok(row?.tags.includes("Activity not correlated"));
  assert.deepEqual(row?.groupIds, []);
  assert.ok(row?.tags.includes("Policy not correlated"));
});
test("manual aliases and tags survive a DHCP hostname change", () => {
  const [row] = mergeExternalClients([], [device], new Map([[device.mac, { alias: "Alex laptop", tags: ["Work"] }]]), baseline, false);
  assert.equal(row?.alias, "Alex laptop"); assert.ok(row?.tags.includes("Work"));
});
test("query aliases follow the current DHCP binding rather than a stale IP alias", () => {
  const aliases = mergeExternalAliases(new Map([["172.16.0.50", "old device"]]), [device], new Map());
  assert.equal(aliases.get("172.16.0.50"), "laptop");
});
test("stale router data is visible as stale", () => {
  const [row] = mergeExternalClients([], [device], new Map(), baseline, true);
  assert.ok(row?.tags.includes("DHCP data stale"));
});
