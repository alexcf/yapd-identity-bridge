import assert from "node:assert/strict";
import test from "node:test";
import { mergeExternalClients, mergeExternalAliases, liveExternalDevices, type IdentityDevice } from "./identity-provider";

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
test("metric-only identity is not presented as a bound DHCP lease", () => {
  const observed: IdentityDevice = { ...device, isStatic: null, active: null, identityKind: "observation",
    sources: [{ id: "metrics", type: "prometheus", retrievedAt: new Date().toISOString(), status: "fresh" }] };
  const [row] = mergeExternalClients([], [observed], new Map(), baseline, false, "Prometheus");
  assert.ok(row?.tags.includes("Observed identity"));
  assert.ok(row?.tags.includes("Source: prometheus"));
  assert.ok(!row?.tags.includes("Dynamic lease"));
  assert.ok(row?.comment?.includes("not verified"));
  assert.equal(row?.numQueries, 0);
});
test("observational aliases preserve existing query names", () => {
  const observed: IdentityDevice = { ...device, identityKind: "observation" };
  const aliases = mergeExternalAliases(new Map([[device.ips[0]!, "Pi-hole name"]]), [observed], new Map());
  assert.equal(aliases.get(device.ips[0]!), "Pi-hole name");
});
test("a cached source stays visibly stale when another provider refreshes", () => {
  const [row] = mergeExternalClients([], [{ ...device, stale: true }], new Map(), baseline, false);
  assert.ok(row?.tags.includes("DHCP data stale"));
});
test("DHCP observation IP expires even when its collector or the worker has stopped", () => {
  const now = Date.now();
  const observed: IdentityDevice = { ...device, identityKind: "observation",
    expiresAt: new Date(now + 60_000).toISOString(),
    ipExpiresAt: { [device.ips[0]!]: new Date(now - 1000).toISOString() } };
  assert.deepEqual(liveExternalDevices([observed], now)[0]?.ips, []);
  assert.equal(mergeExternalAliases(new Map(), [observed], new Map()).size, 0);
});
test("expired passive identity is removed while native Pi-hole history remains", () => {
  const observed: IdentityDevice = { ...device, expiresAt: "2000-01-01T00:00:00Z" };
  assert.deepEqual(liveExternalDevices([observed]), []);
  assert.deepEqual(mergeExternalClients([], [observed], new Map(), baseline, false), []);
});
