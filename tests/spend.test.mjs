import test from "node:test";
import assert from "node:assert/strict";
import { estimateMicroUsd } from "../api/generate.mjs";

test("token counts convert to integer micro-USD at the model's price", () => {
  // 1M input at $0.25/Mtok + 1M output at $1.5/Mtok = $1.75 = 1,750,000 µ$
  assert.equal(estimateMicroUsd(1_000_000, 1_000_000, "gemini-3.1-flash-lite"), 1_750_000);
  // A typical organize call: ~3K in, ~500 out ≈ 1,500 µ$ ($0.0015)
  assert.equal(estimateMicroUsd(3000, 500, "gemini-3.1-flash-lite"), 1500);
});

test("unknown models fall back to the default price instead of free", () => {
  assert.equal(
    estimateMicroUsd(1000, 1000, "gemini-9000"),
    estimateMicroUsd(1000, 1000, "gemini-3.1-flash-lite")
  );
});

test("rounds up so spend never undercounts", () => {
  assert.equal(estimateMicroUsd(1, 0, "gemini-3.1-flash-lite"), 1);
});
