# Contract spec artifacts

This directory holds a versioned, machine-readable export of the `will`
contract's public interface: every entry-point function signature, and the
`Will`, `Beneficiary`, `Guardian`, `WillStatus`, and `WillError` types as
they are actually compiled into the deployed WASM.

Consumers such as [`williams-sdk`](https://github.com/Williams/williams-sdk)
diff their hand-maintained TypeScript types and XDR encoders against this
file to detect spec drift before it ships.

## Files

- `will-v<crate-version>.json` — one file per released crate version, named
  after the `version` field in `contracts/will/Cargo.toml` at the time of
  export (e.g. `will-v0.1.0.json`, `will-v1.3.0.json`). Never overwritten once
  published; a new crate version gets a new file. `scripts/export-spec.sh`
  enforces this: it refuses to write over an existing snapshot unless the
  explicit update mode described below is requested.
- `will-v0.1.0.json` — initial baseline specification snapshot.
- `will-v1.4.0.json` — adds `get_will_history_page_v2` with an exclusive
  `Option<u64>` cursor. To continue paging, pass the last returned
  transition's `seq` directly to v2. The existing u32 endpoint is still
  available for legacy clients.
- `will-v1.3.0.json` — specification snapshot synchronized to crate
  version `1.3.0`, adding:
  - **Multi-token & mixed-allocation create/update signatures:** `create_will`
    (`tokens: Vec<(Address, i128)>`, `guardian_threshold: u32`,
    `keeper_bounty_bps: Option<u32>`, `confirmation_delay_seconds: u64`),
    `update_periods` (`Option<u64>` parameters), and `update_will_settings`
    (`Option` parameters for atomic batch updates).
  - **Confirmation window lifecycle:** `confirm_will`,
    `refund_unconfirmed_will`.
  - **Payout resilience & keeper bounty targeting:** `retry_failed_payout`,
    `redirect_failed_payout`, `set_keeper_bounty_token`.
  - **Guardian consent & weighted quorums:** `update_guardians_weighted`,
    `accept_guardian_role`, `reject_guardian_role`, `reset_guardian_consent`,
    `guardian_cancel_trigger`, `get_guardian_vote_status`,
    `get_guardian_votes`.
  - **Estate restructuring & privacy-preserving beneficiaries:** `split_will`,
    `merge_wills`, `clone_will`, `batch_create_wills`,
    `add_hashed_beneficiary`, `reveal_and_claim`.
  - **Archival, closure & paginated queries:** `close_will`, `archive_will`,
    `get_archived_will`, `extend_archived_will_ttl`, `get_will_history_page`,
    `get_owner_stats`, `get_owner_status_page`, `audit_protocol_stats`,
    `repair_protocol_stats`, `recompute_protocol_stats_chunk`.
  - **Expanded types & error codes:** `Allocation`, `GuardianConsent`,
    `GuardianSpec`, `HashedBeneficiary`, `ProtocolStatsAudit`, `OwnerStats`,
    `WillPage`, `GuardianVoteRecord`, updated `Will` / `Beneficiary` /
    `Guardian` / `WillStatusTransition` fields, and `WillError` codes `1`–`58`
    (including `InvalidDelegate = 58`).

## Schema and validation

The schema is **additive**: it was published after the snapshots and does not
rewrite them. The bytes of `will-v0.1.0.json` and `will-v1.3.0.json` are
preserved unchanged as the historical record; only their `$schema` reference
now resolves to a real, documented schema. Both existing artifact shapes
validate against it, so no legacy exception is required.

Validate a snapshot with any draft 2020-12 JSON-schema validator, for example:

```bash
# Python (jsonschema >= 4.x)
python -m jsonschema -i spec/will-v1.3.0.json spec/will-spec.schema.json
python -m jsonschema -i spec/will-v0.1.0.json spec/will-spec.schema.json
```

Malformed documents must be rejected, including:

- a function entry missing its `inputs` array,
- unknown top-level keys or unknown shapes for `functions` / `inputs` /
  `types` entries,
- type entries that are not objects with the expected fields.

## How the artifact is produced

The JSON is derived from the compiled contract's on-chain spec, which is
embedded in the WASM as an `SCSpecEntry` XDR stream by `#[contract]` /
`#[contractimpl]` / `#[contracttype]` / `#[contracterror]`. The canonical
way to extract it is the Stellar CLI's spec-export tooling:

```bash
# Build the optimized release wasm
cargo build -p will --release --target wasm32v1-none

# Export the embedded spec as JSON bindings
stellar contract bindings json \
  --wasm target/wasm32v1-none/release/will.wasm \
  --output spec/will-v$(cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(.name=="will") | .version').json
```

`scripts/export-spec.sh` wraps the two commands above so the process is a
single, repeatable entry point (see that script for the exact invocation
used by CI).

### Overwrite policy

The script never silently replaces a published snapshot:

- **Default (write) mode** — if `spec/will-v<version>.json` already exists,
  the script exits with an error and leaves the existing file untouched. To
  publish a changed interface, bump the crate version so a new file is
  created.
- **Check mode** (`--check`) — regenerates the spec into temporary storage
  and compares it against the existing snapshot without writing anything.
  Use this in CI to detect drift.
- **Update mode** (`--update`) — the only way to regenerate an existing
  `will-v<version>.json`. It is intended solely for snapshots of an
  *unreleased* crate version (e.g. while iterating on a PR before the
  version is published). Never use it on a file that has already been
  released or attached to a GitHub Release; those are immutable history.

In every mode the export is first written to temporary storage and only
installed at the final path after it succeeds. If the export fails, the
existing snapshot's bytes are preserved unchanged.

## Update process

1. Bump `version` in `contracts/will/Cargo.toml` as part of any PR that
   changes a public entry-point signature, `Will`/`Beneficiary`/`Guardian`/
   `WillStatus`, or `WillError`.
2. Run `scripts/export-spec.sh` locally (or let the `Spec Export` CI
   workflow do it) to generate `spec/will-v<new-version>.json`. Because the
   version was bumped, this creates a new file; the script refuses to
   overwrite an existing snapshot. If you need to regenerate a snapshot for
   a version that has not been released yet, pass `--update` explicitly.
3. Commit the new file alongside the code change — do not edit or delete
   previously published spec files, they are the historical record SDK
   consumers diff against.
4. On tagged releases, the same JSON file is additionally attached to the
   GitHub Release as a downloadable artifact by
   `.github/workflows/spec-export.yml`.

This is documented in the top-level [README](../README.md#contract-spec-artifact)
as well.
