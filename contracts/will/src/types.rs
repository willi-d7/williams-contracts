use soroban_sdk::{contracttype, Address, Bytes, Map, Symbol, Vec};

/// How a beneficiary's share of a will is calculated.
///
/// - `Percentage(bp)` is a share expressed in basis points (1 bp = 0.01 %) of
///   whatever balance remains *after* every `FixedAmount` beneficiary on the
///   same will has been paid, applied to **every** token the will holds. All
///   `Percentage` shares on a will must sum to exactly 10,000 (100 % of the
///   remainder).
/// - `FixedAmount(amount)` entitles the beneficiary to exactly `amount` of
///   the will's **primary token** ([`Will::token`], the first entry of the
///   `tokens` list passed to `create_will`), paid before any percentage-based
///   split is computed. The sum of all `FixedAmount` entries on a will can
///   never exceed that token's balance (enforced by
///   `assert_valid_allocations`).
///
/// # Fixed amounts and multi-token wills
///
/// A `FixedAmount` is a claim on one specific token, not on "the will's
/// value". A will holding two tokens and a `FixedAmount(100)` beneficiary
/// pays that beneficiary 100 units of the primary token **in total** — the
/// secondary token's balance is not drawn on to satisfy it, and is instead
/// split among the percentage beneficiaries or, if there are none, refunded
/// to the owner at release time (issue #384, #383).
///
/// A single will may mix both kinds: e.g. one beneficiary with a fixed
/// amount and the rest splitting the remainder by percentage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Allocation {
    Percentage(u32),
    FixedAmount(i128),
}

/// A single beneficiary entry: an address and how much of the will's balance
/// it is entitled to receive when the inheritance is released.
///
/// See [`Allocation`] for how `allocation` is interpreted and validated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Beneficiary {
    pub address: Address,
    pub allocation: Allocation,
}

/// Consent status for a named guardian.
///
/// A guardian must explicitly accept before they can cast a `guardian_trigger`
/// vote. The owner may also reject a guardian's acceptance.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianConsent {
    /// Guardian has been named but has not yet responded.
    Pending = 0,
    /// Guardian has accepted the role and may vote.
    Accepted = 1,
    /// Guardian has declined the role (can be reset to Pending by the owner via reset_guardian_consent).
    Rejected = 2,
}

/// A guardian definition used by the weighted-guardian API.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianSpec {
    pub address: Address,
    pub weight: u32,
}

/// A guardian entry: an address paired with a vote weight and consent status.
///
/// Guardians with higher weights count for more when reaching quorum.
/// If all guardians have weight 1, the threshold is a simple majority count.
/// A guardian must accept their role via `accept_guardian_role` before they
/// can vote in `guardian_trigger`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Guardian {
    pub address: Address,
    pub weight: u32,
    pub consent: GuardianConsent,
}

/// A privacy-preserving beneficiary entry (issue #46).
///
/// The commitment is `sha256(sha256(xdr(beneficiary)) || salt)`. Here
/// `xdr(beneficiary)` is the Stellar `ScVal::Address` encoding returned by
/// `Address::to_xdr`, and `salt` is exactly 32 random bytes. The beneficiary
/// reveals the 64-byte address digest and salt to claim the reserved share.
///
/// See SECURITY.md for Rust and JavaScript examples and test vectors.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashedBeneficiary {
    /// 32-byte SHA-256 digest of the address fingerprint followed by the salt.
    pub commitment: Bytes,
    /// Percentage of the will's balance this beneficiary receives.
    pub percentage: u32,
    /// Whether this hashed beneficiary has already been claimed.
    pub claimed: bool,
}

/// Lifecycle state of a will.
///
/// ```text
/// create_will --(confirmation delay)--> PendingConfirmation
/// create_will --(no delay)------------> Active
///     |                                    |
///     |--(confirm_will)--> Active <--------+
///     |
///     |   Active --(missed check-in / trigger_will)--> Triggered
///     |      |                                            |
///     |      |--(cancel_will)--> Cancelled               |--(grace period expires)--> Released
///     |      |                                            |    |
///     |      |--(emergency_checkin)--> Active            |    |--(close_will)--> Settled
///     |      |--(guardian_cancel_trigger)--> Active       |    |
///     |      |--(guardian_trigger quorum)--> Released ----+    |
///     |                                                          |
///     +--(cancel_will)--> Cancelled <--(cancel_will, PendingConfirmation)
///
/// PendingConfirmation --(cancel_will)--> Cancelled
/// ```
///
/// Every arrow above is a real transition performed by the named entry point;
/// `check_in` and the other settings updates do not change `status`.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WillStatus {
    /// The will has just been created and is waiting for the owner to confirm
    /// it within the confirmation window (issue #43). No check-in clock runs
    /// while a will is in this state.
    PendingConfirmation,
    /// The will is funded and the owner is checking in on schedule.
    Active,
    /// The owner missed a check-in deadline; the grace period is running.
    Triggered,
    /// The grace period expired (or guardians reached quorum) and funds were
    /// distributed to beneficiaries (lump sum or final vested claim).
    Released,
    /// The owner cancelled the will and withdrew the remaining balance.
    Cancelled,
    /// A Released will that has been explicitly closed/archived by the owner.
    Settled,
}

/// A single failed-payout retry request submitted to
/// [`batch_retry_failed_payouts`](crate::WillContract::batch_retry_failed_payouts).
///
/// Each entry names the `(will_id, token, recipient)` tuple whose failed
/// payout should be retried. The amount is read from storage at retry time so
/// callers need not re-specify it, keeping the request compact.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailedPayoutRequest {
    /// The will that recorded the failed payout.
    pub will_id: u64,
    /// The token that was to be paid out.
    pub token: Address,
    /// The recipient that was to receive the payout.
    pub recipient: Address,
}

/// Aggregate protocol statistics that can be queried directly on-chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenLockedBalance {
    /// The token contract address.
    pub token: Address,
    /// The total amount of this token that is currently locked in active wills.
    pub total_locked: i128,
}

/// Aggregate protocol statistics that can be queried directly on-chain.
///
/// # Consistency invariant
///
/// These counters are maintained incrementally by every entry point that
/// creates a will, moves funds in or out of one, or moves it into a terminal
/// state. They are assumed to always equal what
/// [`WillContract::audit_protocol_stats`](crate::WillContract::audit_protocol_stats)
/// recomputes from storage:
///
/// - `active_will_count` == number of wills in `PendingConfirmation`,
///   `Active` or `Triggered` status.
/// - each `total_locked` == sum of that token's entry in `Will::balances`
///   across those same wills.
///
/// # Successful operations only
///
/// The stats reflect only *successful* state transitions. A Soroban
/// invocation that fails (panics or returns a contract error) rolls back
/// every storage write it made, so a failed operation cannot be counted
/// on-chain. Failure rates must be measured off-chain from transaction
/// results.
///
/// # Discrete bounded storage architecture (Issue #22)
///
/// On-chain locked totals are stored in individual storage entries under
/// `DataKey::TotalLocked(Address)`, decoupling per-token balance updates from
/// vector-scanning overhead. `total_locked_by_token` is assembled at query
/// time for backward-compatible off-chain reporting.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolStats {
    /// The number of wills that are still in a non-terminal state.
    pub active_will_count: u64,
    /// Locked balances by token for all currently active wills.
    pub total_locked_by_token: Vec<TokenLockedBalance>,
}

/// Result of comparing the incrementally-maintained [`ProtocolStats`] against
/// a fresh recomputation from every will's stored balance (#441, #498).
///
/// Returned by `WillContract::audit_protocol_stats`. `consistent` is the
/// single field most callers need; `stored`/`computed` are kept alongside it
/// so a caller who finds `consistent == false` can pinpoint exactly which
/// counter (and, within `total_locked_by_token`, which token) drifted,
/// without a second call.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolStatsAudit {
    /// The stats currently persisted in instance storage, maintained
    /// incrementally by every entry point that touches a will.
    pub stored: ProtocolStats,
    /// The stats freshly recomputed by scanning every will's stored balance
    /// (see `storage::recompute_protocol_stats`) — the ground truth this
    /// audit checks `stored` against.
    pub computed: ProtocolStats,
    /// True when `stored` and `computed` agree on `active_will_count` and
    /// every token's `total_locked`.
    pub consistent: bool,
}

/// Aggregate statistics for the wills owned by a single address (issue #447).
///
/// Returned by `get_owner_stats` so clients can show ownership totals
/// alongside a paginated `get_wills_by_owner` listing without walking every
/// page themselves.
///
/// # Portfolio-size limitation
///
/// `get_owner_stats` loads **every** will in the owner's discovery index in a
/// single call, so its read footprint grows with the owner's whole portfolio
/// (the production index cap is `storage::MAX_WILLS_PER_INDEX`). Callers with
/// large portfolios should prefer the bounded, paginated
/// [`OwnerStatsPage`] API (`get_owner_stats_page`), which loads at most a
/// documented number of wills per call and returns partial totals a client can
/// combine off-chain. The aggregate API is retained unchanged for
/// compatibility.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerStats {
    /// Total number of wills indexed under this owner, in any status.
    pub total_wills: u32,
    /// Number of those wills that are still non-terminal
    /// (`PendingConfirmation`, `Active` or `Triggered`).
    pub active_wills: u32,
    /// Locked balances by token, summed across the owner's non-terminal wills.
    pub total_locked_by_token: Vec<TokenLockedBalance>,
}

/// One page of an owner's aggregate statistics, returned by
/// `get_owner_stats_page` (issue #245).
///
/// A page covers a contiguous slice of the owner's discovery index, so a
/// client can walk the whole portfolio in bounded steps and combine the
/// partial [`OwnerStats`] values into the same totals the aggregate
/// `get_owner_stats` call would return for an unchanged small portfolio.
///
/// # Per-call ID bound
///
/// Each call loads at most the requested number of wills from the discovery
/// index, clamped to `storage::MAX_WILLS_PER_INDEX`. The bound applies to the
/// number of index entries read, not to the number of wills that end up
/// counted: entries whose record is missing or incompatible are still read
/// (and therefore consume the bound) but contribute nothing to the totals.
///
/// # Cross-call consistency policy
///
/// Pages are **not** a snapshot: there is no isolation between calls. Each
/// page is computed from the discovery index and will records as they exist
/// at the time of that call, so:
///
/// - a will that changes lifecycle state between two page reads is counted
///   according to its state when its page was read;
/// - a will created or removed between two page reads may be counted in a
///   later page, or not at all, depending on where it lands relative to the
///   cursor;
/// - a migrated discovery index is counted by its **current** contents — the
///   cursor is a position in the index as it exists on that call, not a
///   stable identifier of a particular will.
///
/// Clients that need a point-in-time total should read all pages and treat
/// the result as approximate, or use the aggregate `get_owner_stats` call.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerStatsPage {
    /// Partial totals for the wills covered by this page.
    pub stats: OwnerStats,
    /// Cursor to pass to fetch the next page, or `None` when this is the
    /// last page.
    pub next_cursor: Option<u64>,
    /// True when this page reaches the end of the owner's discovery index,
    /// i.e. no further pages exist. Mirrors `next_cursor.is_none()` and is
    /// provided so callers can branch on a single boolean.
    pub done: bool,
}

/// Per-ID outcome of a batch will lookup, returned by
/// `get_wills_with_diagnostics` (issue #240).
///
/// # Result mapping
///
/// The returned vector maps **1:1** to the input `ids` vector: the result at
/// index `i` describes the lookup of `ids[i]`. Input order is preserved and
/// duplicate IDs are looked up and reported once per occurrence, so a caller
/// can zip the two vectors without any further bookkeeping.
///
/// This lets a caller distinguish an ID that does not exist ([`Self::NotFound`])
/// from one that exists but cannot be decoded by this contract version
/// ([`Self::UnsupportedSchemaVersion`]) — a distinction the permissive
/// `get_wills` lookup deliberately hides by skipping both.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillLookupResult {
    /// The will exists and was decoded successfully.
    Found(Will),
    /// No will is stored under the requested ID.
    NotFound,
    /// A will is stored under the requested ID, but it was written with a
    /// schema version this contract cannot decode. The record needs
    /// migration; it is present, not absent.
    UnsupportedSchemaVersion,
    /// The lookup failed with another declared contract error, reported by
    /// its numeric code. No unrelated private data is exposed.
    Error(u32),
}

/// Reserved: a beneficiary's claimable share in a pull-based distribution.
///
/// **Not used by the contract today.** There is no pull mode, no
/// `pull_distribution` field on [`Will`] and no `claim_share` entry point, so
/// nothing ever constructs or reads this type; distribution is push-only (see
/// the crate-level docs). It is kept only because the type is part of the
/// published contract spec (see `spec/will-v0.1.0.json`), so removing it would
/// be a breaking spec change. It is retained as a placeholder for the
/// pull-based claim feature requested in issue #11; anything reading this type
/// as a description of current behaviour is reading stale documentation
/// (#364).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimableShare {
    /// The total amount the beneficiary is entitled to claim.
    pub total: i128,
    /// The amount already claimed (0 or `total`).
    pub claimed: i128,
}

/// The full on-chain state of a single will.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Will {
    /// Unique, monotonically increasing identifier for this will.
    pub id: u64,
    /// The primary owner address. Used for backwards-compatible single-owner
    /// flows and as the refund destination on cancellation.
    pub owner: Address,
    /// Map of token contract address → amount currently locked in the will,
    /// in each token's base units. A will may hold any number of distinct
    /// SEP-41 compliant tokens simultaneously.
    pub balances: Map<Address, i128>,
    /// The token contract (e.g. a USDC Stellar Asset Contract) held by the will.
    pub token: Address,
    /// Legacy/reserved compatibility field, retained only for stored-layout
    /// and wire compatibility. It is **not** an active transfer-mode switch:
    /// no production code reads it to choose a transfer primitive, and every
    /// creation path stores `false`.
    ///
    /// Native XLM is represented by its Stellar Asset Contract address and is
    /// transferred through `token::Client` (SEP-41) exactly like any other
    /// token — there is no native-asset special case. Do not remove this field
    /// or change its serialization/layout.
    pub is_native: bool,
    /// The amount of `token` currently locked in the will, in the token's base units.
    /// A legacy mirror of `balances[token]` kept for backward compatibility;
    /// every writer that touches the primary token's balance must update both
    /// fields together until this mirror is fully removed.
    pub balance: i128,
    /// The visible beneficiaries of the will and how each is allocated.
    ///
    /// Entries may mix two allocation kinds (see [`Allocation`]), so this
    /// list does **not** always describe a split of 10,000 basis points.
    /// `assert_valid_allocations` enforces, on every write:
    /// - every `Allocation::Percentage(bp)` is non-zero, and the `Percentage`
    ///   entries together sum to exactly 10,000 basis points. This check only
    ///   applies when at least one `Percentage` entry is present — a
    ///   `FixedAmount`-only list has no percentage total to check;
    /// - every `Allocation::FixedAmount(amount)` is positive, and their sum
    ///   does not exceed the will's **primary-token** balance
    ///   ([`Will::token`]). A sum *below* that balance is allowed, since the
    ///   headroom is reserved for a later `add_hashed_beneficiary` and is
    ///   otherwise refunded to the owner at release;
    /// - no address appears twice ([`crate::WillError::DuplicateBeneficiary`]).
    ///
    /// So: percentages must sum to 10,000 when present, while fixed amounts
    /// are bounded above by the primary-token balance and need not account for
    /// the whole of it.
    pub beneficiaries: Vec<Beneficiary>,
    /// Privacy-preserving beneficiaries registered by commitment hash (issue #46).
    ///
    /// Each `HashedBeneficiary::percentage` is expressed in the same basis
    /// points (1 bp = 0.01 %, 10,000 = 100 %) as `Allocation::Percentage`, not
    /// in whole percent. They are withheld from the visible beneficiaries'
    /// share of each token and are claimable later via `reveal_and_claim` once
    /// the pre-image is revealed.
    ///
    /// `assert_valid_percentages` requires the visible `Percentage` entries
    /// plus every hashed percentage to total at most 10,000 basis points — the
    /// hashed entries take priority, and the remainder is what the visible
    /// percentage split divides. Unlike `beneficiaries`, a will with no
    /// percentage beneficiaries at all is legal, and its leftover primary-token
    /// balance is refunded to the owner on release.
    pub hashed_beneficiaries: Vec<HashedBeneficiary>,
    /// How many days the owner may go without checking in before the will
    /// can be triggered.
    pub checkin_period_days: u64,
    /// How many days after being triggered the owner has to prove they are
    /// alive (via `emergency_checkin`) before inheritance can be released.
    pub grace_period_days: u64,
    /// Unix timestamp (seconds) of the owner's last check-in.
    pub last_checkin: u64,
    /// Unix timestamp (seconds) until which re-triggering is blocked after an
    /// `emergency_checkin` (#104). `0` for newly created, cloned, split and
    /// legacy-migrated wills, which have no cooldown pending yet. This is the
    /// cooldown deadline, distinct from `last_checkin + checkin_period_days`
    /// (the missed check-in deadline used to start the grace period).
    pub trigger_cooldown_until: u64,
    /// Unix timestamp (seconds) at which the grace period started, if the
    /// will is triggered. This is the missed check-in deadline
    /// (`last_checkin + checkin_period_days`), not the time `trigger_will`
    /// was called, so the release time does not drift with keeper delays.
    pub trigger_time: Option<u64>,
    /// Unix timestamp (seconds) by which the owner must call `confirm_will`
    /// to move from `PendingConfirmation` to `Active` (issue #43).
    /// `None` once the will is confirmed or if no delay was requested.
    pub confirmation_deadline: Option<u64>,
    /// Current lifecycle state of the will.
    pub status: WillStatus,
    /// Optional guardians (up to 3) who may force an early release
    /// via a weight-based quorum using `guardian_trigger`.
    pub guardians: Vec<Guardian>,
    /// Accumulated weight of live guardian votes cast in the current cycle.
    /// Recomputed from the current guardian list on every vote (issue #453),
    /// so votes from removed, rejected or expired guardians are never counted.
    /// Accumulated weight of guardian votes cast in the current cycle.
    /// Quorum is reached when this reaches (or exceeds) `guardian_threshold`;
    /// see [`Will::guardian_threshold`] for the comparison and
    /// [`Will::guardian_votes`] for the corresponding head count.
    pub guardian_vote_weight: u32,
    /// Number of distinct guardians on the current list with a live vote to
    /// trigger the current guardian-release cycle. Never exceeds
    /// `guardians.len()`. Release triggers when this reaches `guardian_threshold`.
    pub guardian_votes: u32,
    /// Accumulated weight of guardian votes cast toward cancelling the current
    /// trigger. Reaches quorum at `guardian_threshold`, returning the will to
    /// `Active` and resetting the check-in deadline.
    pub guardian_cancel_vote_weight: u32,
    /// Number of distinct guardians who have voted to cancel the current trigger.
    pub guardian_cancel_votes: u32,
    /// The weight that a guardian quorum must accumulate to take effect.
    ///
    /// This is compared against the **accumulated vote weight**
    /// ([`Will::guardian_vote_weight`], and
    /// [`Will::guardian_cancel_vote_weight`] for the cancel path), not against
    /// [`Will::guardian_votes`]. With every guardian weighted 1 the two are
    /// equivalent, but a weighted guardian list installed via
    /// `update_guardians_weighted` lets a single guardian of weight 3 satisfy a
    /// threshold of 3 on its own.
    ///
    /// It is validated in `1..=total_weight`, where `total_weight` is
    /// `guardians.len()` for the unweighted lists that `create_will`,
    /// `update_guardians` and `update_will_settings` produce, and the sum of
    /// the supplied weights for a weighted list. Shrinking a non-empty guardian
    /// list below the stored threshold is rejected, since the quorum would
    /// become unreachable. An empty guardian list disables the mechanism and no
    /// threshold is checked.
    pub guardian_threshold: u32,
    /// Unix timestamp (seconds) of the last guardian-list change.
    /// `guardian_trigger` is only effective after a cooldown period has
    /// elapsed since this timestamp, preventing a compromised owner from
    /// swapping guardians right before a malicious action.
    pub guardian_list_updated_at: u64,
    /// Additional grace days granted via `request_grace_extension` (#102).
    /// Stacks on top of the will's base `grace_period_days`; capped at
    /// `MAX_GRACE_EXTENSION_DAYS` to prevent indefinite stalling.
    pub grace_extension_days: u64,
    /// Schema version for this will. Used to track which contract version
    /// wrote this state and enable forward/backward compatible migrations.
    /// See `migration.rs` and the "Storage schema versioning" section of
    /// CONTRIBUTING.md for how new versions are introduced.
    pub schema_version: u32,
    /// Optional keeper bounty in basis points (e.g., 10 = 0.1%).
    /// When set, a portion of the inheritance is paid to callers who trigger
    /// or release the will (not to the owner). Defaults to 0.
    pub keeper_bounty_bps: u32,
    /// Which token the keeper bounty is paid from (#109).
    ///
    /// `None` — the default, and what every creation path stores — deducts
    /// the bounty proportionally from **every** token the will holds: each
    /// token contributes `floor(balance * keeper_bounty_bps / 10_000)` of
    /// itself. A keeper's incentive therefore scales with the estate's whole
    /// value instead of an arbitrarily chosen first token: an estate holding
    /// 1 XLM and 100,000 USDC pays 1% of each, not 1% of the XLM alone.
    ///
    /// `Some(token)` concentrates the whole bounty on that one token, so the
    /// owner can target the asset keepers actually want (typically the native
    /// asset, so the bounty covers the keeper's gas). The token must be one
    /// the will holds; if its bounty share rounds to zero, `distribute`
    /// falls back to the proportional split so a dust-sized target can never
    /// leave the keeper unpaid while the will holds value elsewhere.
    ///
    /// Set through [`crate::WillContract::set_keeper_bounty_token`].
    pub keeper_bounty_token: Option<Address>,
    /// Optional delegate address that may call `check_in` on the owner's
    /// behalf. `None` means only the owner can check in.
    pub delegate: Option<Address>,
}

/// A page of wills returned by a filtered, paginated query (#455).
///
/// Carries the total number of matching wills so callers know how many
/// results exist in all, and an explicit `next_cursor` so they never have to
/// infer "more pages?" from the page length.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WillPage {
    /// The wills on this page, in ascending id order.
    pub wills: Vec<Will>,
    /// Total number of wills matching the filter across all pages.
    pub total_count: u32,
    /// Cursor to pass to fetch the next page, or `None` if this is the last page.
    pub next_cursor: Option<u64>,
}

/// Reasons a guardian can provide when casting a trigger vote.
///
/// # Trustless Consensus Model & Informational Metadata
///
/// **Important**: `GuardianVoteReason` is purely **informational metadata**.
/// There is **no on-chain consensus requirement** or agreement check among
/// voting guardians. Two or more guardians can cast trigger votes with conflicting
/// reasons (e.g. Guardian A votes `Deceased` while Guardian B votes `Incapacitated`
/// or `Other`), and quorum is reached immediately once the accumulated vote weight
/// satisfies the threshold without requiring agreement on the reason.
///
/// The contract enforces threshold-based authorization, not semantic consensus
/// over the real-world condition of the owner.
///
/// ## Off-Chain Auditing Patterns
///
/// Because on-chain consensus on reasons is deliberately not enforced, off-chain
/// indexers, legal executors, and auditing systems should:
/// 1. Query all cast guardian votes and reasons via [`crate::WillContract::get_guardian_votes`]
///    or individual votes via [`crate::WillContract::get_guardian_vote_status`].
/// 2. Audit the reason metadata for conflicting claims across guardians.
/// 3. Flag any discrepancies (e.g. conflicting `Deceased` vs `Unreachable` votes)
///    for manual inspection or off-chain legal verification before taking irrevocable
///    real-world legal actions.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianVoteReason {
    /// The owner is confirmed deceased.
    Deceased = 0,
    /// The owner is incapacitated and unable to check in.
    Incapacitated = 1,
    /// The owner cannot be reached or located.
    Unreachable = 2,
    /// Any other reason not covered by the above.
    Other = 3,
}

/// Public status of a guardian's vote to **cancel** the current trigger
/// (issue #214).
///
/// This is the cancellation counterpart of the trigger-vote inspection
/// returned by `get_guardian_vote_status`, and is deliberately a distinct
/// type so a caller can never confuse a release vote with a cancel vote.
/// It is read-only: querying it requires no authorization and mutates no
/// state.
///
/// A vote only counts toward the live cancellation tally while it is
/// unexpired and the guardian is still on the will's guardian list with
/// `GuardianConsent::Accepted` consent — exactly the rules
/// `recount_guardian_cancel_votes` applies. `has_voted` reports whether a
/// record exists at all; `is_live` reports whether that record currently
/// counts toward quorum.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianCancelVoteStatus {
    /// Whether the guardian has a stored cancellation vote record for the
    /// current trigger cycle, live or expired.
    pub has_voted: bool,
    /// Whether the stored vote is currently counted toward the cancellation
    /// quorum (unexpired, guardian still listed and accepted).
    pub is_live: bool,
    /// Unix timestamp (seconds) at which the stored vote was cast, if any.
    pub voted_at: Option<u64>,
    /// Unix timestamp (seconds) at which the stored vote expires, if any.
    /// `None` when no vote record exists.
    pub expires_at: Option<u64>,
    /// The guardian's vote weight as currently configured on the will, or 0
    /// if the guardian is no longer listed.
    pub weight: u32,
}

/// A single entry in a will's on-chain audit trail, recording one status
/// transition. The full history of a will can be reconstructed by reading
/// all entries in insertion order.
#[contracttype]
#[derive(Clone, Debug)]
pub struct WillStatusTransition {
    /// The will this transition belongs to.
    pub will_id: u64,
    /// The status before the transition.
    pub from_status: WillStatus,
    /// The status after the transition.
    pub to_status: WillStatus,
    /// Unix timestamp (seconds) when the transition occurred.
    pub timestamp: u64,
    /// The address that initiated the transition, or the contract address
    /// for transitions triggered by anyone (e.g. `trigger_will`,
    /// `release_inheritance`).
    pub actor: Address,
    /// A short label describing what caused the transition
    /// (e.g. "create", "checkin", "trigger", "release").
    pub action: Symbol,
    /// Monotonically increasing sequence number, unique per will and
    /// assigned in append order by `storage::append_history` (#500).
    ///
    /// Unlike an entry's position in the retained trail -- which shifts
    /// whenever `storage::MAX_HISTORY_ENTRIES` trims the oldest entry, so the
    /// same index can silently point at a different, newer entry over time --
    /// `seq` never changes once assigned. A caller that stores a `seq` it has
    /// already seen can detect a gap (entries trimmed out from under it)
    /// instead of misreading a shifted position as unchanged, which is what
    /// made `check_in`/`emergency_checkin` history reads stale under
    /// `paginate_history`'s positional cursor.
    pub seq: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_vote_reason_discriminants() {
        assert_eq!(GuardianVoteReason::Deceased as u32, 0);
        assert_eq!(GuardianVoteReason::Incapacitated as u32, 1);
        assert_eq!(GuardianVoteReason::Unreachable as u32, 2);
        assert_eq!(GuardianVoteReason::Other as u32, 3);
    }
}
