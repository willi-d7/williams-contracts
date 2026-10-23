#![cfg(test)]

//! Tests for `migrate_owner_portfolio` (#110).
//!
//! Covers:
//! - Full portfolio migration: `get_wills_by_owner` on the new address returns
//!   all ids previously owned by the old address.
//! - Old index key is pruned: `get_wills_by_owner` on the old address returns
//!   empty after migration.
//! - Per-status index migration: `get_wills_by_owner_and_status` on the new
//!   address returns the correct ids by status.
//! - Additive merge: if `new_owner` already has wills, the migrated ids are
//!   appended without duplication.
//! - Self-migration is rejected with `WillError::NotOwner`.
//! - The `"portmig"` event is emitted with the correct topic and payload.
//! - Migrating an owner with no wills is a no-op (no panic).

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
    vec, Address, Env,
};

use crate::event_test_support as ev;
use crate::{Allocation, Beneficiary, WillContract, WillContractClient, WillError, WillStatus};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Creates a minimal test environment: (env, contract_id, token_address).
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let deployer = Address::generate(&env);
    let token_address = env
        .register_stellar_asset_contract_v2(deployer.clone())
        .address();
    let contract_id = env.register(WillContract, ());

    (env, contract_id, token_address)
}

/// Mints tokens to `owner` and creates one will, returning the will id.
fn create_one_will(
    env: &Env,
    client: &WillContractClient,
    owner: &Address,
    token: &Address,
) -> u64 {
    StellarAssetClient::new(env, token).mint(owner, &1_000_000);

    client.create_will(
        owner,
        &vec![env, (token.clone(), 100_000_i128)],
        &vec![
            env,
            Beneficiary {
                address: Address::generate(env),
                allocation: Allocation::Percentage(10_000),
            },
        ],
        &90,
        &7,
        &vec![env],
        &0,
        &None,
        &0,
    )
}

// ── basic migration ───────────────────────────────────────────────────────────

/// After migrating, `get_wills_by_owner(new_owner)` contains all ids that
/// were previously owned by `old_owner`, and `get_wills_by_owner(old_owner)`
/// is empty.
#[test]
fn migrate_portfolio_moves_owner_wills_index() {
    let (env, contract_id, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    let id1 = create_one_will(&env, &client, &old_owner, &token);
    let id2 = create_one_will(&env, &client, &old_owner, &token);

    // Before migration: old_owner has both wills, new_owner has none.
    assert_eq!(client.get_wills_by_owner(&old_owner, &None, &100).len(), 2);
    assert!(client.get_wills_by_owner(&new_owner, &None, &100).is_empty());

    client.migrate_owner_portfolio(&old_owner, &new_owner);

    // After migration: new_owner holds both wills.
    let after_new = client.get_wills_by_owner(&new_owner, &None, &100);
    assert_eq!(after_new.len(), 2);
    let found_ids: std::vec::Vec<u64> = after_new.iter().map(|w| w.id).collect();
    assert!(found_ids.contains(&id1), "id1 not found in new_owner index");
    assert!(found_ids.contains(&id2), "id2 not found in new_owner index");

    // Old owner's index is cleared.
    assert!(
        client.get_wills_by_owner(&old_owner, &None, &100).is_empty(),
        "old_owner index should be empty after migration"
    );
}

// ── per-status index migration ────────────────────────────────────────────────

/// `get_wills_by_owner_and_status` on the new address returns the correct ids
/// after migration, and the old address's per-status bucket is cleared.
#[test]
fn migrate_portfolio_moves_owner_status_index() {
    let (env, contract_id, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    // create_will puts the will in PendingConfirmation; confirm it to Active.
    let id = create_one_will(&env, &client, &old_owner, &token);
    client.confirm_will(&id, &old_owner);

    // Sanity: old_owner has it under Active.
    let before =
        client.get_wills_by_owner_and_status(&old_owner, &WillStatus::Active, &None, &100);
    assert_eq!(before.len(), 1);
    assert_eq!(before.get(0).unwrap().id, id);

    client.migrate_owner_portfolio(&old_owner, &new_owner);

    // new_owner sees it under Active.
    let after_new =
        client.get_wills_by_owner_and_status(&new_owner, &WillStatus::Active, &None, &100);
    assert_eq!(after_new.len(), 1);
    assert_eq!(after_new.get(0).unwrap().id, id);

    // old_owner's Active bucket is gone.
    assert!(
        client
            .get_wills_by_owner_and_status(&old_owner, &WillStatus::Active, &None, &100)
            .is_empty(),
        "old_owner Active bucket should be empty after migration"
    );
}

// ── additive merge ────────────────────────────────────────────────────────────

/// If `new_owner` already has wills, the migrated ids are appended without
/// duplicating either party's existing entries.
#[test]
fn migrate_portfolio_additive_merge() {
    let (env, contract_id, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    // new_owner already owns one will.
    let existing_id = create_one_will(&env, &client, &new_owner, &token);
    // old_owner owns one will.
    let migrating_id = create_one_will(&env, &client, &old_owner, &token);

    client.migrate_owner_portfolio(&old_owner, &new_owner);

    let after = client.get_wills_by_owner(&new_owner, &None, &100);
    assert_eq!(after.len(), 2, "new_owner should have exactly 2 wills");
    let found_ids: std::vec::Vec<u64> = after.iter().map(|w| w.id).collect();
    assert!(
        found_ids.contains(&existing_id),
        "existing will should still be present"
    );
    assert!(
        found_ids.contains(&migrating_id),
        "migrated will should be present"
    );
}

// ── self-migration rejected ───────────────────────────────────────────────────

/// Migrating to yourself must be rejected with `WillError::NotOwner`.
#[test]
fn migrate_portfolio_self_migration_rejected() {
    let (env, contract_id, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    create_one_will(&env, &client, &owner, &token);

    let result = client.try_migrate_owner_portfolio(&owner, &owner);
    assert_eq!(
        result,
        Err(Ok(WillError::NotOwner)),
        "self-migration should be rejected with NotOwner"
    );
}

// ── event emitted ─────────────────────────────────────────────────────────────

/// `migrate_owner_portfolio` emits a `("portmig", old_owner)` event whose
/// data payload is `new_owner`.
#[test]
fn migrate_portfolio_emits_portmig_event() {
    let (env, contract_id, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    create_one_will(&env, &client, &old_owner, &token);
    client.migrate_owner_portfolio(&old_owner, &new_owner);

    // Use ev::find_event with will_id=None since the 2nd topic is an Address,
    // not a u64 will id.
    let event = ev::find_event(&env, symbol_short!("portmig"), None, "portmig");

    // Second topic should be old_owner.
    assert_eq!(
        ev::topic_address(&env, &event, 1),
        Some(old_owner.clone()),
        "portmig event second topic should be old_owner"
    );

    // Data payload should be new_owner.
    assert_eq!(
        ev::data_address(&env, &event),
        Some(new_owner.clone()),
        "portmig event data should be new_owner"
    );
}

// ── empty source portfolio ────────────────────────────────────────────────────

/// Migrating an owner with no wills is a no-op: no panic, and new_owner's
/// index remains empty.
#[test]
fn migrate_portfolio_empty_source_is_no_op() {
    let (env, contract_id, _token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let old_owner = Address::generate(&env);
    let new_owner = Address::generate(&env);

    // Neither address has any wills — should not panic.
    client.migrate_owner_portfolio(&old_owner, &new_owner);

    assert!(
        client.get_wills_by_owner(&new_owner, &None, &100).is_empty(),
        "new_owner should have no wills after migrating an empty portfolio"
    );
}
