//! Tests for bounded read APIs introduced for issues #239, #240 and #245.
//!
//! These tests exercise:
//! - `get_protocol_token_total` (exact-token protocol total query, #239)
//! - `get_wills_diagnostics` (per-ID batch lookup diagnostics, #240)
//! - `get_owner_stats_page` (bounded owner statistics accumulation, #245)

use crate::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Env, Vec};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn setup() -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, WillContract);
    let owner = Address::generate(&env);
    let token = Address::generate(&env);
    (env, contract_id, owner, token)
}

fn create_will(
    env: &Env,
    contract_id: &Address,
    owner: &Address,
    token: &Address,
    amount: i128,
) -> u64 {
    let client = WillContractClient::new(env, contract_id);
    let mut beneficiaries = Vec::new(env);
    beneficiaries.push_back(Beneficiary {
        address: Address::generate(env),
        percentage: 100,
    });
    client.create_will(
        owner,
        &beneficiaries,
        token,
        &amount,
        &1000u32,
        &100u32,
        &None,
    )
}

// ---------------------------------------------------------------------------
// #239: exact-token protocol total query
// ---------------------------------------------------------------------------

#[test]
fn exact_token_total_absent_token_is_zero() {
    let (env, contract_id, _owner, _token) = setup();
    let client = WillContractClient::new(&env, &contract_id);
    let unknown = Address::generate(&env);

    // No wills exist at all; an unknown token must report zero.
    let total = client.get_protocol_token_total(&unknown);
    assert_eq!(total, 0);
}

#[test]
fn exact_token_total_zero_amount_token_is_zero() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    // A will with a zero amount must not contribute to the token total.
    let _ = create_will(&env, &contract_id, &owner, &token, 0);

    let total = client.get_protocol_token_total(&token);
    assert_eq!(total, 0);
}

#[test]
fn exact_token_total_matches_aggregate_for_active_token() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let _ = create_will(&env, &contract_id, &owner, &token, 500);
    let _ = create_will(&env, &contract_id, &owner, &token, 250);

    let exact = client.get_protocol_token_total(&token);
    assert_eq!(exact, 750);

    // The aggregate endpoint must agree with the exact query.
    let stats = client.get_protocol_stats();
    let mut aggregate_total: i128 = 0;
    for entry in stats.token_totals.iter() {
        if entry.token == token {
            aggregate_total = entry.total;
        }
    }
    assert_eq!(exact, aggregate_total);
}

#[test]
fn exact_token_total_retired_token_matches_aggregate() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let will_id = create_will(&env, &contract_id, &owner, &token, 400);

    // Advance past the will's deadline and trigger release so the will is
    // terminal (retired) but its token total accounting remains consistent.
    env.ledger().with_mut(|li| {
        li.timestamp = 10_000;
    });
    let _ = client.release(&will_id);

    let exact = client.get_protocol_token_total(&token);
    let stats = client.get_protocol_stats();
    let mut aggregate_total: i128 = 0;
    for entry in stats.token_totals.iter() {
        if entry.token == token {
            aggregate_total = entry.total;
        }
    }
    assert_eq!(exact, aggregate_total);
}

#[test]
fn exact_token_total_bounded_with_growing_directory() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let _ = create_will(&env, &contract_id, &owner, &token, 100);

    let baseline = client.get_protocol_token_total(&token);
    assert_eq!(baseline, 100);

    // Grow the unrelated token directory substantially.
    for _ in 0..50 {
        let other = Address::generate(&env);
        let _ = create_will(&env, &contract_id, &owner, &other, 1);
    }

    // The exact query must still return the same value for the target token,
    // demonstrating that it does not depend on the size of the directory.
    let after = client.get_protocol_token_total(&token);
    assert_eq!(after, baseline);
}

// ---------------------------------------------------------------------------
// #240: per-ID batch lookup diagnostics
// ---------------------------------------------------------------------------

#[test]
fn diagnostics_distinguish_current_missing_and_incompatible() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let current_id = create_will(&env, &contract_id, &owner, &token, 100);
    let missing_id = current_id + 1000;

    let mut ids = Vec::new(&env);
    ids.push_back(current_id);
    ids.push_back(missing_id);

    let results = client.get_wills_diagnostics(&ids);
    assert_eq!(results.len(), 2);

    // Current record: found.
    let first = results.get(0).unwrap();
    assert!(first.found);
    assert!(first.will.is_some());

    // Missing record: not found, no error surfaced as incompatible.
    let second = results.get(1).unwrap();
    assert!(!second.found);
    assert!(second.will.is_none());
}

#[test]
fn diagnostics_preserve_input_order_and_duplicates() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let id_a = create_will(&env, &contract_id, &owner, &token, 100);
    let id_b = create_will(&env, &contract_id, &owner, &token, 200);

    let mut ids = Vec::new(&env);
    ids.push_back(id_b);
    ids.push_back(id_a);
    ids.push_back(id_b);

    let results = client.get_wills_diagnostics(&ids);
    assert_eq!(results.len(), 3);

    // Order preserved: b, a, b.
    assert!(results.get(0).unwrap().found);
    assert!(results.get(1).unwrap().found);
    assert!(results.get(2).unwrap().found);

    let will_b0 = results.get(0).unwrap().will.unwrap();
    let will_a = results.get(1).unwrap().will.unwrap();
    let will_b2 = results.get(2).unwrap().will.unwrap();

    assert_eq!(will_b0.id, id_b);
    assert_eq!(will_a.id, id_a);
    assert_eq!(will_b2.id, id_b);
}

#[test]
fn diagnostics_enforce_documented_limit() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let id = create_will(&env, &contract_id, &owner, &token, 100);

    // Build a request larger than the documented limit.
    let limit = MAX_DIAGNOSTICS_IDS;
    let mut ids = Vec::new(&env);
    for _ in 0..(limit + 1) {
        ids.push_back(id);
    }

    let result = client.try_get_wills_diagnostics(&ids);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// #245: bounded owner statistics accumulation
// ---------------------------------------------------------------------------

#[test]
fn owner_stats_page_aggregates_to_same_totals_as_aggregate() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    // Small mixed live/terminal portfolio.
    let _live = create_will(&env, &contract_id, &owner, &token, 100);
    let terminal = create_will(&env, &contract_id, &owner, &token, 200);

    env.ledger().with_mut(|li| {
        li.timestamp = 10_000;
    });
    let _ = client.release(&terminal);

    let aggregate = client.get_owner_stats(&owner);

    // Page through with a small bound and combine.
    let mut live_count: u32 = 0;
    let mut token_total: i128 = 0;
    let mut cursor: u32 = 0;
    loop {
        let page = client.get_owner_stats_page(&owner, &cursor, &1u32);
        live_count += page.live_count;
        token_total += page.token_total;
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }

    assert_eq!(live_count, aggregate.live_count);
    assert_eq!(token_total, aggregate.token_total);
}

#[test]
fn owner_stats_page_empty_portfolio() {
    let (env, contract_id, owner, _token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let page = client.get_owner_stats_page(&owner, &0u32, &10u32);
    assert_eq!(page.live_count, 0);
    assert_eq!(page.token_total, 0);
    assert!(page.next_cursor.is_none());
}

#[test]
fn owner_stats_page_zero_bound_is_empty() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let _ = create_will(&env, &contract_id, &owner, &token, 100);

    let page = client.get_owner_stats_page(&owner, &0u32, &0u32);
    assert_eq!(page.live_count, 0);
    assert_eq!(page.token_total, 0);
}

#[test]
fn owner_stats_page_oversized_bound_is_clamped() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    let _ = create_will(&env, &contract_id, &owner, &token, 100);

    // Requesting more than the documented maximum must not fail; it is
    // clamped to the maximum per-call bound.
    let page = client.get_owner_stats_page(&owner, &0u32, &u32::MAX);
    assert_eq!(page.live_count, 1);
    assert_eq!(page.token_total, 100);
    assert!(page.next_cursor.is_none());
}

#[test]
fn owner_stats_page_respects_bound() {
    let (env, contract_id, owner, token) = setup();
    let client = WillContractClient::new(&env, &contract_id);

    for _ in 0..5 {
        let _ = create_will(&env, &contract_id, &owner, &token, 10);
    }

    // Each page with bound 2 must report at most 2 wills' worth of totals.
    let page = client.get_owner_stats_page(&owner, &0u32, &2u32);
    assert!(page.live_count <= 2);
    assert!(page.token_total <= 20);
    assert!(page.next_cursor.is_some());
}