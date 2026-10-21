#![cfg(test)]

//! Regression tests for issue #104: `emergency_checkin` grants a guaranteed
//! minimum active window during which `trigger_will` is rejected, preventing
//! keepers from repeatedly re-triggering estates right at expiration
//! boundaries.

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
    vec, Address, Env,
};

use crate::{
    storage, Allocation, Beneficiary, WillContract, WillContractClient, WillError, WillStatus,
};

const DAY: u64 = 86_400;

fn advance(env: &Env, days: u64) {
    env.ledger().with_mut(|l| l.timestamp += days * DAY);
}

fn setup(env: &Env) -> (WillContractClient<'_>, Address, Address) {
    let owner = Address::generate(env);
    let sac = env.register_stellar_asset_contract_v2(owner.clone());
    let token_address = sac.address();
    StellarAssetClient::new(env, &token_address).mint(&owner, &10_000_000);

    let contract_id = env.register(WillContract, ());
    let client = WillContractClient::new(env, &contract_id);
    (client, owner, token_address)
}

fn create_will(
    env: &Env,
    client: &WillContractClient<'_>,
    owner: &Address,
    token_address: &Address,
    beneficiary: &Address,
) -> u64 {
    client.create_will(
        owner,
        &vec![env, (token_address.clone(), 1_000_000_i128)],
        &vec![
            env,
            Beneficiary {
                address: beneficiary.clone(),
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

/// Drives a will into `Triggered` by advancing past the check-in period and
/// invoking `trigger_will` as a non-owner caller.
fn trigger_will(env: &Env, client: &WillContractClient<'_>, will_id: u64) {
    env.ledger().with_mut(|l| l.timestamp += 91 * DAY);
    client.trigger_will(&will_id);
}

#[test]
fn emergency_checkin_grants_cooldown_blocking_retrigger() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let owner = Address::generate(&env);
    let heir = Address::generate(&env);
    let (client, owner, token_address) = setup(&env);
    let will_id = create_will(&env, &client, &owner, &token_address, &heir);

    // Drive the will into `Triggered`.
    trigger_will(&env, &client, will_id);
    assert_eq!(client.get_will(&will_id).status, WillStatus::Triggered);

    // Owner checks in to cancel the trigger.
    client.emergency_checkin(&will_id, &owner);
    assert_eq!(client.get_will(&will_id).status, WillStatus::Active);

    // Immediately re-triggering must be rejected during the cooldown window.
    let err = client.try_trigger_will(&will_id).unwrap_err().unwrap();
    assert_eq!(
        err,
        WillError::CheckinNotDue.into(),
        "trigger_will must be rejected during the cooldown after emergency_checkin"
    );

    // The will remains Active and indexed accordingly.
    assert_eq!(client.get_will(&will_id).status, WillStatus::Active);
}

#[test]
fn cooldown_expires_after_24_hours() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let owner = Address::generate(&env);
    let heir = Address::generate(&env);
    let (client, owner, token_address) = setup(&env);
    let will_id = create_will(&env, &client, &owner, &token_address, &heir);

    trigger_will(&env, &client, will_id);
    client.emergency_checkin(&will_id, &owner);

    // Advance exactly 24 hours (the cooldown). `trigger_will` should still be
    // blocked at the boundary since `now < cooldown_until`.
    advance(&env, 1);
    let err = client.try_trigger_will(&will_id).unwrap_err().unwrap();
    assert_eq!(
        err,
        WillError::CheckinNotDue.into(),
        "trigger_will must still be rejected at the cooldown boundary"
    );

    // Advance one more second past the cooldown: trigger should now succeed.
    env.ledger().with_mut(|l| l.timestamp += 1);
    client.trigger_will(&will_id);
    assert_eq!(client.get_will(&will_id).status, WillStatus::Triggered);
}

#[test]
fn emergency_checkin_resets_checkin_deadline() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_700_000_000);

    let owner = Address::generate(&env);
    let heir = Address::generate(&env);
    let (client, owner, token_address) = setup(&env);
    let will_id = create_will(&env, &client, &owner, &token_address, &heir);

    trigger_will(&env, &client, will_id);
    client.emergency_checkin(&will_id, &owner);

    // After check-in, the will's last_checkin is refreshed so a new
    // check-in period starts from now.
    let will = client.get_will(&will_id);
    assert_eq!(will.status, WillStatus::Active);
    assert_eq!(will.last_checkin, env.ledger().timestamp());
}
