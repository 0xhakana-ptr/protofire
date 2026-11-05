//! power/src/governors/tests.rs
//!
//! The CPU governors: the frequency each one picks from a load, and the target
//! it tracks.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::governors::*;

#[test]
fn governor_names_are_stable() {
    assert_eq!(GovernorType::Performance.name(), "performance");
    assert_eq!(GovernorType::Powersave.name(), "powersave");
    assert_eq!(GovernorType::Ondemand.name(), "ondemand");
    assert_eq!(GovernorType::Schedutil.name(), "schedutil");
    assert_eq!(GovernorType::Userspace.name(), "userspace");
}

#[test]
fn userspace_never_scales() {
    assert_eq!(
        calculate_target(GovernorType::Userspace, 50, 100_000, 400_000, 200_000),
        None
    );
}

#[test]
fn performance_always_returns_max() {
    assert_eq!(
        calculate_target(GovernorType::Performance, 0, 100_000, 400_000, 200_000),
        Some(400_000)
    );
    assert_eq!(
        calculate_target(GovernorType::Performance, 100, 100_000, 400_000, 200_000),
        Some(400_000)
    );
}

#[test]
fn powersave_always_returns_min() {
    assert_eq!(
        calculate_target(GovernorType::Powersave, 100, 100_000, 400_000, 200_000),
        Some(100_000)
    );
}

#[test]
fn schedutil_maps_load_to_frequency() {
    // Load 50% of range [100k, 400k] → 250 MHz, well within hysteresis.
    let target = calculate_target(GovernorType::Schedutil, 50, 100_000, 400_000, 200_000);
    assert_eq!(target, Some(250_000));
}

#[test]
fn schedutil_extremes_are_direct() {
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 95, 100_000, 400_000, 200_000),
        Some(400_000)
    );
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 5, 100_000, 400_000, 200_000),
        Some(100_000)
    );
}

#[test]
fn schedutil_prevents_frequency_jitter() {
    // Up-move blocked: load 14 % maps to 142 MHz, but a raise from
    // 140 MHz requires load >= 15, so the frequency holds.
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 14, 100_000, 400_000, 140_000),
        None
    );

    // Down-move blocked: load 90 % maps to 370 MHz, but a cut from
    // 400 MHz requires load < 90, so the frequency holds.
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 90, 100_000, 400_000, 400_000),
        None
    );

    // A large load drop (5%) forces the floor directly.
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 5, 100_000, 400_000, 250_000),
        Some(100_000)
    );
}

#[test]
fn ondemand_raises_frequency_on_high_load() {
    let target = calculate_target(GovernorType::Ondemand, 90, 100_000, 400_000, 200_000);
    assert!(target.is_some());
    let target = target.unwrap();
    assert!((200_000..=400_000).contains(&target));
    assert!(target > 200_000);
}

#[test]
fn ondemand_lowers_frequency_on_low_load() {
    let target = calculate_target(GovernorType::Ondemand, 10, 100_000, 400_000, 300_000);
    assert!(target.is_some());
    let target = target.unwrap();
    assert!((100_000..=300_000).contains(&target));
    assert!(target < 300_000);
}

#[test]
fn degenerate_range_returns_none() {
    assert_eq!(
        calculate_target(GovernorType::Performance, 50, 400_000, 400_000, 400_000),
        None
    );
}
