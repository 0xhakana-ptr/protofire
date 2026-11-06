//! power/src/governors/mod.rs
//!
//! CPU frequency scaling governors.

// Type definitions

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorType {
    Performance, // max performance: always run at max frequency
    Powersave,   // power saving: always run at min frequency
    Ondemand,    // on-demand: scale up on load, down slowly
    Schedutil,   // scheduler load: direct mapping
    Userspace,   // user-controlled: never scales automatically
}

impl GovernorType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Powersave => "powersave",
            Self::Ondemand => "ondemand",
            Self::Schedutil => "schedutil",
            Self::Userspace => "userspace",
        }
    }
}

// Ondemand parameters

const ONDEMAND_UP_THRESHOLD: u8 = 80; // scale up when load > 80%
const ONDEMAND_DOWN_THRESHOLD: u8 = 25; // scale down when load < 25%
const ONDEMAND_STEP_PERCENT: u32 = 10; // step up by 10% each time

// Schedutil parameters

const SCHEDUTIL_UP_RATE: u8 = 15; // scale up when load rises 15%
const SCHEDUTIL_DOWN_RATE: u8 = 10; // scale down when load drops 10%

// Core logic

/// Compute the target frequency for a governor.
///
/// `min_freq`/`max_freq`/`current` are in KHz; `load` is the CPU-busy ratio
/// in 0..=100.  Returns `None` when no frequency change is warranted (or for
/// `Userspace`, which never scales automatically).  The caller passes the
/// current frequency as a snapshot so the pure policy logic stays
/// unit-testable.
pub fn calculate_target(
    gov: GovernorType,
    load: u8,
    min_freq: u32,
    max_freq: u32,
    current: u32,
) -> Option<u32> {
    if max_freq <= min_freq {
        return None;
    }
    let load = load.min(100);

    match gov {
        GovernorType::Performance => Some(max_freq),
        GovernorType::Powersave => Some(min_freq),
        GovernorType::Userspace => None,

        GovernorType::Ondemand => {
            // Sampling throttle lives in the scheduler: `update_policy` calls
            // this at 1 Hz.
            if load >= ONDEMAND_UP_THRESHOLD {
                // Scale up quickly
                let step =
                    ((max_freq - min_freq) as u64 * ONDEMAND_STEP_PERCENT as u64 / 100) as u32;
                let step = step.max(50_000); // at least 50 MHz
                Some(current.saturating_add(step).min(max_freq))
            } else if load <= ONDEMAND_DOWN_THRESHOLD {
                // Scale down slowly
                let step =
                    ((current - min_freq) as u64 * ONDEMAND_STEP_PERCENT as u64 / 100 / 2) as u32;
                let step = step.max(25_000); // at least 25 MHz
                Some(current.saturating_sub(step).max(min_freq))
            } else {
                None
            }
        }

        GovernorType::Schedutil => {
            // Map the scheduler load directly to a frequency
            let target_freq = min_freq + ((max_freq - min_freq) as u64 * load as u64 / 100) as u32;

            // Extreme loads set the bounds directly
            match load {
                95..=100 => return Some(max_freq),
                0..=5 => return Some(min_freq),
                _ => {}
            }

            // Prevent frequency jitter: add hysteresis
            if target_freq > current {
                // Scale up: load must be high enough
                if load >= SCHEDUTIL_UP_RATE {
                    Some(target_freq)
                } else {
                    None
                }
            } else if target_freq < current {
                // Scale down: load must be low enough
                if load < 100 - SCHEDUTIL_DOWN_RATE {
                    Some(target_freq)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

// Tests

#[cfg(test)]
mod tests;
