//! Cooperative execution accounting for a single analysis thread.
//!
//! Work limits count decoder attempts and CFG/SSA/folding work, independently
//! of output pagination. Cancellation unwinds to the caller's analysis boundary
//! without invoking the panic hook; callers retain the decoded evidence they own.
use serde::Serialize;
use std::cell::RefCell;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Limits {
    pub decode_instructions: Option<u64>,
    pub ssa_work: Option<u64>,
    pub deadline_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Stop {
    pub stage: &'static str,
    pub reason: &'static str,
    pub consumed: u64,
    pub limit: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Metrics {
    pub limits: Limits,
    pub decode_instructions: u64,
    pub ssa_work: u64,
    pub stop: Option<Stop>,
}

struct State {
    started: Instant,
    metrics: Metrics,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    static TRAVERSAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Querying existing SSA uses the traversal allowance, while retaining the
/// shared deadline. Do not wrap decoding or building a new snapshot in this.
pub(crate) fn traversal<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) { TRAVERSAL.with(|v| v.set(self.0)); }
    }
    let _restore = Restore(TRAVERSAL.with(|v| v.replace(true)));
    f()
}

/// Restores the previous scope even after cancellation or a decompiler panic.
pub struct Scope(Option<State>);

impl Scope {
    pub fn new(limits: Limits) -> Self {
        Self(STATE.with(|state| {
            state.replace(Some(State {
                started: Instant::now(),
                metrics: Metrics {
                    limits,
                    ..Metrics::default()
                },
            }))
        }))
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        STATE.with(|state| {
            state.replace(self.0.take());
        });
    }
}

pub fn metrics() -> Metrics {
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .map(|s| s.metrics.clone())
            .unwrap_or_default()
    })
}

pub fn stopped() -> Option<Stop> {
    STATE.with(|state| state.borrow().as_ref().and_then(|s| s.metrics.stop.clone()))
}

fn charge(stage: &'static str, decode: bool, amount: u64) -> Result<(), Stop> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let Some(state) = state.as_mut() else {
            return Ok(());
        };
        if let Some(stop) = &state.metrics.stop {
            return Err(stop.clone());
        }
        let counters = &mut state.metrics;
        let stop = if let Some(limit) = counters
            .limits
            .deadline_ms
            .filter(|ms| state.started.elapsed() >= Duration::from_millis(*ms))
        {
            Some(Stop {
                stage,
                reason: "deadline",
                consumed: state.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                limit,
            })
        } else {
            let (consumed, limit) = if decode {
                (
                    &mut counters.decode_instructions,
                    counters.limits.decode_instructions,
                )
            } else {
                (&mut counters.ssa_work, counters.limits.ssa_work)
            };
            if let Some(limit) = limit.filter(|limit| amount > limit.saturating_sub(*consumed)) {
                Some(Stop {
                    stage,
                    reason: if decode {
                        "decode_limit"
                    } else {
                        "ssa_work_limit"
                    },
                    consumed: *consumed,
                    limit,
                })
            } else {
                *consumed = consumed.saturating_add(amount);
                None
            }
        };
        if let Some(stop) = stop {
            counters.stop = Some(stop.clone());
            Err(stop)
        } else {
            Ok(())
        }
    })
}

/// Call before each decoder invocation, including attempts that fail.
pub fn decode_step() -> Result<(), Stop> {
    charge("decode", true, 1)
}

/// Deadline checkpoint without charging a work unit.
pub fn poll(stage: &'static str) -> Result<(), Stop> {
    charge(stage, false, 0)
}

/// Charge CFG/SSA/folding work and cancel at a catch_unwind analysis boundary.
/// The Stop payload is distinct from an unexpected decompiler panic.
pub fn work(stage: &'static str, units: u64) {
    let units = TRAVERSAL.with(|traversal| if traversal.get() { 0 } else { units });
    if let Err(stop) = charge(stage, false, units) {
        std::panic::resume_unwind(Box::new(stop));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_stop_before_excess_work_and_scopes_restore_after_unwind() {
        let scope = Scope::new(Limits {
            decode_instructions: Some(2),
            ssa_work: Some(3),
            deadline_ms: None,
        });
        decode_step().unwrap();
        decode_step().unwrap();
        assert_eq!(decode_step().unwrap_err().reason, "decode_limit");
        assert_eq!(metrics().decode_instructions, 2);
        {
            let _nested = Scope::new(Limits {
                ssa_work: Some(3),
                ..Limits::default()
            });
            let result = std::panic::catch_unwind(|| {
                work("ssa", 2);
                work("fold", 2);
            });
            let stop = *result.unwrap_err().downcast::<Stop>().unwrap();
            assert_eq!(stop.stage, "fold");
            assert_eq!(stop.consumed, 2);
        }
        assert_eq!(metrics().decode_instructions, 2);
        drop(scope);
        assert!(stopped().is_none());
    }

    #[test]
    fn zero_deadline_and_zero_work_limits_are_explicit() {
        let _scope = Scope::new(Limits {
            deadline_ms: Some(0),
            ..Limits::default()
        });
        assert_eq!(poll("cache").unwrap_err().reason, "deadline");
        let _nested = Scope::new(Limits {
            ssa_work: Some(0),
            ..Limits::default()
        });
        poll("cache").unwrap(); // reading a cache does not construct SSA
        assert!(std::panic::catch_unwind(|| work("cfg", 1)).is_err());
    }

    #[test]
    fn elapsed_deadline_stops_a_later_phase_and_keeps_earlier_work_counts() {
        let _scope=Scope::new(Limits {deadline_ms:Some(100),..Limits::default()});
        decode_step().unwrap();work("ssa",3);
        // Make the clock state deterministic without a sleeping test.
        STATE.with(|state|state.borrow_mut().as_mut().unwrap().started=Instant::now()-Duration::from_millis(101));
        let stop=poll("render").unwrap_err();
        assert_eq!(stop.reason,"deadline");assert_eq!(stop.stage,"render");
        assert_eq!(metrics().decode_instructions,1);assert_eq!(metrics().ssa_work,3);
    }
}
