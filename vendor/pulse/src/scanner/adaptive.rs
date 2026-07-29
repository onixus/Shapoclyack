//! Adaptive concurrency controller.
//!
//! `-c` is treated as a **ceiling**. After each host batch we look at the
//! timeout ratio and ramp concurrency up/down so sparse/lossy networks don't
//! stall on max parallelism, and healthy LANs can climb toward the ceiling.

/// Min concurrent probes when adaptive is on.
pub const ADAPTIVE_FLOOR: usize = 16;
/// Start at this fraction of the ceiling.
pub const ADAPTIVE_START_NUM: usize = 1;
pub const ADAPTIVE_START_DEN: usize = 4;

#[derive(Debug, Clone)]
pub struct AdaptiveController {
    pub enabled: bool,
    /// Hard ceiling (from `-c`).
    pub ceiling: usize,
    /// Current concurrency / inflight.
    pub current: usize,
    /// Last observed timeout ratio (0.0–1.0).
    pub last_timeout_ratio: f64,
    adjustments: u32,
}

impl AdaptiveController {
    pub fn new(enabled: bool, ceiling: usize) -> Self {
        let ceiling = ceiling.max(1);
        let current = if enabled {
            ((ceiling * ADAPTIVE_START_NUM) / ADAPTIVE_START_DEN)
                .clamp(ADAPTIVE_FLOOR.min(ceiling), ceiling)
        } else {
            ceiling
        };
        Self {
            enabled,
            ceiling,
            current,
            last_timeout_ratio: 0.0,
            adjustments: 0,
        }
    }

    pub fn concurrency(&self) -> usize {
        self.current.max(1)
    }

    /// Feed batch stats. Returns `Some(new)` if concurrency changed.
    pub fn observe_batch(&mut self, probes: usize, timeouts: usize) -> Option<usize> {
        if !self.enabled || probes == 0 {
            return None;
        }
        let ratio = timeouts as f64 / probes as f64;
        self.last_timeout_ratio = ratio;
        let old = self.current;

        // High timeout rate → back off hard (network/host can't keep up)
        if ratio >= 0.40 {
            self.current = ((self.current as f64) * 0.65)
                .round()
                .max(ADAPTIVE_FLOOR as f64)
                .min(self.ceiling as f64) as usize;
        } else if ratio >= 0.25 {
            self.current = ((self.current as f64) * 0.85)
                .round()
                .max(ADAPTIVE_FLOOR as f64)
                .min(self.ceiling as f64) as usize;
        } else if ratio <= 0.08 {
            // Healthy → ramp up
            self.current = ((self.current as f64) * 1.30)
                .round()
                .max(ADAPTIVE_FLOOR as f64)
                .min(self.ceiling as f64) as usize;
        } else if ratio <= 0.15 {
            self.current = ((self.current as f64) * 1.10)
                .round()
                .max(ADAPTIVE_FLOOR as f64)
                .min(self.ceiling as f64) as usize;
        }

        self.current = self.current.clamp(1, self.ceiling);
        if self.current != old {
            self.adjustments += 1;
            Some(self.current)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_below_ceiling() {
        let c = AdaptiveController::new(true, 500);
        assert!(c.current < 500);
        assert!(c.current >= ADAPTIVE_FLOOR);
    }

    #[test]
    fn backs_off_on_timeouts() {
        let mut c = AdaptiveController::new(true, 200);
        c.current = 200;
        let n = c.observe_batch(100, 50); // 50% timeouts
        assert!(n.is_some());
        assert!(c.current < 200);
    }

    #[test]
    fn ramps_when_healthy() {
        let mut c = AdaptiveController::new(true, 400);
        c.current = 50;
        let _ = c.observe_batch(100, 2); // 2% timeouts
        assert!(c.current > 50);
        assert!(c.current <= 400);
    }

    #[test]
    fn disabled_stays_at_ceiling() {
        let mut c = AdaptiveController::new(false, 300);
        assert_eq!(c.current, 300);
        assert!(c.observe_batch(100, 90).is_none());
        assert_eq!(c.current, 300);
    }
}
