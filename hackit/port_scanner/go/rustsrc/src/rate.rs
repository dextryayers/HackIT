use std::time::{Duration, Instant};

/// PID rate controller — maintains target packet rate
pub struct RateController {
    target_rate: f64,
    kp: f64,
    ki: f64,
    kd: f64,
    integral: f64,
    prev_error: f64,
    last_update: Instant,
    packet_count: u64,
    window_start: Instant,
}

impl RateController {
    pub fn new(target_rate: f64) -> Self {
        RateController {
            target_rate,
            kp: 0.5,
            ki: 0.1,
            kd: 0.05,
            integral: 0.0,
            prev_error: 0.0,
            last_update: Instant::now(),
            packet_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Call before sending a batch of packets
    pub fn tick(&mut self, batch_size: u64) {
        self.packet_count += batch_size;
        let elapsed = self.window_start.elapsed();
        if elapsed < Duration::from_millis(100) {
            return;
        }
        let actual_rate = self.packet_count as f64 / elapsed.as_secs_f64();
        let error = self.target_rate - actual_rate;
        self.integral += error * elapsed.as_secs_f64();
        self.integral = self.integral.clamp(-self.target_rate, self.target_rate);
        let derivative = (error - self.prev_error) / elapsed.as_secs_f64();
        let adjustment = self.kp * error + self.ki * self.integral + self.kd * derivative;

        let new_rate = (actual_rate + adjustment).max(1.0);
        let delay = if new_rate > 0.0 {
            (1.0 / new_rate * 1_000_000.0) as u64
        } else {
            1000
        };

        self.prev_error = error;
        self.last_update = Instant::now();
        self.packet_count = 0;
        self.window_start = Instant::now();
    }

    /// Adaptive adjustment — reduce rate if packet loss detected
    pub fn on_packet_loss(&mut self) {
        self.target_rate *= 0.7;
        self.target_rate = self.target_rate.max(100.0);
    }

    pub fn target_rate(&self) -> f64 {
        self.target_rate
    }
}
