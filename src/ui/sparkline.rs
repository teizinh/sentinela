use std::collections::VecDeque;

/// 8-level Unicode block elements for sparkline rendering (lowest to highest).
pub const TICKS: [char; 8] = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// 4-level Braille patterns optionally usable for high-density rendering.
#[allow(dead_code)]
pub const BRAILLE_TICKS: [char; 4] = ['⣀', '⣤', '⣶', '⣿'];

/// Sliding-buffer Sparkline generator for terminal visualizations.
#[derive(Debug, Clone, PartialEq)]
pub struct Sparkline {
    data: VecDeque<f64>,
    capacity: usize,
}

#[allow(dead_code)]
impl Sparkline {
    /// Creates a new Sparkline with a fixed sliding-buffer capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Appends a new value to the sliding buffer, discarding the oldest value if full.
    pub fn push(&mut self, val: f64) {
        if self.capacity == 0 {
            return;
        }
        let clean_val = if val.is_nan() {
            0.0
        } else {
            val
        };
        if self.data.len() >= self.capacity {
            self.data.pop_front();
        }
        self.data.push_back(clean_val);
    }

    /// Number of items currently stored in the sliding buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the sliding buffer contains no elements.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the capacity of the sliding buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Clears all recorded values.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Returns an iterator over current values in chronological order.
    pub fn iter(&self) -> impl Iterator<Item = &f64> {
        self.data.iter()
    }

    /// Renders a Unicode sparkline string formatted for the given terminal display `width`.
    ///
    /// Normalizes values between min and max within the sliding buffer.
    /// Handles edge cases:
    /// - `width == 0`: returns an empty string `""`.
    /// - Empty buffer: returns `width` spaces `" ".repeat(width)`.
    /// - All identical values or all zero values: renders level 0 (`' '`).
    /// - `width > capacity` or `width > data.len()`: left-padded with spaces so total width matches.
    /// - `width < data.len()`: displays the most recent `width` values from the sliding buffer.
    pub fn render(&self, width: usize) -> String {
        if width == 0 {
            return String::new();
        }

        if self.data.is_empty() {
            return " ".repeat(width);
        }

        // Min and max within the sliding buffer
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for &v in &self.data {
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }

        let range = max - min;

        // Take up to `width` most recent values
        let count = self.data.len().min(width);
        let skip = self.data.len() - count;
        let padding = width - count;

        let mut output = String::with_capacity(width * 4);
        if padding > 0 {
            output.push_str(&" ".repeat(padding));
        }

        for &val in self.data.iter().skip(skip) {
            let tick = if range <= f64::EPSILON {
                // All identical values or all zeros: default to lowest tick level
                TICKS[0]
            } else {
                let ratio = ((val - min) / range).clamp(0.0, 1.0);
                let idx = (ratio * 7.0).round() as usize;
                let clamped_idx = idx.min(TICKS.len() - 1);
                TICKS[clamped_idx]
            };
            output.push(tick);
        }

        output
    }
}

impl Default for Sparkline {
    fn default() -> Self {
        Self::new(24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparkline_empty_renders_empty_or_spaces() {
        let spark = Sparkline::new(10);
        assert_eq!(spark.render(0), "");
        assert_eq!(spark.render(5), "     ");
        let rendered = spark.render(10);
        assert_eq!(rendered.chars().count(), 10);
        assert!(rendered.chars().all(|c| c == ' '));
    }

    #[test]
    fn test_sparkline_monotonic_increasing() {
        let mut spark = Sparkline::new(8);
        for i in 0..8 {
            spark.push(i as f64);
        }
        let rendered = spark.render(8);
        assert_eq!(rendered, " ▂▃▄▅▆▇█");
        assert_eq!(rendered.chars().count(), 8);
    }

    #[test]
    fn test_sparkline_uniform_values() {
        let mut spark = Sparkline::new(10);
        for _ in 0..10 {
            spark.push(42.0);
        }
        let rendered = spark.render(10);
        assert_eq!(rendered.chars().count(), 10);
        assert_eq!(rendered, "          ");

        let mut spark_zeros = Sparkline::new(5);
        for _ in 0..5 {
            spark_zeros.push(0.0);
        }
        let rendered_zeros = spark_zeros.render(5);
        assert_eq!(rendered_zeros.chars().count(), 5);
        assert_eq!(rendered_zeros, "     ");
    }

    #[test]
    fn test_sparkline_fixed_width_bounds() {
        let mut spark = Sparkline::new(5);
        spark.push(10.0);
        spark.push(20.0);
        spark.push(30.0);

        // width > capacity and width > data.len()
        let rendered_wide = spark.render(10);
        assert_eq!(rendered_wide.chars().count(), 10);
        assert!(rendered_wide.starts_with("       ")); // 7 leading spaces + 3 ticks

        // width == data.len()
        let rendered_exact = spark.render(3);
        assert_eq!(rendered_exact.chars().count(), 3);

        // width < data.len()
        let rendered_narrow = spark.render(2);
        assert_eq!(rendered_narrow.chars().count(), 2);

        // width == 0
        let rendered_zero = spark.render(0);
        assert_eq!(rendered_zero, "");
    }

    #[test]
    fn test_sparkline_sliding_capacity_eviction() {
        let mut spark = Sparkline::new(3);
        spark.push(1.0);
        spark.push(2.0);
        spark.push(3.0);
        assert_eq!(spark.len(), 3);

        spark.push(4.0);
        assert_eq!(spark.len(), 3);
        let vals: Vec<f64> = spark.iter().copied().collect();
        assert_eq!(vals, vec![2.0, 3.0, 4.0]);
    }

    #[test]
    fn test_sparkline_nan_handling() {
        let mut spark = Sparkline::new(3);
        spark.push(f64::NAN);
        spark.push(10.0);
        assert_eq!(spark.len(), 2);
        let rendered = spark.render(2);
        assert_eq!(rendered.chars().count(), 2);
        assert_eq!(rendered, " █");
    }

    #[test]
    fn test_sparkline_zero_capacity() {
        let mut spark = Sparkline::new(0);
        spark.push(10.0);
        assert_eq!(spark.len(), 0);
        assert_eq!(spark.render(5), "     ");
    }
}
