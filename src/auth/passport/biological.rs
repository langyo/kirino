#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct BiologicalVerifier {
    threshold: f64,
}

impl BiologicalVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self { threshold: 0.85 }
    }

    #[must_use]
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    pub fn verify(&self, sample: &[u8], template: &[u8]) -> Result<bool> {
        if sample.is_empty() || template.is_empty() {
            return Ok(false);
        }
        let score = self.compute_similarity(sample, template);
        Ok(score >= self.threshold)
    }

    fn compute_similarity(&self, a: &[u8], b: &[u8]) -> f64 {
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 1.0;
        }
        let min_len = a.len().min(b.len());
        let mut matching_bits = 0usize;
        for i in 0..min_len {
            matching_bits += (a[i] ^ b[i]).count_zeros() as usize;
        }
        let total_bits = max_len * 8;
        matching_bits as f64 / total_bits as f64
    }
}

impl Default for BiologicalVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_samples() {
        let v = BiologicalVerifier::new();
        let template = vec![1, 2, 3, 4, 5];
        assert!(v.verify(&template, &template).unwrap());
    }

    #[test]
    fn test_completely_different() {
        let v = BiologicalVerifier::new();
        let sample = vec![0xFF; 16];
        let template = vec![0x00; 16];
        assert!(!v.verify(&sample, &template).unwrap());
    }

    #[test]
    fn test_empty_input() {
        let v = BiologicalVerifier::new();
        assert!(!v.verify(&[], &[1, 2, 3]).unwrap());
    }

    #[test]
    fn test_custom_threshold() {
        let v = BiologicalVerifier::with_threshold(0.5);
        let a = vec![0xAA; 16];
        let mut b = vec![0xAA; 16];
        b[0] = 0x55;
        assert!(v.verify(&a, &b).unwrap());
    }
}
