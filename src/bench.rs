use crate::error::DnsError;
use crate::protocol::edns::EdnsOptions;
use crate::protocol::message::DnsMessage;
use crate::protocol::types::RecordType;
use crate::transport;
use std::time::Duration;

pub struct BenchResult {
    pub successful: usize,
    pub failed: usize,
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub histogram: Vec<(f64, usize)>,
}

#[allow(clippy::too_many_arguments)]
pub fn run_benchmark(
    server: &str,
    port: u16,
    name: &str,
    qtype: RecordType,
    count: usize,
    timeout: Duration,
    force_tcp: bool,
    dnssec: bool,
) -> BenchResult {
    let mut latencies: Vec<f64> = Vec::with_capacity(count);
    let mut failed = 0;

    let edns = EdnsOptions {
        dnssec_ok: dnssec,
        ..EdnsOptions::default()
    };

    for i in 0..count {
        if i % 10 == 0 || i == count - 1 {
            eprint!("\r  benchmarking... {}/{}", i + 1, count);
        }

        let latency_result = (|| -> Result<f64, DnsError> {
            let (query, _id) = DnsMessage::build_query(name, qtype, true, Some(&edns))?;
            let r = transport::send_query(server, port, &query, force_tcp, timeout)?;
            Ok(r.elapsed.as_secs_f64() * 1000.0)
        })();

        match latency_result {
            Ok(ms) => latencies.push(ms),
            Err(_) => failed += 1,
        }
    }
    eprintln!("\r  benchmarking... {}/{} done", count, count);

    latencies.sort_by(|a, b| a.total_cmp(b));

    let successful = latencies.len();
    let min_ms = latencies.first().copied().unwrap_or(0.0);
    let max_ms = latencies.last().copied().unwrap_or(0.0);
    let avg_ms = if successful > 0 {
        latencies.iter().sum::<f64>() / successful as f64
    } else {
        0.0
    };
    let p50_ms = percentile(&latencies, 50);
    let p90_ms = percentile(&latencies, 90);
    let p99_ms = percentile(&latencies, 99);
    let histogram = build_histogram(&latencies, 10);

    BenchResult {
        successful,
        failed,
        min_ms,
        max_ms,
        avg_ms,
        p50_ms,
        p90_ms,
        p99_ms,
        histogram,
    }
}

fn percentile(sorted: &[f64], pct: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn build_histogram(sorted: &[f64], buckets: usize) -> Vec<(f64, usize)> {
    if sorted.is_empty() {
        return vec![];
    }
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let range = max - min;
    if range < 0.001 {
        return vec![(max, sorted.len())];
    }

    let bucket_width = range / buckets as f64;
    let mut hist = Vec::with_capacity(buckets);
    for i in 0..buckets {
        let lower = min + bucket_width * i as f64;
        let upper = min + bucket_width * (i + 1) as f64;
        let count = sorted
            .iter()
            .filter(|&&v| {
                if i == 0 {
                    v >= lower && v <= upper
                } else {
                    v > lower && v <= upper
                }
            })
            .count();
        hist.push((upper, count));
    }
    hist
}

#[cfg(test)]
mod tests {
    use super::{build_histogram, percentile};

    #[test]
    fn percentile_of_empty_set_is_zero_not_nan() {
        assert_eq!(percentile(&[], 50), 0.0);
        assert_eq!(percentile(&[], 99), 0.0);
    }

    #[test]
    fn percentile_of_single_element_is_that_element() {
        assert_eq!(percentile(&[42.0], 0), 42.0);
        assert_eq!(percentile(&[42.0], 50), 42.0);
        assert_eq!(percentile(&[42.0], 100), 42.0);
    }

    #[test]
    fn percentile_matches_hand_computed_values() {
        let sorted: Vec<f64> = (1..=10).map(|n| n as f64).collect();
        // index = round(pct/100 * 9)
        assert_eq!(percentile(&sorted, 0), 1.0);
        assert_eq!(percentile(&sorted, 50), 6.0); // round(4.5) = 5 -> value 6.0
        assert_eq!(percentile(&sorted, 90), 9.0); // round(8.1) = 8 -> value 9.0
        assert_eq!(percentile(&sorted, 99), 10.0); // round(8.91) = 9 -> value 10.0
        assert_eq!(percentile(&sorted, 100), 10.0);
    }

    #[test]
    fn percentile_index_is_clamped_to_last_element() {
        // pct > 100 must not index out of bounds.
        assert_eq!(percentile(&[1.0, 2.0], 200), 2.0);
    }

    #[test]
    fn histogram_of_empty_set_is_empty() {
        assert!(build_histogram(&[], 10).is_empty());
    }

    #[test]
    fn histogram_of_identical_latencies_collapses_to_one_bucket() {
        // Degenerate range (< 0.001) takes the single-bucket branch.
        let hist = build_histogram(&[5.0, 5.0, 5.0], 10);
        assert_eq!(hist, vec![(5.0, 3)]);
    }

    #[test]
    fn histogram_counts_every_sample_exactly_once() {
        let sorted = vec![0.0, 1.0, 2.5, 5.0, 7.5, 10.0];
        let hist = build_histogram(&sorted, 4);
        assert_eq!(hist.len(), 4);
        let total: usize = hist.iter().map(|(_, c)| c).sum();
        assert_eq!(total, sorted.len());
    }

    #[test]
    fn histogram_bucket_boundaries_do_not_double_count() {
        // Values exactly on bucket edges must land in exactly one bucket.
        let sorted = vec![0.0, 2.5, 5.0, 7.5, 10.0];
        let hist = build_histogram(&sorted, 4);
        let total: usize = hist.iter().map(|(_, c)| c).sum();
        assert_eq!(total, sorted.len());
        // First bucket is inclusive on both ends: contains 0.0 and 2.5.
        assert_eq!(hist[0].1, 2);
    }
}
