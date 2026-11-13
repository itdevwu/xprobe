//! Evidence summarization and deterministic result-quality assessment.

use xprobe_protocol::{
    CorrelationConfidence, Evidence, EvidenceExemplar, EvidenceMode, LatencyRank, MatchedEventPair,
    MeasurementResult, QualityIssue, QualitySeverity, QualityVerdict, ResultQuality, SessionStatus,
};

/// Clock error at or above this share of the p50 latency is a caution.
const CLOCK_ERROR_CAUTION_DIVISOR: u64 = 10;
/// Fewer matched samples than this make tail ranks coarse.
const TAIL_SAMPLE_FLOOR: u64 = 100;

/// Nearest-rank index shared by latency statistics and exemplars.
pub(crate) fn rank_index(len: usize, percentile: usize) -> usize {
    (percentile * len).div_ceil(100).saturating_sub(1)
}

/// Evidence as produced by correlation: every pair inline plus exemplars.
pub(crate) fn full_evidence(pairs: Vec<MatchedEventPair>) -> Evidence {
    Evidence {
        mode: EvidenceMode::Full,
        exemplars: exemplars(&pairs),
        pairs: Some(pairs),
        artifact: None,
    }
}

/// Select one pair per latency rank, merging ranks that land on the same pair.
pub(crate) fn exemplars(pairs: &[MatchedEventPair]) -> Vec<EvidenceExemplar> {
    if pairs.is_empty() {
        return Vec::new();
    }
    let mut order = (0..pairs.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| (pairs[index].latency_ns, index));
    let ranks = [
        (LatencyRank::Min, 0),
        (LatencyRank::P50, rank_index(order.len(), 50)),
        (LatencyRank::P90, rank_index(order.len(), 90)),
        (LatencyRank::P99, rank_index(order.len(), 99)),
        (LatencyRank::Max, order.len() - 1),
    ];
    let mut selected: Vec<(usize, Vec<LatencyRank>)> = Vec::new();
    for (rank, position) in ranks {
        match selected.last_mut() {
            Some((last, labels)) if *last == position => labels.push(rank),
            _ => selected.push((position, vec![rank])),
        }
    }
    selected
        .into_iter()
        .map(|(position, ranks)| EvidenceExemplar {
            ranks,
            pair: pairs[order[position]].clone(),
        })
        .collect()
}

/// Recompute quality and apply the requested evidence mode.
///
/// Call this after every caller-side change to status, collection, or
/// warnings so the verdict describes the emitted result.
pub fn finalize(result: &mut MeasurementResult, mode: EvidenceMode) {
    result.quality = assess(result);
    result.evidence.mode = mode;
    if mode == EvidenceMode::Summary {
        result.evidence.pairs = None;
    }
}

/// Interpret status, correlation, sample, and clock fields deterministically.
#[must_use]
pub fn assess(result: &MeasurementResult) -> ResultQuality {
    let mut issues = Vec::new();
    let samples = &result.measurement.samples;
    match result.status {
        SessionStatus::Completed => {}
        SessionStatus::TimedOut => issues.push(caution(
            "TIMED_OUT",
            "capture reached its timeout before the sample or duration bound; statistics are partial"
                .to_owned(),
        )),
        SessionStatus::Cancelled | SessionStatus::Failed => issues.push(caution(
            "INCOMPLETE_SESSION",
            "session did not complete; statistics are partial".to_owned(),
        )),
    }
    match result.correlation.confidence {
        CorrelationConfidence::Exact | CorrelationConfidence::High => {}
        CorrelationConfidence::Heuristic => issues.push(caution(
            "HEURISTIC_CORRELATION",
            "pairs are matched by time order; they do not prove request-level causality".to_owned(),
        )),
        CorrelationConfidence::Ambiguous => issues.push(caution(
            "AMBIGUOUS_CORRELATION",
            "the correlation method cannot uniquely pair events".to_owned(),
        )),
    }
    if samples.ambiguous != 0 {
        issues.push(caution(
            "AMBIGUOUS_PAIRS",
            format!("{} candidate pairs were ambiguous", samples.ambiguous),
        ));
    }
    let unmatched = samples.unmatched_start + samples.unmatched_end;
    if unmatched != 0 {
        let message = format!(
            "{} start and {} end events were unmatched alongside {} matched pairs",
            samples.unmatched_start, samples.unmatched_end, samples.matched
        );
        issues.push(if unmatched > samples.matched {
            caution("UNMATCHED_EVENTS", message)
        } else {
            info("UNMATCHED_EVENTS", message)
        });
    }
    match result.clock.estimated_error_ns {
        None => issues.push(info(
            "CLOCK_ERROR_UNAVAILABLE",
            "no error bound is reported for GPU-to-host timestamp interpolation".to_owned(),
        )),
        Some(error)
            if result.measurement.latency_ns.p50 != 0
                && error.saturating_mul(CLOCK_ERROR_CAUTION_DIVISOR)
                    >= result.measurement.latency_ns.p50 =>
        {
            issues.push(caution(
                "CLOCK_ERROR_LARGE",
                format!(
                    "timestamp error bound {error} ns is at least 10% of the p50 latency {} ns",
                    result.measurement.latency_ns.p50
                ),
            ));
        }
        Some(_) => {}
    }
    if samples.matched < TAIL_SAMPLE_FLOOR {
        issues.push(info(
            "FEW_SAMPLES",
            format!(
                "tail ranks such as p99 are estimated from {} matched samples",
                samples.matched
            ),
        ));
    }
    let verdict = if issues
        .iter()
        .any(|issue| issue.severity == QualitySeverity::Caution)
    {
        QualityVerdict::Caution
    } else {
        QualityVerdict::Good
    };
    ResultQuality { verdict, issues }
}

fn caution(code: &str, message: String) -> QualityIssue {
    QualityIssue {
        code: code.to_owned(),
        severity: QualitySeverity::Caution,
        message,
    }
}

fn info(code: &str, message: String) -> QualityIssue {
    QualityIssue {
        code: code.to_owned(),
        severity: QualitySeverity::Info,
        message,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use xprobe_protocol::{
        CaptureCompleteness, ClockDomain, ClockQuality, CollectionSummary, CorrelationConfidence,
        CorrelationSummary, Event, EventSource, EventType, EvidenceMode, LatencyRank,
        LatencyStatistics, MatchedEventPair, Measurement, MeasurementResult, QualitySeverity,
        QualityVerdict, ResultQuality, SampleSummary, SchemaVersion, SchemaVersion3, SessionStatus,
    };

    use super::{assess, exemplars, finalize, full_evidence, rank_index};

    fn event(timestamp_ns: u64) -> Event {
        Event {
            schema_version: SchemaVersion::current(),
            session_id: "s".to_owned(),
            event_id: format!("e{timestamp_ns}"),
            sequence: timestamp_ns,
            source: EventSource::Ebpf,
            event_type: EventType::SyscallEntry,
            pid: 1,
            tid: 1,
            cpu: Some(0),
            timestamp_raw: timestamp_ns,
            timestamp_ns,
            clock_domain: ClockDomain::HostMonotonic,
            timestamp_error_ns: None,
            process_start_time: Some(1),
            host: None,
            cuda: None,
            nvtx: None,
            attributes: BTreeMap::new(),
        }
    }

    fn pair(latency_ns: u64) -> MatchedEventPair {
        MatchedEventPair {
            start: event(0),
            end: event(latency_ns),
            latency_ns,
        }
    }

    fn result(matched: u64, p50: u64) -> MeasurementResult {
        MeasurementResult {
            schema_version: SchemaVersion3::current(),
            ok: true,
            session_id: "s".to_owned(),
            status: SessionStatus::Completed,
            measurement: Measurement {
                name: None,
                samples: SampleSummary {
                    matched,
                    unmatched_start: 0,
                    unmatched_end: 0,
                    ambiguous: 0,
                    dropped: 0,
                },
                latency_ns: LatencyStatistics {
                    min: p50,
                    mean: 0.0,
                    p50,
                    p90: p50,
                    p95: p50,
                    p99: p50,
                    max: p50,
                },
            },
            quality: ResultQuality {
                verdict: QualityVerdict::Good,
                issues: Vec::new(),
            },
            correlation: CorrelationSummary {
                method: "exact".to_owned(),
                confidence: CorrelationConfidence::Exact,
                score: 1.0,
            },
            clock: ClockQuality {
                alignment: "host_monotonic".to_owned(),
                estimated_error_ns: Some(0),
            },
            collection: CollectionSummary {
                completeness: CaptureCompleteness::Complete,
                host_events: 0,
                cuda_events: 0,
                dropped_events: 0,
                cupti: None,
            },
            evidence: full_evidence(vec![pair(p50)]),
            warnings: Vec::new(),
        }
    }

    fn codes(result: &MeasurementResult) -> Vec<(String, QualitySeverity)> {
        assess(result)
            .issues
            .into_iter()
            .map(|issue| (issue.code, issue.severity))
            .collect()
    }

    #[test]
    fn exemplars_follow_statistic_ranks_and_merge_shared_pairs() {
        let pairs = (1..=200).rev().map(pair).collect::<Vec<_>>();
        let selected = exemplars(&pairs);
        let ranks = selected
            .iter()
            .map(|exemplar| (exemplar.ranks.clone(), exemplar.pair.latency_ns))
            .collect::<Vec<_>>();
        assert_eq!(
            ranks,
            [
                (vec![LatencyRank::Min], 1),
                (vec![LatencyRank::P50], 100),
                (vec![LatencyRank::P90], 180),
                (vec![LatencyRank::P99], 198),
                (vec![LatencyRank::Max], 200),
            ]
        );
        assert_eq!(rank_index(200, 99), 197);
        let single = exemplars(&[pair(7)]);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].ranks.len(), 5);
        assert_eq!(exemplars(&[]), Vec::new());
    }

    #[test]
    fn clean_exact_result_is_good() {
        let quality = assess(&result(100, 1_000));
        assert_eq!(quality.verdict, QualityVerdict::Good);
        assert_eq!(quality.issues, []);
    }

    #[test]
    fn few_samples_and_minor_unmatched_are_informational() {
        let mut value = result(10, 1_000);
        value.measurement.samples.unmatched_end = 2;
        let quality = assess(&value);
        assert_eq!(quality.verdict, QualityVerdict::Good);
        assert_eq!(
            codes(&value),
            [
                ("UNMATCHED_EVENTS".to_owned(), QualitySeverity::Info),
                ("FEW_SAMPLES".to_owned(), QualitySeverity::Info),
            ]
        );
    }

    #[test]
    fn interpretation_limits_are_cautions() {
        let mut value = result(100, 1_000);
        value.status = SessionStatus::TimedOut;
        value.correlation.confidence = CorrelationConfidence::Heuristic;
        value.measurement.samples.ambiguous = 1;
        value.measurement.samples.unmatched_start = 101;
        value.clock.estimated_error_ns = Some(100);
        assert_eq!(assess(&value).verdict, QualityVerdict::Caution);
        assert_eq!(
            codes(&value),
            [
                ("TIMED_OUT".to_owned(), QualitySeverity::Caution),
                ("HEURISTIC_CORRELATION".to_owned(), QualitySeverity::Caution),
                ("AMBIGUOUS_PAIRS".to_owned(), QualitySeverity::Caution),
                ("UNMATCHED_EVENTS".to_owned(), QualitySeverity::Caution),
                ("CLOCK_ERROR_LARGE".to_owned(), QualitySeverity::Caution),
            ]
        );
    }

    #[test]
    fn unknown_clock_error_is_reported() {
        let mut value = result(100, 1_000);
        value.clock.estimated_error_ns = None;
        assert_eq!(
            codes(&value),
            [("CLOCK_ERROR_UNAVAILABLE".to_owned(), QualitySeverity::Info)]
        );
        value.clock.estimated_error_ns = Some(99);
        assert_eq!(codes(&value), []);
    }

    #[test]
    fn finalize_recomputes_quality_and_trims_summary_pairs() {
        let mut value = result(100, 1_000);
        value.status = SessionStatus::TimedOut;
        finalize(&mut value, EvidenceMode::Summary);
        assert_eq!(value.quality.verdict, QualityVerdict::Caution);
        assert_eq!(value.evidence.mode, EvidenceMode::Summary);
        assert_eq!(value.evidence.pairs, None);
        assert_eq!(value.evidence.exemplars.len(), 1);

        let mut value = result(100, 1_000);
        finalize(&mut value, EvidenceMode::Full);
        assert_eq!(value.evidence.pairs.map(|pairs| pairs.len()), Some(1));
    }
}
