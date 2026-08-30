//! Shared NDJSON record used by every recon finding emitter.

use serde::Serialize;
use serde_json::{Map, Value};

pub const FINDING_SCHEMA: &str = "rsleigh.finding/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    /// A byte/text/pseudocode pattern matched; no semantic proof was attempted.
    Pattern,
    /// Analysis combined multiple signals but remains approximate.
    Heuristic,
    /// A bounded solver or exact parser established the stated result.
    Proved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStage {
    File,
    Discover,
    Lift,
    Decompile,
    Prove,
}

/// Stable envelope for line-oriented recon output.
///
/// Emitter-specific evidence is flattened to retain useful fields such as
/// `sink_kind` while every line still carries the same identity, confidence,
/// stage, and summary keys.
#[derive(Debug, Clone, Serialize)]
pub struct FindingRecord {
    pub schema: &'static str,
    pub kind: String,
    pub producer: String,
    pub confidence: FindingConfidence,
    pub stage: FindingStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub summary: String,
    #[serde(flatten)]
    pub evidence: Map<String, Value>,
}

impl FindingRecord {
    pub fn new(
        kind: impl Into<String>,
        producer: impl Into<String>,
        confidence: FindingConfidence,
        stage: FindingStage,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            schema: FINDING_SCHEMA,
            kind: kind.into(),
            producer: producer.into(),
            confidence,
            stage,
            severity: None,
            function: None,
            address: None,
            summary: summary.into(),
            evidence: Map::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: Value) -> Self {
        if let Value::Object(mut fields) = evidence {
            for reserved in [
                "schema",
                "kind",
                "producer",
                "confidence",
                "stage",
                "severity",
                "function",
                "address",
                "summary",
            ] {
                fields.remove(reserved);
            }
            self.evidence = fields;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_flat_and_confidence_is_explicit() {
        let record = FindingRecord::new(
            "taint_flow",
            "smt-candidates",
            FindingConfidence::Proved,
            FindingStage::Prove,
            "recv reaches memcpy",
        )
        .with_evidence(serde_json::json!({
            "schema": "producer-cannot-shadow-envelope",
            "sink_kind": "LengthArg"
        }));
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(value["schema"], FINDING_SCHEMA);
        assert_eq!(value["confidence"], "proved");
        assert_eq!(value["sink_kind"], "LengthArg");
    }
}
