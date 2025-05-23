/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// https://github.com/mstange/samply/blob/main/gecko_profile/src/markers.rs

use std::time::Instant;

use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub enum MarkerTiming {
    Instant(Instant),
    Interval(Instant, Instant),
    IntervalStart(Instant),
    IntervalEnd(Instant),
}

pub trait ProfilerMarker {
    /// The name of the marker type.
    const MARKER_TYPE_NAME: &'static str;

    /// A static method that returns a `MarkerSchema`, which contains all the
    /// information needed to stream the display schema associated with a
    /// marker type.
    fn schema() -> MarkerSchema;

    /// A method that streams the marker payload data as a serde_json object.
    fn json_marker_data(&self) -> Value;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerSchema {
    #[serde(rename = "name")]
    pub type_name: &'static str,

    /// List of marker display locations. Empty for SpecialFrontendLocation.
    #[serde(rename = "display")]
    pub locations: Vec<MarkerLocation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub chart_label: Option<&'static str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooltip_label: Option<&'static str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_label: Option<&'static str>,

    #[serde(rename = "data")]
    pub fields: Vec<MarkerSchemaField>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerLocation {
    MarkerChart,
    MarkerTable,
    /// This adds markers to the main marker timeline in the header.
    TimelineOverview,
    /// In the timeline, this is a section that breaks out markers that are
    /// related to memory. When memory counters are enabled, this is its own
    /// track, otherwise it is displayed with the main thread.
    TimelineMemory,
    /// This adds markers to the IPC timeline area in the header.
    TimelineIPC,
    /// This adds markers to the FileIO timeline area in the header.
    #[serde(rename = "timeline-fileio")]
    TimelineFileIO,
    /// TODO - This is not supported yet.
    StackChart,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum MarkerSchemaField {
    /// Static fields have the same value on all markers. This is used for
    /// a "Description" field in the tooltip, for example.
    Static(MarkerStaticField),

    /// Dynamic fields have a per-marker value. The ProfilerMarker implementation
    /// on the marker type needs to serialize a field on the data JSON object with
    /// the matching key.
    Dynamic(MarkerDynamicField),
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkerStaticField {
    pub label: &'static str,
    pub value: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkerDynamicField {
    pub key: &'static str,

    #[serde(skip_serializing_if = "str::is_empty")]
    pub label: &'static str,

    pub format: MarkerFieldFormat,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub searchable: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerFieldFormat {
    // ----------------------------------------------------
    // String types.
    /// A URL, supports PII sanitization
    Url,

    /// A file path, supports PII sanitization.
    FilePath,

    /// A plain String, never sanitized for PII.
    /// Important: Do not put URL or file path information here, as it will not
    /// be sanitized during profile upload. Please be careful with including
    /// other types of PII here as well.
    String,

    // ----------------------------------------------------
    // Numeric types
    /// For time data that represents a duration of time.
    /// e.g. "Label: 5s, 5ms, 5μs"
    Duration,

    /// Data that happened at a specific time, relative to the start of the
    /// profile. e.g. "Label: 15.5s, 20.5ms, 30.5μs"
    Time,

    /// The following are alternatives to display a time only in a specific unit
    /// of time.
    Seconds, // "Label: 5s"
    Milliseconds, // "Label: 5ms"
    Microseconds, // "Label: 5μs"
    Nanoseconds,  // "Label: 5ns"

    /// e.g. "Label: 5.55mb, 5 bytes, 312.5kb"
    Bytes,

    /// This should be a value between 0 and 1.
    /// "Label: 50%"
    Percentage,

    // The integer should be used for generic representations of numbers.
    // Do not use it for time information.
    // "Label: 52, 5,323, 1,234,567"
    Integer,

    // The decimal should be used for generic representations of numbers.
    // Do not use it for time information.
    // "Label: 52.23, 0.0054, 123,456.78"
    Decimal,
}

/// The simplest possible example marker type. It contains no information
/// beyond the name string that's passed to ThreadBuilder::add_marker.
#[derive(Debug, Clone)]
pub struct TracingMarker();

impl ProfilerMarker for TracingMarker {
    const MARKER_TYPE_NAME: &'static str = "tracing";

    fn json_marker_data(&self) -> Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![
                MarkerLocation::MarkerChart,
                MarkerLocation::MarkerTable,
                MarkerLocation::TimelineOverview,
            ],
            chart_label: None,
            tooltip_label: None,
            table_label: None,
            fields: vec![],
        }
    }
}

/// An example marker type with some text content.
#[derive(Debug, Clone)]
pub struct TextMarker(pub String);

impl ProfilerMarker for TextMarker {
    const MARKER_TYPE_NAME: &'static str = "Text";

    fn json_marker_data(&self) -> Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
            "name": self.0
        })
    }

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![MarkerLocation::MarkerChart, MarkerLocation::MarkerTable],
            chart_label: Some("{marker.data.name}"),
            tooltip_label: None,
            table_label: Some("{marker.name} - {marker.data.name}"),
            fields: vec![MarkerSchemaField::Dynamic(MarkerDynamicField {
                key: "name",
                label: "Details",
                format: MarkerFieldFormat::String,
                searchable: None,
            })],
        }
    }
}
