// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use agent_control_spec::{Limits, Manifest, RuntimeError};
use serde_json::json;

const MANIFEST: &str = r#"agent_control_specification_version: 0.4.0-alpha.1
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
"#;

#[test]
fn string_chain_file_and_json_entry_points_agree() {
    let expected = Manifest::from_yaml_str(MANIFEST).unwrap();
    assert_eq!(Manifest::parse_yaml_str(MANIFEST).unwrap(), expected);
    assert_eq!(Manifest::from_yaml_chain(&[MANIFEST]).unwrap(), expected);
    let serialized = serde_json::to_string(&expected).unwrap();
    assert_eq!(Manifest::from_json_str(&serialized).unwrap(), expected);
    assert_eq!(Manifest::from_yaml_str(&serialized).unwrap(), expected);

    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("yaml-parser-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("manifest.yaml");
    std::fs::write(&path, MANIFEST).unwrap();
    assert_eq!(Manifest::from_path(&path).unwrap(), expected);
    let larger_source = format!("{MANIFEST}# {}\n", "x".repeat(1_048_576));
    std::fs::write(&path, larger_source).unwrap();
    assert!(Manifest::from_path(&path).is_err());
    assert_eq!(
        Manifest::from_path_with_limits(
            &path,
            Limits {
                max_merged_manifest_bytes: 2_097_152,
                ..Limits::default()
            },
        )
        .unwrap(),
        expected
    );
    std::fs::write(&path, format!("{MANIFEST}\n---\n{MANIFEST}")).unwrap();
    let error = Manifest::from_path(&path).unwrap_err();
    assert!(error.detail().contains("manifest.yaml"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn typed_policy_maps_keep_nested_values_and_aliases() {
    let source = MANIFEST.replace(
        "    type: test",
        "    type: test\n    nested: &data {array: [true, null, 7, 1.5, \"7\"]}\n    copy: *data\n    literal: {<<: {key: value}}\n    flags: [True, FALSE, tRuE, !!bool TRUE, !!str TRUE]",
    );
    let manifest = Manifest::from_yaml_str(&source).unwrap();
    let value = serde_json::to_value(manifest).unwrap();
    assert_eq!(
        value["policies"]["p"]["nested"],
        value["policies"]["p"]["copy"]
    );
    assert_eq!(
        value["policies"]["p"]["nested"]["array"],
        json!([true, null, 7, 1.5, "7"])
    );
    assert_eq!(
        value["policies"]["p"]["literal"],
        json!({"<<": {"key": "value"}})
    );
    assert_eq!(
        value["policies"]["p"]["flags"],
        json!([true, false, "tRuE", true, "TRUE"])
    );
}

#[test]
fn malformed_unsupported_and_duplicate_values_are_rejected() {
    for field in [
        "    value: !custom prod",
        "    value: {1: prod}",
        "    value: {nested: !custom prod}",
        "    value: .nan",
        "    value: .inf",
        "    value: 18446744073709551616",
        "    value: -9223372036854775809",
        "    value: 0x10000000000000000",
        "    value: {key: one, key: two}",
        "    value: one\n    value: two",
    ] {
        let source = MANIFEST.replace("    type: test", &format!("    type: test\n{field}"));
        assert!(Manifest::parse_yaml_str(&source).is_err(), "{field}");
        assert!(Manifest::from_yaml_str(&source).is_err(), "{field}");
        assert!(Manifest::from_yaml_chain(&[&source]).is_err(), "{field}");
    }
    for source in [
        "".to_string(),
        "{bad".into(),
        format!("{MANIFEST}---\n{MANIFEST}"),
    ] {
        assert!(Manifest::from_yaml_str(&source).is_err());
    }
}

#[test]
fn legacy_numeric_strings_are_not_reinterpreted_as_limits() {
    for scalar in ["010", "1_000", "1:2:3", "0X10"] {
        let source = format!("{MANIFEST}metadata:\n  value: {scalar}\n");
        let manifest = Manifest::from_yaml_str(&source).unwrap();
        assert_eq!(manifest.metadata["value"], scalar);
        let invalid = format!("{MANIFEST}approval:\n  timeout_seconds: {scalar}\n");
        assert!(Manifest::from_yaml_str(&invalid).is_err(), "{scalar}");
    }
}

#[test]
fn invalid_extends_reports_the_field_context_without_accepting_a_new_shape() {
    let invalid = format!("{MANIFEST}extends:\n  - path: ./parent.yaml\n");
    let error = Manifest::parse_yaml_str(&invalid).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(error.detail().contains("extends"));

    let valid = format!("{MANIFEST}extends:\n  - ./parent.yaml\n");
    assert!(Manifest::parse_yaml_str(&valid).is_ok());
}

#[test]
fn yaml_resources_are_bounded_for_single_and_chain_parsing() {
    let mut bomb = String::from("    a0: &a0 [x, x]\n");
    for i in 1..20 {
        bomb.push_str(&format!("    a{i}: &a{i} [*a{}, *a{}]\n", i - 1, i - 1));
    }

    for source in [
        " ".repeat(1_048_577),
        MANIFEST.replace(
            "    type: test",
            &format!(
                "    type: test\n    value: {}0{}",
                "[".repeat(70),
                "]".repeat(70)
            ),
        ),
        MANIFEST.replace("    type: test", &format!("    type: test\n{bomb}")),
    ] {
        let result = Manifest::parse_yaml_str(&source);
        assert!(
            matches!(result, Err(RuntimeError::ResourceLimitExceeded(_))),
            "{result:?}"
        );
        assert!(matches!(
            Manifest::from_yaml_chain(&[&source]),
            Err(RuntimeError::ResourceLimitExceeded(_))
        ));
    }
}
