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

struct ScratchDirectory(std::path::PathBuf);

impl ScratchDirectory {
    fn new(name: &str) -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn string_chain_file_and_json_entry_points_agree() {
    let expected = Manifest::from_yaml_str(MANIFEST).unwrap();
    assert_eq!(Manifest::parse_yaml_str(MANIFEST).unwrap(), expected);
    assert_eq!(Manifest::from_yaml_chain(&[MANIFEST]).unwrap(), expected);
    let serialized = serde_json::to_string(&expected).unwrap();
    assert_eq!(Manifest::from_json_str(&serialized).unwrap(), expected);
    assert_eq!(Manifest::from_yaml_str(&serialized).unwrap(), expected);

    let directory = ScratchDirectory::new("yaml-parser");
    let path = directory.0.join("manifest.yaml");
    std::fs::write(&path, MANIFEST).unwrap();
    assert_eq!(Manifest::from_path(&path).unwrap(), expected);
    let larger_source = format!("{MANIFEST}# {}\n", "x".repeat(1_048_576));
    std::fs::write(&path, larger_source).unwrap();
    assert!(matches!(
        Manifest::from_path(&path),
        Err(RuntimeError::ResourceLimitExceeded(_))
    ));
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
}

#[test]
fn typed_strings_and_keys_require_string_scalars() {
    for scalar in ["1", "1.0", "true", "null", ""] {
        let source = MANIFEST.replace(
            "policy_target: $snap.input",
            &format!("policy_target: {scalar}"),
        );
        assert!(
            matches!(
                Manifest::parse_yaml_str(&source),
                Err(RuntimeError::ManifestInvalid(_))
            ),
            "{scalar}"
        );
        let source = format!("{MANIFEST}metadata: {{{scalar}: value}}");
        assert!(Manifest::parse_yaml_str(&source).is_err(), "{scalar}");
    }
    for scalar in ["1", "1.0", "true", "null"] {
        let source = MANIFEST.replace(
            "policy_target: $snap.input",
            &format!("policy_target: \"{scalar}\""),
        );
        assert!(Manifest::parse_yaml_str(&source).is_ok(), "{scalar}");
        let source = format!("{MANIFEST}metadata: {{\"{scalar}\": value}}");
        assert!(Manifest::parse_yaml_str(&source).is_ok(), "{scalar}");
    }
    let source = MANIFEST.replace("policy_target: $snap.input", "policy_target: \"\"");
    assert!(Manifest::parse_yaml_str(&source).is_ok());
}

#[test]
fn structures_are_maps_and_errors_retain_paths_and_locations() {
    for source in [
        "- 0.4.0-alpha.1\n- {}\n- []\n- {p: {type: test}}\n- {input: {policy_target: $snap.input, policy: {id: p}}}\n".into(),
        MANIFEST.replace("    policy:\n      id: p", "    policy: [p]"),
        MANIFEST.replace("    policy_target: $snap.input\n    policy:\n      id: p", "    [\"$snap.input\", null, null, {}, {id: p}]"),
        format!("{MANIFEST}extends: [[https://example.com/base.yaml]]"),
        format!("{MANIFEST}approval: [deny]"),
    ] {
        let error = Manifest::parse_yaml_str(&source).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid", "{source}");
        assert!(Manifest::from_yaml_chain(&[&source]).is_err());
    }
    for (source, path) in [
        (
            MANIFEST.replace("id: p", "foo: p"),
            "intervention_points.input.policy",
        ),
        (
            MANIFEST.replace("  input:", "  state:"),
            "intervention_points",
        ),
        (
            MANIFEST.replace("    policy:\n      id: p", "    policy: p"),
            "intervention_points.input.policy",
        ),
        (
            format!("{MANIFEST}extends: [{{path: ./parent.yaml}}]"),
            "extends",
        ),
    ] {
        let error = Manifest::parse_yaml_str(&source).unwrap_err();
        assert!(error.detail().contains(path), "{error}");
        assert!(
            error.detail().contains("line ") && error.detail().contains("column "),
            "{error}"
        );
    }
}

#[test]
fn tabs_bom_and_explicit_scalar_tags() {
    for scalar in ["1", "abc", "-1"] {
        let block = format!("{MANIFEST}metadata:\n  value:\t{scalar}\n");
        let flow = format!("{MANIFEST}metadata: {{value:\t{scalar}}}");
        assert_eq!(
            Manifest::parse_yaml_str(&block).unwrap(),
            Manifest::parse_yaml_str(&flow).unwrap()
        );
    }
    assert!(Manifest::parse_yaml_str(&format!("{MANIFEST}metadata:\n\tvalue: 1")).is_err());
    assert_eq!(
        Manifest::parse_yaml_str(&format!("\u{feff}{MANIFEST}")).unwrap(),
        Manifest::parse_yaml_str(MANIFEST).unwrap()
    );
    assert!(Manifest::parse_yaml_str(&format!("{MANIFEST}\u{feff}metadata: {{}}")).is_err());
    for scalar in [
        "! 7",
        "! abc",
        "! \"7\"",
        "! true",
        "! {}",
        "! []",
        "!<!> 7",
        "! |-\n    7",
    ] {
        let error = Manifest::parse_yaml_str(&format!("{MANIFEST}metadata:\n  value: {scalar}"))
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid", "{scalar}");
    }
    for scalar in ["!!null \"\"", "!!null |-\n"] {
        let parsed =
            Manifest::parse_yaml_str(&format!("{MANIFEST}metadata:\n  value: {scalar}")).unwrap();
        assert_eq!(parsed.metadata["value"], json!(null));
    }
    let parsed = Manifest::parse_yaml_str(&format!(
        "{MANIFEST}approval: {{timeout_seconds: !!int \"1\"}}"
    ))
    .unwrap();
    assert_eq!(parsed.approval.unwrap().timeout_seconds, Some(1));
    let parsed =
        Manifest::parse_yaml_str(&format!("{MANIFEST}approval: {{timeout_seconds: -0}}")).unwrap();
    assert_eq!(parsed.approval.as_ref().unwrap().timeout_seconds, Some(0));
    assert!(parsed.validate().is_err());
    let source = MANIFEST.replace(
        "policy_target: $snap.input",
        "policy_target: $snap.input\n    policy_target_kind: !!null \"\"",
    );
    assert!(Manifest::from_yaml_str(&source)
        .unwrap()
        .intervention_points[&agent_control_spec::InterceptionPoint::Input]
        .policy_target_kind
        .is_none());
}

#[test]
fn budgets_are_configurable_and_independent_from_policy_depth() {
    let limits = Limits {
        max_policy_input_depth: 0,
        ..Limits::default()
    };
    assert!(Manifest::from_yaml_str_with_limits(MANIFEST, limits).is_ok());
    let source = format!(
        "{MANIFEST}metadata:\n  anchor: &a x\n  copies: [{}]\n",
        vec!["*a"; 1000].join(",")
    );
    assert_eq!(
        Manifest::parse_yaml_str(&source).unwrap().metadata["copies"]
            .as_array()
            .unwrap()
            .len(),
        1000
    );
    let maximum_aliases = format!(
        "{MANIFEST}metadata:\n  anchor: &a x\n  copies: [{}]\n",
        vec!["*a"; Limits::default().max_manifest_aliases].join(",")
    );
    assert_eq!(
        Manifest::parse_yaml_str(&maximum_aliases).unwrap().metadata["copies"]
            .as_array()
            .unwrap()
            .len(),
        Limits::default().max_manifest_aliases
    );
    for limits in [
        Limits {
            max_manifest_depth: 1,
            ..Limits::default()
        },
        Limits {
            max_manifest_nodes: 1,
            ..Limits::default()
        },
        Limits {
            max_manifest_events: 1,
            ..Limits::default()
        },
        Limits {
            max_manifest_aliases: 999,
            ..Limits::default()
        },
        Limits {
            max_manifest_anchors: 0,
            ..Limits::default()
        },
        Limits {
            max_manifest_anchor_events: 0,
            ..Limits::default()
        },
    ] {
        let error = Manifest::parse_yaml_str_with_limits(&source, limits).unwrap_err();
        assert_eq!(
            error.reason(),
            "runtime_error:resource_limit_exceeded",
            "{error}"
        );
    }
    let source = format!("{MANIFEST}metadata: [{}]", vec!["x"; 100_001].join(","));
    assert!(matches!(
        Manifest::parse_yaml_str(&source),
        Err(RuntimeError::ResourceLimitExceeded(_))
    ));
    assert!(Manifest::parse_yaml_str_with_limits(
        &source,
        Limits {
            max_manifest_nodes: 110_000,
            ..Limits::default()
        }
    )
    .is_ok());
    let source = format!("{MANIFEST}metadata: [{}]", vec!["x"; 300_001].join(","));
    let error = Manifest::parse_yaml_str(&source).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
    assert!(error.detail().contains("event limit"));
}

#[test]
fn json_loader_source_is_bounded_even_when_padding_compacts_away() {
    let directory = ScratchDirectory::new("json-parser-source");
    let path = directory.0.join("manifest.json");
    let json = serde_json::to_string(&Manifest::parse_yaml_str(MANIFEST).unwrap()).unwrap();
    std::fs::write(&path, format!("{json}{}", " ".repeat(1_048_576))).unwrap();
    assert!(matches!(
        Manifest::from_path(&path),
        Err(RuntimeError::ResourceLimitExceeded(_))
    ));
    assert!(Manifest::from_path_with_limits(
        &path,
        Limits {
            max_merged_manifest_bytes: 2_097_152,
            ..Limits::default()
        }
    )
    .is_ok());
}

#[test]
fn parser_errors_are_for_authors_not_parser_configuration_advice() {
    for source in [
        format!("{MANIFEST}metadata: {{key: one, key: two}}"),
        format!("{MANIFEST}metadata: {{key: .inf}}"),
        MANIFEST.replace("type: test", "type: null"),
    ] {
        let error = Manifest::parse_yaml_str(&source).unwrap_err();
        for internal in [
            "DuplicateKeyPolicy",
            "Options",
            "Option<String>",
            "reject_non_finite",
        ] {
            assert!(!error.detail().contains(internal), "{error}");
        }
    }
}

#[test]
fn tagged_blocks_preserve_metadata_and_sibling_fields() {
    for (block, expected) in [
        ("!!bool |-\n    TRUE", json!(true)),
        ("!!int >-\n    7", json!(7)),
        ("!!float |-\n    7", json!(7.0)),
        ("!!str |-\n    first\n    second", json!("first\nsecond")),
        ("!!str >-\n    first\n    second", json!("first second")),
        ("!!null |-\n", json!(null)),
    ] {
        let source = format!("{MANIFEST}metadata:\n  value: {block}\n  required: true\n");
        let manifest = Manifest::from_yaml_str(&source).unwrap();
        assert_eq!(
            manifest.metadata,
            json!({"value": expected, "required": true}),
            "{block}"
        );
    }
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
        "    value: !!bool null",
        "    value: !!int null",
        "    value: !!float null",
        "    value: !!null garbage",
        "    value: !custom null",
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
