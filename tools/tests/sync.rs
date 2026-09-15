use tools::sync::*;

#[test]
fn the_scp_rule_is_applied_before_the_error_rule() {
    let out = substitute(
        "use crate::scp::error::ScpError;\nuse crate::error::Local;",
        &VERIFY_RULES,
    );
    assert_eq!(
        out,
        "use stellar_consensus_verifier::error::ScpError;\nuse super::error::Local;"
    );
}

#[test]
fn report_only_names_the_report_module() {
    let out = substitute("use crate::report;\nreport::ok(\"x\");", &VERIFY_RULES);
    assert_eq!(out, "use crate::logger;\nlogger::ok(\"x\");");
}

#[test]
fn identical_text_has_no_difference() {
    assert!(first_difference("a\nb\n", "a\nb\n").is_none());
    assert!(first_difference("a\nb\n", "a\nc\n").is_some());
}
