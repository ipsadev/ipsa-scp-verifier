use tools::sync::*;

#[test]
fn substitutions_apply_in_order() {
    let out = substitute(
        "use crate::error::ContractError;\nfn f() -> ContractError",
        &VENDOR_RULES,
    );
    assert!(out.starts_with("use crate::scp::error::ScpError;"));
    assert!(out.ends_with("fn f() -> ScpError"));
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
