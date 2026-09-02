#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use serctl_policy::compile_policy_json;

fuzz_target!(|data: &[u8]| {
    // Keep the raw document path for grammar, duplicate-field, UTF-8 and
    // document-size coverage.
    let _ = compile_policy_json(data);

    // Also drive every input through a structurally valid document so a
    // short, seedless run reaches the production compiler and deny-rule
    // normalization instead of spending all of its budget rediscovering JSON
    // punctuation. Mapping to lowercase ASCII makes interpolation unambiguous
    // and bounded without introducing a second JSON implementation here.
    let program = data
        .iter()
        .take(128)
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect::<String>();
    let structured = format!(
        r#"{{"schema_version":1,"base":"red","run_as":[{{"kind":"uid","value":1000}}],"deny":[{{"kind":"program","name":"{program}"}}]}}"#
    );
    let _ = compile_policy_json(structured.as_bytes());
});
