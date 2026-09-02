//! Canonical, deny-only policy compilation for serctl typed intents.
//!
//! This crate deliberately has no daemon, SSH, filesystem, or UI integration.
//! It turns a bounded schema-v1 policy document into a normalized IR and a
//! stable SHA-256 digest, then evaluates typed intents without executing them.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const POLICY_SCHEMA_VERSION: u16 = 1;
pub const INTENT_SCHEMA_VERSION: u16 = 1;

pub const MAX_POLICY_DOCUMENT_BYTES: usize = 64 * 1024;
pub const MAX_POLICY_CAPABILITIES: usize = 16;
pub const MAX_POLICY_IDENTITIES: usize = 16;
pub const MAX_POLICY_DENY_RULES: usize = 256;
pub const MAX_PROCESS_PROGRAMS: usize = 32;
pub const MAX_PROCESS_ENV_KEYS: usize = 16;

pub const MAX_PROGRAM_BYTES: usize = 128;
pub const MAX_IDENTITY_BYTES: usize = 64;
pub const MAX_ENV_NAME_BYTES: usize = 64;
pub const MAX_ENV_VALUE_BYTES: usize = 1024;
pub const MAX_ENV_COUNT: usize = 16;
pub const MAX_ENV_TOTAL_BYTES: usize = 8 * 1024;
pub const MAX_ARG_COUNT: usize = 64;
pub const MAX_ARG_BYTES: usize = 4 * 1024;
pub const MAX_ARG_TOTAL_BYTES: usize = 16 * 1024;
pub const MAX_PATH_COUNT: usize = 8;
pub const MAX_PATH_BYTES: usize = 4 * 1024;

const POLICY_DIGEST_DOMAIN: &[u8] = b"serctl-policy-ir-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseTemplate {
    Green,
    Yellow,
    Red,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    FsList,
    FsRead,
    ProcessInspect,
    FsWriteNew,
    TransferRead,
    TransferWrite,
    ProcessRun,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunAs {
    User { name: String },
    Uid { value: u32 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathFlavor {
    Posix,
    Windows,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentPath {
    pub flavor: PathFlavor,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntentBudget {
    pub bytes: u64,
    pub output_bytes: u64,
    pub parallel: u16,
    pub operations: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedIntent {
    pub schema_version: u16,
    pub capability: Capability,
    pub run_as: RunAs,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default)]
    pub paths: Vec<IntentPath>,
    pub budget: IntentBudget,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsOverlay {
    #[serde(default)]
    pub max_deadline_ms: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    #[serde(default)]
    pub max_parallel: Option<u16>,
    #[serde(default)]
    pub max_operations: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOverlay {
    /// A subset of the selected base template's fixed program identifiers.
    /// `None` inherits the base set; an empty list denies all process programs.
    #[serde(default)]
    pub programs: Option<Vec<String>>,
    /// A subset of the selected base template's fixed environment keys.
    #[serde(default)]
    pub env_keys: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DenyRule {
    Capability { capability: Capability },
    Program { name: String },
    PathPrefix { flavor: PathFlavor, value: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u16,
    pub base: BaseTemplate,
    /// Optional narrowing selection. Every entry must already exist in `base`.
    #[serde(default)]
    pub capabilities: Option<Vec<Capability>>,
    /// Explicit non-root execution identities. The compiler sorts and deduplicates.
    pub run_as: Vec<RunAs>,
    #[serde(default)]
    pub limits: LimitsOverlay,
    #[serde(default)]
    pub process: ProcessOverlay,
    #[serde(default)]
    pub deny: Vec<DenyRule>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonCode {
    Allowed,
    SchemaInvalid,
    SchemaUnsupported,
    PolicyTooLarge,
    PolicyLimitExceeded,
    CapabilityExpandsBase,
    IdentityExpandsBase,
    ProgramExpandsBase,
    EnvironmentExpandsBase,
    InvariantRootRunAs,
    InvariantCommandInterpreter,
    InvariantShellCommandFlag,
    InvariantDangerousProgram,
    InvariantEnvironmentInjection,
    InvariantControlCharacter,
    InvariantPathTraversal,
    InvariantPathNotAbsolute,
    InvariantAmbiguousPath,
    IntentShapeMismatch,
    IntentCapabilityDenied,
    IntentIdentityDenied,
    IntentProgramDenied,
    IntentEnvironmentDenied,
    IntentPathDenied,
    IntentDeadlineInvalid,
    IntentDeadlineExceeded,
    IntentBudgetInvalid,
    IntentBudgetExceeded,
    IntentArgumentLimitExceeded,
    IntentEnvironmentLimitExceeded,
    IntentPathLimitExceeded,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::SchemaInvalid => "schema.invalid",
            Self::SchemaUnsupported => "schema.unsupported",
            Self::PolicyTooLarge => "policy.too_large",
            Self::PolicyLimitExceeded => "policy.limit_exceeded",
            Self::CapabilityExpandsBase => "policy.capability_expands_base",
            Self::IdentityExpandsBase => "policy.identity_expands_base",
            Self::ProgramExpandsBase => "policy.program_expands_base",
            Self::EnvironmentExpandsBase => "policy.environment_expands_base",
            Self::InvariantRootRunAs => "invariant.root_run_as",
            Self::InvariantCommandInterpreter => "invariant.command_interpreter",
            Self::InvariantShellCommandFlag => "invariant.shell_command_flag",
            Self::InvariantDangerousProgram => "invariant.dangerous_program",
            Self::InvariantEnvironmentInjection => "invariant.environment_injection",
            Self::InvariantControlCharacter => "invariant.control_character",
            Self::InvariantPathTraversal => "invariant.path_traversal",
            Self::InvariantPathNotAbsolute => "invariant.path_not_absolute",
            Self::InvariantAmbiguousPath => "invariant.ambiguous_path",
            Self::IntentShapeMismatch => "intent.shape_mismatch",
            Self::IntentCapabilityDenied => "intent.capability_denied",
            Self::IntentIdentityDenied => "intent.identity_denied",
            Self::IntentProgramDenied => "intent.program_denied",
            Self::IntentEnvironmentDenied => "intent.environment_denied",
            Self::IntentPathDenied => "intent.path_denied",
            Self::IntentDeadlineInvalid => "intent.deadline_invalid",
            Self::IntentDeadlineExceeded => "intent.deadline_exceeded",
            Self::IntentBudgetInvalid => "intent.budget_invalid",
            Self::IntentBudgetExceeded => "intent.budget_exceeded",
            Self::IntentArgumentLimitExceeded => "intent.argument_limit_exceeded",
            Self::IntentEnvironmentLimitExceeded => "intent.environment_limit_exceeded",
            Self::IntentPathLimitExceeded => "intent.path_limit_exceeded",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ReasonCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError {
    code: ReasonCode,
    message: String,
}

impl PolicyError {
    fn new(code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> ReasonCode {
        self.code
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveLimits {
    pub max_deadline_ms: u64,
    pub max_bytes: u64,
    pub max_output_bytes: u64,
    pub max_parallel: u16,
    pub max_operations: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedPath {
    pub flavor: PathFlavor,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIr {
    schema_version: u16,
    base: BaseTemplate,
    capabilities: BTreeSet<Capability>,
    run_as: BTreeSet<RunAs>,
    limits: EffectiveLimits,
    process_programs: BTreeSet<String>,
    process_env_keys: BTreeSet<String>,
    allowed_paths: BTreeSet<NormalizedPath>,
    denied_paths: BTreeSet<NormalizedPath>,
}

impl PolicyIr {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn base(&self) -> BaseTemplate {
        self.base
    }

    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    pub fn run_as(&self) -> &BTreeSet<RunAs> {
        &self.run_as
    }

    pub const fn limits(&self) -> EffectiveLimits {
        self.limits
    }

    pub fn process_programs(&self) -> &BTreeSet<String> {
        &self.process_programs
    }

    pub fn process_env_keys(&self) -> &BTreeSet<String> {
        &self.process_env_keys
    }

    /// Immutable base-template path ceiling. An empty set means every
    /// path-bearing capability fails closed.
    pub fn allowed_paths(&self) -> &BTreeSet<NormalizedPath> {
        &self.allowed_paths
    }

    pub fn denied_paths(&self) -> &BTreeSet<NormalizedPath> {
        &self.denied_paths
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        // PolicyIr has fixed field order and only ordered collections. This is
        // the schema-v1 canonical representation covered by digest fixtures.
        serde_json::to_vec(self).map_err(|error| {
            PolicyError::new(
                ReasonCode::SchemaInvalid,
                format!("serialize canonical policy IR: {error}"),
            )
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PolicyDigest(String);

impl PolicyDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicy {
    ir: PolicyIr,
    digest: PolicyDigest,
}

impl CompiledPolicy {
    pub fn ir(&self) -> &PolicyIr {
        &self.ir
    }

    pub fn digest(&self) -> &PolicyDigest {
        &self.digest
    }

    /// Return the exact ordered schema-v1 IR representation covered by the
    /// policy digest (the digest additionally includes its domain separator).
    pub fn canonical_ir_json(&self) -> Result<Vec<u8>, PolicyError> {
        self.ir.canonical_bytes()
    }

    /// Validate and explain an intent without performing any external action.
    pub fn explain(&self, intent: &TypedIntent) -> Explanation {
        match evaluate_intent(&self.ir, intent) {
            Ok(()) => Explanation::allowed(&self.digest),
            Err(code) => Explanation::denied(&self.digest, code),
        }
    }

    /// Alias that makes the no-side-effect contract explicit to callers.
    pub fn dry_run(&self, intent: &TypedIntent) -> Explanation {
        self.explain(intent)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    pub allowed: bool,
    pub reason_code: ReasonCode,
    pub policy_digest: PolicyDigest,
}

impl Explanation {
    fn allowed(digest: &PolicyDigest) -> Self {
        Self {
            allowed: true,
            reason_code: ReasonCode::Allowed,
            policy_digest: digest.clone(),
        }
    }

    fn denied(digest: &PolicyDigest, reason_code: ReasonCode) -> Self {
        Self {
            allowed: false,
            reason_code,
            policy_digest: digest.clone(),
        }
    }
}

pub fn compile_policy_json(bytes: &[u8]) -> Result<CompiledPolicy, PolicyError> {
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(PolicyError::new(
            ReasonCode::PolicyTooLarge,
            "policy document exceeds 64 KiB",
        ));
    }
    let document: PolicyDocument = serde_json::from_slice(bytes).map_err(|error| {
        PolicyError::new(
            ReasonCode::SchemaInvalid,
            format!("parse policy schema: {error}"),
        )
    })?;
    compile_policy(document)
}

pub fn compile_policy(document: PolicyDocument) -> Result<CompiledPolicy, PolicyError> {
    if document.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::new(
            ReasonCode::SchemaUnsupported,
            "policy schema_version must be 1",
        ));
    }
    enforce_count(
        document.capabilities.as_ref().map_or(0, Vec::len),
        MAX_POLICY_CAPABILITIES,
        "policy capability selection",
    )?;
    if document.run_as.is_empty() {
        return Err(PolicyError::new(
            ReasonCode::PolicyLimitExceeded,
            "policy requires at least one explicit non-root run_as identity",
        ));
    }
    enforce_count(
        document.run_as.len(),
        MAX_POLICY_IDENTITIES,
        "policy run_as identities",
    )?;
    enforce_count(
        document.deny.len(),
        MAX_POLICY_DENY_RULES,
        "policy deny rules",
    )?;
    enforce_count(
        document.process.programs.as_ref().map_or(0, Vec::len),
        MAX_PROCESS_PROGRAMS,
        "process program selection",
    )?;
    enforce_count(
        document.process.env_keys.as_ref().map_or(0, Vec::len),
        MAX_PROCESS_ENV_KEYS,
        "process environment selection",
    )?;

    let base_capabilities = template_capabilities(document.base);
    let mut capabilities = match document.capabilities {
        Some(selected) => {
            let selected: BTreeSet<_> = selected.into_iter().collect();
            if !selected.is_subset(&base_capabilities) {
                return Err(PolicyError::new(
                    ReasonCode::CapabilityExpandsBase,
                    "capability selection is not a subset of its base template",
                ));
            }
            selected
        }
        None => base_capabilities,
    };

    let run_as = compile_identity_selection(document.base, document.run_as)?;

    let limits = compile_limits(document.base, document.limits)?;
    let base_programs = template_programs(document.base);
    let mut process_programs = compile_program_selection(
        document.process.programs,
        &base_programs,
        ReasonCode::ProgramExpandsBase,
    )?;
    let base_env_keys = template_env_keys(document.base);
    let mut process_env_keys = compile_env_selection(document.process.env_keys, &base_env_keys)?;
    let allowed_paths = template_allowed_paths(document.base);
    let mut denied_paths = BTreeSet::new();

    for rule in document.deny {
        match rule {
            DenyRule::Capability { capability } => {
                capabilities.remove(&capability);
            }
            DenyRule::Program { name } => {
                let normalized = normalize_program_identifier(&name)?;
                process_programs.remove(&normalized);
            }
            DenyRule::PathPrefix { flavor, value } => {
                denied_paths.insert(NormalizedPath {
                    flavor,
                    value: normalize_path(flavor, &value)?,
                });
            }
        }
    }

    if !capabilities.contains(&Capability::ProcessRun) {
        process_programs.clear();
        process_env_keys.clear();
    }
    if capabilities
        .iter()
        .any(|capability| capability_uses_path(*capability))
        && allowed_paths.is_empty()
    {
        return Err(PolicyError::new(
            ReasonCode::CapabilityExpandsBase,
            "path-bearing capabilities require a non-empty immutable base path ceiling",
        ));
    }

    let ir = PolicyIr {
        schema_version: POLICY_SCHEMA_VERSION,
        base: document.base,
        capabilities,
        run_as,
        limits,
        process_programs,
        process_env_keys,
        allowed_paths,
        denied_paths,
    };
    let canonical = ir.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DIGEST_DOMAIN);
    hasher.update(&canonical);
    let digest = PolicyDigest(hex::encode(hasher.finalize()));
    Ok(CompiledPolicy { ir, digest })
}

fn enforce_count(value: usize, limit: usize, label: &str) -> Result<(), PolicyError> {
    if value > limit {
        return Err(PolicyError::new(
            ReasonCode::PolicyLimitExceeded,
            format!("{label} exceeds its {limit}-item limit"),
        ));
    }
    Ok(())
}

fn template_capabilities(base: BaseTemplate) -> BTreeSet<Capability> {
    use Capability::*;
    let capabilities: &[Capability] = match base {
        // Beta has no universal filesystem root that is safe on every host.
        // Path-bearing capabilities therefore remain outside every template
        // until an executor can supply a fixed, handle-verified base root.
        BaseTemplate::Green | BaseTemplate::Yellow => &[ProcessInspect],
        BaseTemplate::Red => &[ProcessInspect, ProcessRun],
    };
    capabilities.iter().copied().collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityCeiling {
    /// Green/yellow inspection is deliberately confined to the conventional
    /// unprivileged account named by the base. The executor must still resolve
    /// and verify that identity without following aliases.
    NobodyOnly,
    /// Red's beta ProcessRun is limited to fixed, non-mutating program IDs.
    /// Its executor additionally proves that the requested UID is its own
    /// effective non-root UID before dispatch.
    NonRootUidForFixedProcess,
}

const fn template_identity_ceiling(base: BaseTemplate) -> IdentityCeiling {
    match base {
        BaseTemplate::Green | BaseTemplate::Yellow => IdentityCeiling::NobodyOnly,
        BaseTemplate::Red => IdentityCeiling::NonRootUidForFixedProcess,
    }
}

fn compile_identity_selection(
    base: BaseTemplate,
    selected: Vec<RunAs>,
) -> Result<BTreeSet<RunAs>, PolicyError> {
    let selected = selected
        .into_iter()
        .map(validate_run_as)
        .collect::<Result<BTreeSet<_>, _>>()?;
    let inside_ceiling = match template_identity_ceiling(base) {
        IdentityCeiling::NobodyOnly => selected
            .iter()
            .all(|identity| matches!(identity, RunAs::User { name } if name == "nobody")),
        IdentityCeiling::NonRootUidForFixedProcess => selected
            .iter()
            .all(|identity| matches!(identity, RunAs::Uid { value: 1.. })),
    };
    if !inside_ceiling {
        return Err(PolicyError::new(
            ReasonCode::IdentityExpandsBase,
            "run_as selection is not a subset of its base template identity ceiling",
        ));
    }
    Ok(selected)
}

fn template_allowed_paths(_base: BaseTemplate) -> BTreeSet<NormalizedPath> {
    // There is no host-independent path that is safe for arbitrary read,
    // write, or transfer. Empty is an intentional beta ceiling, not an
    // inherited wildcard.
    BTreeSet::new()
}

const fn capability_uses_path(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::FsList
            | Capability::FsRead
            | Capability::FsWriteNew
            | Capability::TransferRead
            | Capability::TransferWrite
    )
}

fn template_programs(base: BaseTemplate) -> BTreeSet<String> {
    let programs: &[&str] = match base {
        BaseTemplate::Green | BaseTemplate::Yellow => &[],
        BaseTemplate::Red => &["id", "true", "uname", "uptime", "whoami"],
    };
    programs.iter().map(|value| (*value).to_owned()).collect()
}

fn template_env_keys(base: BaseTemplate) -> BTreeSet<String> {
    let keys: &[&str] = match base {
        BaseTemplate::Green | BaseTemplate::Yellow => &[],
        BaseTemplate::Red => &["LANG", "LC_ALL", "TZ"],
    };
    keys.iter().map(|value| (*value).to_owned()).collect()
}

fn template_limits(base: BaseTemplate) -> EffectiveLimits {
    match base {
        BaseTemplate::Green => EffectiveLimits {
            max_deadline_ms: 60_000,
            max_bytes: 64 * 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
            max_parallel: 1,
            max_operations: 100,
        },
        BaseTemplate::Yellow => EffectiveLimits {
            max_deadline_ms: 300_000,
            max_bytes: 1024 * 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            max_parallel: 2,
            max_operations: 1_000,
        },
        BaseTemplate::Red => EffectiveLimits {
            // A remote build may legitimately need 20 minutes. Keep five
            // minutes outside this 35-minute execution ceiling for relay and
            // receipt handling under the separately enforced 40-minute grant
            // policy; overlays remain narrowing-only.
            max_deadline_ms: 2_100_000,
            max_bytes: 16 * 1024 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
            max_parallel: 4,
            max_operations: 1_000,
        },
    }
}

fn compile_limits(
    base: BaseTemplate,
    overlay: LimitsOverlay,
) -> Result<EffectiveLimits, PolicyError> {
    let inherited = template_limits(base);
    Ok(EffectiveLimits {
        max_deadline_ms: narrow_limit(
            overlay.max_deadline_ms,
            inherited.max_deadline_ms,
            "max_deadline_ms",
        )?,
        max_bytes: narrow_limit(overlay.max_bytes, inherited.max_bytes, "max_bytes")?,
        max_output_bytes: narrow_limit(
            overlay.max_output_bytes,
            inherited.max_output_bytes,
            "max_output_bytes",
        )?,
        max_parallel: narrow_limit(overlay.max_parallel, inherited.max_parallel, "max_parallel")?,
        max_operations: narrow_limit(
            overlay.max_operations,
            inherited.max_operations,
            "max_operations",
        )?,
    })
}

fn narrow_limit<T>(selected: Option<T>, inherited: T, label: &str) -> Result<T, PolicyError>
where
    T: Copy + Ord + From<u8>,
{
    let selected = selected.unwrap_or(inherited);
    if selected < T::from(1) || selected > inherited {
        return Err(PolicyError::new(
            ReasonCode::PolicyLimitExceeded,
            format!("{label} must be nonzero and cannot exceed its base template"),
        ));
    }
    Ok(selected)
}

fn compile_program_selection(
    selected: Option<Vec<String>>,
    inherited: &BTreeSet<String>,
    expansion_code: ReasonCode,
) -> Result<BTreeSet<String>, PolicyError> {
    let Some(selected) = selected else {
        return Ok(inherited.clone());
    };
    let selected = selected
        .into_iter()
        .map(|program| {
            let normalized = normalize_program_identifier(&program)?;
            validate_program_invariant(&normalized)?;
            Ok(normalized)
        })
        .collect::<Result<BTreeSet<_>, PolicyError>>()?;
    if !selected.is_subset(inherited) {
        return Err(PolicyError::new(
            expansion_code,
            "program selection is not a subset of its base template",
        ));
    }
    Ok(selected)
}

fn compile_env_selection(
    selected: Option<Vec<String>>,
    inherited: &BTreeSet<String>,
) -> Result<BTreeSet<String>, PolicyError> {
    let Some(selected) = selected else {
        return Ok(inherited.clone());
    };
    let selected = selected
        .into_iter()
        .map(|key| normalize_env_key(&key))
        .collect::<Result<BTreeSet<_>, PolicyError>>()?;
    if !selected.is_subset(inherited) {
        return Err(PolicyError::new(
            ReasonCode::EnvironmentExpandsBase,
            "environment selection is not a subset of its base template",
        ));
    }
    Ok(selected)
}

fn validate_run_as(run_as: RunAs) -> Result<RunAs, PolicyError> {
    match &run_as {
        RunAs::Uid { value: 0 } => Err(PolicyError::new(
            ReasonCode::InvariantRootRunAs,
            "UID 0 is an invariant denial",
        )),
        RunAs::Uid { .. } => Ok(run_as),
        RunAs::User { name } => {
            validate_plain_text(name, MAX_IDENTITY_BYTES)?;
            let root_alias = name.eq_ignore_ascii_case("root")
                || name.parse::<u32>().ok().is_some_and(|value| value == 0);
            if root_alias {
                return Err(PolicyError::new(
                    ReasonCode::InvariantRootRunAs,
                    "root identity is an invariant denial",
                ));
            }
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                return Err(PolicyError::new(
                    ReasonCode::SchemaInvalid,
                    "run_as user must be a bounded ASCII account name",
                ));
            }
            Ok(run_as)
        }
    }
}

fn normalize_program_identifier(program: &str) -> Result<String, PolicyError> {
    validate_plain_text(program, MAX_PROGRAM_BYTES)?;
    if program.is_empty()
        || !program
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(PolicyError::new(
            ReasonCode::SchemaInvalid,
            "program must be an identifier resolved by a fixed helper allowlist",
        ));
    }
    let mut normalized = program.to_ascii_lowercase();
    if let Some(without_suffix) = normalized.strip_suffix(".exe") {
        normalized = without_suffix.to_owned();
    }
    Ok(normalized)
}

fn normalize_env_key(key: &str) -> Result<String, PolicyError> {
    validate_plain_text(key, MAX_ENV_NAME_BYTES)?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(PolicyError::new(
            ReasonCode::SchemaInvalid,
            "environment keys must use uppercase ASCII identifiers",
        ));
    }
    if is_dangerous_env_key(key) {
        return Err(PolicyError::new(
            ReasonCode::InvariantEnvironmentInjection,
            "environment key is an invariant denial",
        ));
    }
    Ok(key.to_owned())
}

fn validate_plain_text(value: &str, max_bytes: usize) -> Result<(), PolicyError> {
    if value.len() > max_bytes {
        return Err(PolicyError::new(
            ReasonCode::PolicyLimitExceeded,
            "text value exceeds its byte limit",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(PolicyError::new(
            ReasonCode::InvariantControlCharacter,
            "control characters are an invariant denial",
        ));
    }
    Ok(())
}

fn validate_program_invariant(program: &str) -> Result<(), PolicyError> {
    if is_command_interpreter(program) {
        return Err(PolicyError::new(
            ReasonCode::InvariantCommandInterpreter,
            "command interpreters are an invariant denial",
        ));
    }
    if is_dangerous_program(program) {
        return Err(PolicyError::new(
            ReasonCode::InvariantDangerousProgram,
            "dangerous command family is an invariant denial",
        ));
    }
    Ok(())
}

fn is_command_interpreter(program: &str) -> bool {
    matches!(
        program,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "ksh"
            | "fish"
            | "csh"
            | "tcsh"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "wscript"
            | "cscript"
            | "mshta"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
            | "osascript"
    )
}

fn is_dangerous_program(program: &str) -> bool {
    program.starts_with("mkfs.")
        || matches!(
            program,
            "rm" | "rmdir"
                | "dd"
                | "mkfs"
                | "fdisk"
                | "sfdisk"
                | "cfdisk"
                | "parted"
                | "wipefs"
                | "shred"
                | "chmod"
                | "chown"
                | "chgrp"
                | "setfacl"
                | "mount"
                | "umount"
                | "reboot"
                | "shutdown"
                | "poweroff"
                | "halt"
                | "init"
                | "systemctl"
                | "sudo"
                | "su"
                | "doas"
                | "pkexec"
                | "reg"
                | "regedit"
                | "sc"
                | "net"
                | "netsh"
                | "diskpart"
                | "format"
                | "bcdedit"
                | "cipher"
                | "takeown"
                | "icacls"
        )
}

fn is_dangerous_env_key(key: &str) -> bool {
    key == "PATH"
        || key == "IFS"
        || key == "ENV"
        || key == "BASH_ENV"
        || key == "SHELLOPTS"
        || key == "PYTHONPATH"
        || key.starts_with("LD_")
        || key.starts_with("DYLD_")
}

fn is_shell_command_flag(argument: &str) -> bool {
    matches!(
        argument.to_ascii_lowercase().as_str(),
        "-c" | "/c" | "--command" | "-command" | "-encodedcommand"
    )
}

fn normalize_path(flavor: PathFlavor, value: &str) -> Result<String, PolicyError> {
    validate_plain_text(value, MAX_PATH_BYTES)?;
    if value.contains('%')
        || value.contains('\u{2044}')
        || value.contains('\u{2215}')
        || value.contains('\u{ff0f}')
        || value.contains('\u{ff3c}')
    {
        return Err(PolicyError::new(
            ReasonCode::InvariantAmbiguousPath,
            "encoded or ambiguous path separators are denied",
        ));
    }
    match flavor {
        PathFlavor::Posix => normalize_posix_path(value),
        PathFlavor::Windows => normalize_windows_path(value),
    }
}

fn normalize_posix_path(value: &str) -> Result<String, PolicyError> {
    if !value.starts_with('/') {
        return Err(PolicyError::new(
            ReasonCode::InvariantPathNotAbsolute,
            "POSIX policy paths must be absolute",
        ));
    }
    if value.contains('\\') {
        return Err(PolicyError::new(
            ReasonCode::InvariantAmbiguousPath,
            "backslashes are denied in POSIX policy paths",
        ));
    }
    let mut components = Vec::new();
    for component in value.split('/').filter(|component| !component.is_empty()) {
        if component == "." || component == ".." {
            return Err(PolicyError::new(
                ReasonCode::InvariantPathTraversal,
                "dot path components are denied",
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn normalize_windows_path(value: &str) -> Result<String, PolicyError> {
    let canonical = value.replace('\\', "/");
    if canonical.starts_with("//") || canonical.len() < 3 {
        return Err(PolicyError::new(
            ReasonCode::InvariantPathNotAbsolute,
            "Windows policy paths must be absolute drive paths, not UNC/device paths",
        ));
    }
    let bytes = canonical.as_bytes();
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'/' {
        return Err(PolicyError::new(
            ReasonCode::InvariantPathNotAbsolute,
            "Windows policy paths must use an absolute drive prefix",
        ));
    }
    let mut components = Vec::new();
    for component in canonical[3..]
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if component == "." || component == ".." {
            return Err(PolicyError::new(
                ReasonCode::InvariantPathTraversal,
                "dot path components are denied",
            ));
        }
        if component.contains(':')
            || component.ends_with('.')
            || component.ends_with(' ')
            || is_windows_reserved_component(component)
        {
            return Err(PolicyError::new(
                ReasonCode::InvariantAmbiguousPath,
                "ambiguous Windows path component is denied",
            ));
        }
        components.push(component);
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    if components.is_empty() {
        Ok(format!("{drive}:/"))
    } else {
        Ok(format!("{drive}:/{}", components.join("/")))
    }
}

fn is_windows_reserved_component(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn evaluate_intent(ir: &PolicyIr, intent: &TypedIntent) -> Result<(), ReasonCode> {
    if intent.schema_version != INTENT_SCHEMA_VERSION {
        return Err(ReasonCode::SchemaUnsupported);
    }
    validate_intent_identity(&intent.run_as)?;
    validate_intent_collections(intent)?;

    // Invariants are evaluated before capability or policy-specific denials so
    // selecting a different base template cannot mask or relax them.
    let normalized_program = intent
        .program
        .as_deref()
        .map(|program| {
            let program = normalize_program_identifier(program).map_err(|error| error.code())?;
            validate_program_invariant(&program).map_err(|error| error.code())?;
            Ok(program)
        })
        .transpose()?;
    let mut normalized_env_names = BTreeSet::new();
    for variable in &intent.env {
        let key = normalize_env_key(&variable.name).map_err(|error| error.code())?;
        if !normalized_env_names.insert(key) {
            return Err(ReasonCode::IntentEnvironmentDenied);
        }
    }
    let normalized_paths = intent
        .paths
        .iter()
        .map(|path| {
            Ok(NormalizedPath {
                flavor: path.flavor,
                value: normalize_path(path.flavor, &path.value).map_err(|error| error.code())?,
            })
        })
        .collect::<Result<Vec<_>, ReasonCode>>()?;

    validate_intent_shape(intent)?;

    if !ir.capabilities.contains(&intent.capability) {
        return Err(ReasonCode::IntentCapabilityDenied);
    }
    if !ir.run_as.contains(&intent.run_as) {
        return Err(ReasonCode::IntentIdentityDenied);
    }
    validate_intent_deadline_and_budget(ir.limits, intent)?;

    if let Some(program) = normalized_program {
        if !ir.process_programs.contains(&program) {
            return Err(ReasonCode::IntentProgramDenied);
        }
    }

    for key in normalized_env_names {
        if !ir.process_env_keys.contains(&key) {
            return Err(ReasonCode::IntentEnvironmentDenied);
        }
    }

    for normalized in &normalized_paths {
        if !ir
            .allowed_paths
            .iter()
            .any(|prefix| path_prefix_matches(prefix, normalized))
        {
            return Err(ReasonCode::IntentPathDenied);
        }
        if ir
            .denied_paths
            .iter()
            .any(|prefix| path_prefix_matches(prefix, normalized))
        {
            return Err(ReasonCode::IntentPathDenied);
        }
    }
    Ok(())
}

fn validate_intent_identity(run_as: &RunAs) -> Result<(), ReasonCode> {
    validate_run_as(run_as.clone())
        .map(|_| ())
        .map_err(|error| error.code())
}

fn validate_intent_collections(intent: &TypedIntent) -> Result<(), ReasonCode> {
    if intent
        .program
        .as_ref()
        .is_some_and(|program| program.len() > MAX_PROGRAM_BYTES)
    {
        return Err(ReasonCode::IntentArgumentLimitExceeded);
    }
    if intent.argv.len() > MAX_ARG_COUNT {
        return Err(ReasonCode::IntentArgumentLimitExceeded);
    }
    let mut argument_bytes = 0_usize;
    for argument in &intent.argv {
        if argument.len() > MAX_ARG_BYTES {
            return Err(ReasonCode::IntentArgumentLimitExceeded);
        }
        if argument.chars().any(char::is_control) {
            return Err(ReasonCode::InvariantControlCharacter);
        }
        if is_shell_command_flag(argument) {
            return Err(ReasonCode::InvariantShellCommandFlag);
        }
        argument_bytes = argument_bytes.saturating_add(argument.len());
    }
    if argument_bytes > MAX_ARG_TOTAL_BYTES {
        return Err(ReasonCode::IntentArgumentLimitExceeded);
    }

    if intent.env.len() > MAX_ENV_COUNT {
        return Err(ReasonCode::IntentEnvironmentLimitExceeded);
    }
    let mut env_bytes = 0_usize;
    for variable in &intent.env {
        if variable.name.len() > MAX_ENV_NAME_BYTES || variable.value.len() > MAX_ENV_VALUE_BYTES {
            return Err(ReasonCode::IntentEnvironmentLimitExceeded);
        }
        if variable.name.chars().any(char::is_control)
            || variable.value.chars().any(char::is_control)
        {
            return Err(ReasonCode::InvariantControlCharacter);
        }
        env_bytes = env_bytes
            .saturating_add(variable.name.len())
            .saturating_add(variable.value.len());
    }
    if env_bytes > MAX_ENV_TOTAL_BYTES {
        return Err(ReasonCode::IntentEnvironmentLimitExceeded);
    }

    if intent.paths.len() > MAX_PATH_COUNT {
        return Err(ReasonCode::IntentPathLimitExceeded);
    }
    if intent
        .paths
        .iter()
        .any(|path| path.value.len() > MAX_PATH_BYTES)
    {
        return Err(ReasonCode::IntentPathLimitExceeded);
    }
    Ok(())
}

fn validate_intent_shape(intent: &TypedIntent) -> Result<(), ReasonCode> {
    use Capability::*;
    match intent.capability {
        FsList | FsRead | FsWriteNew | TransferRead | TransferWrite => {
            if intent.program.is_some()
                || !intent.argv.is_empty()
                || !intent.env.is_empty()
                || intent.paths.len() != 1
            {
                return Err(ReasonCode::IntentShapeMismatch);
            }
        }
        ProcessInspect => {
            if intent.program.is_some()
                || !intent.argv.is_empty()
                || !intent.env.is_empty()
                || !intent.paths.is_empty()
            {
                return Err(ReasonCode::IntentShapeMismatch);
            }
        }
        ProcessRun => {
            // A process intent may carry one typed path for its working
            // directory. The path still passes the same absolute,
            // traversal, ambiguity, and deny-prefix checks as filesystem
            // intents; additional paths are shape-confused and rejected.
            if intent.program.is_none() || intent.paths.len() > 1 {
                return Err(ReasonCode::IntentShapeMismatch);
            }
        }
    }
    Ok(())
}

fn validate_intent_deadline_and_budget(
    limits: EffectiveLimits,
    intent: &TypedIntent,
) -> Result<(), ReasonCode> {
    if intent.deadline_ms == 0 {
        return Err(ReasonCode::IntentDeadlineInvalid);
    }
    if intent.deadline_ms > limits.max_deadline_ms {
        return Err(ReasonCode::IntentDeadlineExceeded);
    }
    if intent.budget.parallel == 0 || intent.budget.operations == 0 {
        return Err(ReasonCode::IntentBudgetInvalid);
    }
    if intent.budget.bytes > limits.max_bytes
        || intent.budget.output_bytes > limits.max_output_bytes
        || intent.budget.parallel > limits.max_parallel
        || intent.budget.operations > limits.max_operations
    {
        return Err(ReasonCode::IntentBudgetExceeded);
    }
    Ok(())
}

fn path_prefix_matches(prefix: &NormalizedPath, path: &NormalizedPath) -> bool {
    if prefix.flavor != path.flavor {
        return false;
    }
    let (prefix_value, path_value) = match prefix.flavor {
        PathFlavor::Posix => (prefix.value.clone(), path.value.clone()),
        PathFlavor::Windows => (
            prefix.value.to_ascii_lowercase(),
            path.value.to_ascii_lowercase(),
        ),
    };
    if prefix_value == "/" || prefix_value.ends_with(":/") {
        return path_value.starts_with(&prefix_value);
    }
    path_value == prefix_value
        || path_value
            .strip_prefix(&prefix_value)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> RunAs {
        RunAs::User {
            name: name.to_owned(),
        }
    }

    fn base_document(base: BaseTemplate) -> PolicyDocument {
        PolicyDocument {
            schema_version: POLICY_SCHEMA_VERSION,
            base,
            capabilities: None,
            run_as: vec![match base {
                BaseTemplate::Green | BaseTemplate::Yellow => user("nobody"),
                BaseTemplate::Red => RunAs::Uid { value: 1000 },
            }],
            limits: LimitsOverlay::default(),
            process: ProcessOverlay::default(),
            deny: Vec::new(),
        }
    }

    fn budget() -> IntentBudget {
        IntentBudget {
            bytes: 1024,
            output_bytes: 1024,
            parallel: 1,
            operations: 1,
        }
    }

    fn fs_read(path: &str) -> TypedIntent {
        TypedIntent {
            schema_version: INTENT_SCHEMA_VERSION,
            capability: Capability::FsRead,
            run_as: user("nobody"),
            program: None,
            argv: Vec::new(),
            env: Vec::new(),
            paths: vec![IntentPath {
                flavor: PathFlavor::Posix,
                value: path.to_owned(),
            }],
            budget: budget(),
            deadline_ms: 10_000,
        }
    }

    fn process(program: &str) -> TypedIntent {
        TypedIntent {
            schema_version: INTENT_SCHEMA_VERSION,
            capability: Capability::ProcessRun,
            run_as: RunAs::Uid { value: 1000 },
            program: Some(program.to_owned()),
            argv: Vec::new(),
            env: Vec::new(),
            paths: Vec::new(),
            budget: budget(),
            deadline_ms: 10_000,
        }
    }

    fn process_inspect() -> TypedIntent {
        TypedIntent {
            schema_version: INTENT_SCHEMA_VERSION,
            capability: Capability::ProcessInspect,
            run_as: user("nobody"),
            program: None,
            argv: Vec::new(),
            env: Vec::new(),
            paths: Vec::new(),
            budget: budget(),
            deadline_ms: 10_000,
        }
    }

    fn next_permutation(values: &mut [usize]) -> bool {
        let Some(pivot) = (0..values.len().saturating_sub(1))
            .rev()
            .find(|index| values[*index] < values[*index + 1])
        else {
            return false;
        };
        let successor = (pivot + 1..values.len())
            .rev()
            .find(|index| values[*index] > values[pivot])
            .expect("permutation pivot must have a successor");
        values.swap(pivot, successor);
        values[pivot + 1..].reverse();
        true
    }

    fn ordered_policy_json(order: &[usize]) -> Vec<u8> {
        let fields = [
            r#""schema_version":1"#,
            r#""base":"red""#,
            r#""capabilities":["process_inspect","process_run"]"#,
            r#""run_as":[{"kind":"uid","value":1000}]"#,
            r#""limits":{}"#,
            r#""process":{"programs":["id","whoami"],"env_keys":["LANG","TZ"]}"#,
            r#""deny":[{"kind":"program","name":"id"}]"#,
        ];
        let mut json = String::from("{");
        for (position, index) in order.iter().enumerate() {
            if position > 0 {
                json.push(',');
            }
            json.push_str(fields[*index]);
        }
        json.push('}');
        json.into_bytes()
    }

    #[test]
    fn schema_is_strict_and_bounded() {
        let unknown = br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"deploy"}],"surprise":true}"#;
        assert_eq!(
            compile_policy_json(unknown).unwrap_err().code(),
            ReasonCode::SchemaInvalid
        );

        let mut unsupported = base_document(BaseTemplate::Green);
        unsupported.schema_version = 2;
        assert_eq!(
            compile_policy(unsupported).unwrap_err().code(),
            ReasonCode::SchemaUnsupported
        );

        let oversized = vec![b' '; MAX_POLICY_DOCUMENT_BYTES + 1];
        assert_eq!(
            compile_policy_json(&oversized).unwrap_err().code(),
            ReasonCode::PolicyTooLarge
        );
    }

    #[test]
    fn deterministic_policy_parser_mutation_corpus_is_panic_free_and_fail_closed() {
        let valid = ordered_policy_json(&(0..7).collect::<Vec<_>>());
        assert!(compile_policy_json(&valid).is_ok());

        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("whitespace", b" \r\n\t".to_vec()),
            ("null", b"null".to_vec()),
            ("array", b"[]".to_vec()),
            ("unterminated-object", b"{".to_vec()),
            ("trailing-token", [valid.as_slice(), b"false"].concat()),
            ("invalid-utf8", vec![0xff, 0xfe, 0xfd]),
            (
                "duplicate-top-level-field",
                br#"{"schema_version":1,"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}]}"#.to_vec(),
            ),
            (
                "duplicate-nested-field",
                br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}],"limits":{"max_bytes":1,"max_bytes":1}}"#.to_vec(),
            ),
            (
                "unknown-run-as-field",
                br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody","extra":true}]}"#.to_vec(),
            ),
            (
                "unknown-limits-field",
                br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}],"limits":{"extra":1}}"#.to_vec(),
            ),
            (
                "unknown-process-field",
                br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}],"process":{"extra":[]}}"#.to_vec(),
            ),
            (
                "unknown-deny-field",
                br#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}],"deny":[{"kind":"capability","capability":"fs_read","extra":true}]}"#.to_vec(),
            ),
            (
                "wrong-scalar-types",
                br#"{"schema_version":"1","base":false,"run_as":{}}"#.to_vec(),
            ),
            (
                "integer-overflow",
                br#"{"schema_version":18446744073709551615,"base":"green","run_as":[]}"#.to_vec(),
            ),
        ];

        let mut deeply_nested = String::from(
            r#"{"schema_version":1,"base":"green","run_as":[{"kind":"user","name":"nobody"}],"unknown":"#,
        );
        deeply_nested.push_str(&"[".repeat(256));
        deeply_nested.push_str(&"]".repeat(256));
        deeply_nested.push('}');
        cases.push(("recursion-limit", deeply_nested.into_bytes()));

        for cut in 0..valid.len() {
            let result = std::panic::catch_unwind(|| compile_policy_json(&valid[..cut]));
            assert!(result.is_ok(), "truncation {cut} panicked");
            assert!(result.unwrap().is_err(), "truncation {cut} was accepted");
        }
        for index in 0..valid.len() {
            let mut invalid_utf8 = valid.clone();
            invalid_utf8[index] = 0xff;
            let result = std::panic::catch_unwind(|| compile_policy_json(&invalid_utf8));
            assert!(result.is_ok(), "invalid UTF-8 mutation {index} panicked");
            assert!(
                result.unwrap().is_err(),
                "invalid UTF-8 mutation {index} was accepted"
            );
        }
        for (name, bytes) in cases {
            let result = std::panic::catch_unwind(|| compile_policy_json(&bytes));
            assert!(result.is_ok(), "mutation {name} panicked");
            assert!(result.unwrap().is_err(), "mutation {name} was accepted");
        }

        let mut exact_limit = valid.clone();
        exact_limit.resize(MAX_POLICY_DOCUMENT_BYTES, b' ');
        let exact = compile_policy_json(&exact_limit).expect("exact byte limit must remain valid");
        assert_eq!(
            exact.digest(),
            compile_policy_json(&valid).unwrap().digest()
        );
        exact_limit.push(b' ');
        assert_eq!(
            compile_policy_json(&exact_limit).unwrap_err().code(),
            ReasonCode::PolicyTooLarge
        );
    }

    #[test]
    fn all_top_level_json_field_orders_compile_to_one_canonical_policy() {
        let baseline = compile_policy_json(&ordered_policy_json(&(0..7).collect::<Vec<_>>()))
            .expect("baseline policy must compile");
        let mut order: Vec<usize> = (0..7).collect();
        let mut permutations = 0usize;
        loop {
            let candidate = compile_policy_json(&ordered_policy_json(&order))
                .unwrap_or_else(|error| panic!("field order {order:?} failed: {error}"));
            assert_eq!(candidate.ir(), baseline.ir(), "field order {order:?}");
            assert_eq!(
                candidate.digest(),
                baseline.digest(),
                "field order {order:?}"
            );
            permutations += 1;
            if !next_permutation(&mut order) {
                break;
            }
        }
        assert_eq!(permutations, 5_040);
    }

    #[test]
    fn deny_rule_reordering_and_replay_are_idempotent_but_json_fields_are_not() {
        let rules = vec![
            DenyRule::Capability {
                capability: Capability::ProcessInspect,
            },
            DenyRule::Program { name: "id".into() },
            DenyRule::PathPrefix {
                flavor: PathFlavor::Posix,
                value: "/srv/secrets".into(),
            },
        ];
        let mut baseline_document = base_document(BaseTemplate::Red);
        baseline_document.deny = rules.clone();
        let baseline = compile_policy(baseline_document).unwrap();

        let mut order = vec![0usize, 1, 2];
        loop {
            let mut document = base_document(BaseTemplate::Red);
            document.deny = order.iter().map(|index| rules[*index].clone()).collect();
            let candidate = compile_policy(document).unwrap();
            assert_eq!(candidate.ir(), baseline.ir());
            assert_eq!(candidate.digest(), baseline.digest());
            if !next_permutation(&mut order) {
                break;
            }
        }

        let mut replayed = base_document(BaseTemplate::Red);
        replayed.deny = rules
            .iter()
            .chain(rules.iter())
            .cloned()
            .collect::<Vec<_>>();
        let replayed = compile_policy(replayed).unwrap();
        assert_eq!(replayed.ir(), baseline.ir());
        assert_eq!(replayed.digest(), baseline.digest());

        let duplicate_json_field = br#"{
            "schema_version":1,
            "base":"red",
            "deny":[],
            "deny":[],
            "run_as":[{"kind":"uid","value":1000}]
        }"#;
        assert_eq!(
            compile_policy_json(duplicate_json_field)
                .unwrap_err()
                .code(),
            ReasonCode::SchemaInvalid
        );
    }

    #[test]
    fn policy_and_intent_collection_limits_are_enforced() {
        let mut identities = base_document(BaseTemplate::Green);
        identities.run_as = (1..=(MAX_POLICY_IDENTITIES + 1))
            .map(|index| RunAs::Uid {
                value: index as u32,
            })
            .collect();
        assert_eq!(
            compile_policy(identities).unwrap_err().code(),
            ReasonCode::PolicyLimitExceeded
        );

        let mut denies = base_document(BaseTemplate::Green);
        denies.deny = (0..=MAX_POLICY_DENY_RULES)
            .map(|_| DenyRule::Capability {
                capability: Capability::FsRead,
            })
            .collect();
        assert_eq!(
            compile_policy(denies).unwrap_err().code(),
            ReasonCode::PolicyLimitExceeded
        );

        let green = compile_policy(base_document(BaseTemplate::Green)).unwrap();
        let mut too_many_paths = fs_read("/srv/file");
        too_many_paths.paths = (0..=MAX_PATH_COUNT)
            .map(|index| IntentPath {
                flavor: PathFlavor::Posix,
                value: format!("/srv/{index}"),
            })
            .collect();
        assert_eq!(
            green.dry_run(&too_many_paths).reason_code,
            ReasonCode::IntentPathLimitExceeded
        );

        let mut long_path = fs_read("/srv/file");
        long_path.paths[0].value = format!("/{}", "x".repeat(MAX_PATH_BYTES));
        assert_eq!(
            green.dry_run(&long_path).reason_code,
            ReasonCode::IntentPathLimitExceeded
        );

        let red = compile_policy(base_document(BaseTemplate::Red)).unwrap();
        let mut too_many_env = process("whoami");
        too_many_env.env = (0..=MAX_ENV_COUNT)
            .map(|index| EnvVar {
                name: format!("KEY_{index}"),
                value: "x".into(),
            })
            .collect();
        assert_eq!(
            red.dry_run(&too_many_env).reason_code,
            ReasonCode::IntentEnvironmentLimitExceeded
        );
    }

    #[test]
    fn root_and_uid_zero_are_invariant_denials() {
        for identity in [
            user("root"),
            user("ROOT"),
            user("0"),
            user("00"),
            RunAs::Uid { value: 0 },
        ] {
            let mut document = base_document(BaseTemplate::Red);
            document.run_as = vec![identity];
            assert_eq!(
                compile_policy(document).unwrap_err().code(),
                ReasonCode::InvariantRootRunAs
            );
        }
    }

    #[test]
    fn overlay_cannot_expand_base_capabilities_identities_limits_programs_or_environment() {
        let mut capability = base_document(BaseTemplate::Green);
        capability.capabilities = Some(vec![Capability::TransferWrite]);
        assert_eq!(
            compile_policy(capability).unwrap_err().code(),
            ReasonCode::CapabilityExpandsBase
        );

        for base in [BaseTemplate::Green, BaseTemplate::Yellow, BaseTemplate::Red] {
            let mut identity = base_document(base);
            identity.run_as = vec![user("deploy")];
            assert_eq!(
                compile_policy(identity).unwrap_err().code(),
                ReasonCode::IdentityExpandsBase
            );
        }

        let mut limit = base_document(BaseTemplate::Green);
        limit.limits.max_parallel = Some(2);
        assert_eq!(
            compile_policy(limit).unwrap_err().code(),
            ReasonCode::PolicyLimitExceeded
        );

        let mut program = base_document(BaseTemplate::Red);
        program.process.programs = Some(vec!["curl".into()]);
        assert_eq!(
            compile_policy(program).unwrap_err().code(),
            ReasonCode::ProgramExpandsBase
        );

        let mut environment = base_document(BaseTemplate::Red);
        environment.process.env_keys = Some(vec!["HOME".into()]);
        assert_eq!(
            compile_policy(environment).unwrap_err().code(),
            ReasonCode::EnvironmentExpandsBase
        );
    }

    #[test]
    fn normalized_ir_and_digest_ignore_overlay_order_and_duplicates() {
        let mut first = base_document(BaseTemplate::Red);
        first.capabilities = Some(vec![
            Capability::ProcessInspect,
            Capability::ProcessRun,
            Capability::ProcessInspect,
        ]);
        first.run_as = vec![
            RunAs::Uid { value: 1000 },
            RunAs::Uid { value: 1001 },
            RunAs::Uid { value: 1001 },
        ];
        first.process.programs = Some(vec!["WHOAMI.EXE".into(), "id".into(), "id".into()]);
        first.process.env_keys = Some(vec!["TZ".into(), "LANG".into()]);
        first.deny = vec![
            DenyRule::PathPrefix {
                flavor: PathFlavor::Posix,
                value: "/srv//secret".into(),
            },
            DenyRule::Program { name: "id".into() },
        ];

        let mut second = base_document(BaseTemplate::Red);
        second.capabilities = Some(vec![Capability::ProcessRun, Capability::ProcessInspect]);
        second.run_as = vec![RunAs::Uid { value: 1001 }, RunAs::Uid { value: 1000 }];
        second.process.programs = Some(vec!["id".into(), "whoami".into()]);
        second.process.env_keys = Some(vec!["LANG".into(), "TZ".into(), "LANG".into()]);
        second.deny = vec![
            DenyRule::Program {
                name: "ID.EXE".into(),
            },
            DenyRule::PathPrefix {
                flavor: PathFlavor::Posix,
                value: "/srv/secret/".into(),
            },
        ];

        let first = compile_policy(first).unwrap();
        let second = compile_policy(second).unwrap();
        assert_eq!(first.ir(), second.ir());
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.digest().as_str().len(), 64);
    }

    #[test]
    fn digest_has_a_fixed_schema_v1_fixture() {
        let policy = compile_policy(base_document(BaseTemplate::Green)).unwrap();
        assert_eq!(
            policy.digest().as_str(),
            "f441e36cce1a889a1b66eabe1f4beb06c175df7af61423b51b2a83861ae11e5e"
        );
    }

    #[test]
    fn path_traversal_control_and_ambiguous_encodings_are_invariant_denials() {
        let policy = compile_policy(base_document(BaseTemplate::Green)).unwrap();
        for (path, reason) in [
            ("/srv/../etc/shadow", ReasonCode::InvariantPathTraversal),
            ("/srv/%2e%2e/etc", ReasonCode::InvariantAmbiguousPath),
            ("/srv\\..\\etc", ReasonCode::InvariantAmbiguousPath),
            ("relative/path", ReasonCode::InvariantPathNotAbsolute),
            ("/srv/line\nbreak", ReasonCode::InvariantControlCharacter),
        ] {
            assert_eq!(policy.dry_run(&fs_read(path)).reason_code, reason, "{path}");
        }
    }

    #[test]
    fn windows_paths_reject_traversal_unc_ads_and_reserved_names() {
        let policy = compile_policy(base_document(BaseTemplate::Green)).unwrap();
        for path in [
            r"C:\safe\..\secret",
            r"\\server\share\file",
            r"C:\safe\file:stream",
            r"C:\safe\NUL.txt",
        ] {
            let mut intent = fs_read("/unused");
            intent.paths[0] = IntentPath {
                flavor: PathFlavor::Windows,
                value: path.into(),
            };
            assert!(!policy.dry_run(&intent).allowed, "{path}");
        }
        let mut canonical = fs_read("/unused");
        canonical.paths[0] = IntentPath {
            flavor: PathFlavor::Windows,
            value: r"c:\safe\\file.txt".into(),
        };
        assert_eq!(
            policy.dry_run(&canonical).reason_code,
            ReasonCode::IntentCapabilityDenied
        );
    }

    #[test]
    fn command_interpreters_shell_flags_and_dangerous_families_are_invariants() {
        let policy = compile_policy(base_document(BaseTemplate::Red)).unwrap();
        for (program, reason) in [
            ("bash", ReasonCode::InvariantCommandInterpreter),
            ("PowerShell.EXE", ReasonCode::InvariantCommandInterpreter),
            ("rm", ReasonCode::InvariantDangerousProgram),
            ("mkfs.ext4", ReasonCode::InvariantDangerousProgram),
            ("diskpart.exe", ReasonCode::InvariantDangerousProgram),
        ] {
            assert_eq!(policy.dry_run(&process(program)).reason_code, reason);
        }

        let mut shell_flag = process("whoami");
        shell_flag.argv.push("-c".into());
        assert_eq!(
            policy.dry_run(&shell_flag).reason_code,
            ReasonCode::InvariantShellCommandFlag
        );
    }

    #[test]
    fn typed_process_intent_uses_fixed_program_and_environment_sets() {
        let policy = compile_policy(base_document(BaseTemplate::Red)).unwrap();
        let mut allowed = process("WHOAMI.EXE");
        allowed.env.push(EnvVar {
            name: "LANG".into(),
            value: "C.UTF-8".into(),
        });
        let explanation = policy.dry_run(&allowed);
        assert!(explanation.allowed);
        assert_eq!(explanation.reason_code, ReasonCode::Allowed);
        assert_eq!(
            serde_json::to_value(&explanation).unwrap()["reason_code"],
            "allowed"
        );

        let mut duplicate_env = allowed.clone();
        duplicate_env.env.push(EnvVar {
            name: "LANG".into(),
            value: "en_US.UTF-8".into(),
        });
        assert_eq!(
            policy.dry_run(&duplicate_env).reason_code,
            ReasonCode::IntentEnvironmentDenied
        );

        let mut preload = process("whoami");
        preload.env.push(EnvVar {
            name: "LD_PRELOAD".into(),
            value: "/tmp/inject.so".into(),
        });
        assert_eq!(
            policy.dry_run(&preload).reason_code,
            ReasonCode::InvariantEnvironmentInjection
        );

        let mut twenty_minutes = process("true");
        twenty_minutes.deadline_ms = 1_200_000;
        assert!(policy.dry_run(&twenty_minutes).allowed);
        twenty_minutes.deadline_ms = 2_100_001;
        assert_eq!(
            policy.dry_run(&twenty_minutes).reason_code,
            ReasonCode::IntentDeadlineExceeded
        );

        let mut with_cwd = process("true");
        with_cwd.paths.push(IntentPath {
            flavor: PathFlavor::Posix,
            value: "/srv/app".into(),
        });
        assert_eq!(
            policy.dry_run(&with_cwd).reason_code,
            ReasonCode::IntentPathDenied
        );
        with_cwd.paths.push(IntentPath {
            flavor: PathFlavor::Posix,
            value: "/srv/other".into(),
        });
        assert_eq!(
            policy.dry_run(&with_cwd).reason_code,
            ReasonCode::IntentShapeMismatch
        );
    }

    #[test]
    fn path_prefix_matching_is_segment_aware_and_windows_case_insensitive() {
        let posix = NormalizedPath {
            flavor: PathFlavor::Posix,
            value: normalize_path(PathFlavor::Posix, "/srv/secrets").unwrap(),
        };
        let child = NormalizedPath {
            flavor: PathFlavor::Posix,
            value: normalize_path(PathFlavor::Posix, "/srv/secrets/key").unwrap(),
        };
        let sibling = NormalizedPath {
            flavor: PathFlavor::Posix,
            value: normalize_path(PathFlavor::Posix, "/srv/secrets-old/key").unwrap(),
        };
        assert!(path_prefix_matches(&posix, &child));
        assert!(!path_prefix_matches(&posix, &sibling));

        let windows = NormalizedPath {
            flavor: PathFlavor::Windows,
            value: normalize_path(PathFlavor::Windows, r"C:\Private").unwrap(),
        };
        let windows_child = NormalizedPath {
            flavor: PathFlavor::Windows,
            value: normalize_path(PathFlavor::Windows, r"c:\private\Key.txt").unwrap(),
        };
        assert!(path_prefix_matches(&windows, &windows_child));
    }

    #[test]
    fn beta_templates_have_no_filesystem_or_transfer_path_authority() {
        for base in [BaseTemplate::Green, BaseTemplate::Yellow, BaseTemplate::Red] {
            let policy = compile_policy(base_document(base)).unwrap();
            assert!(policy.ir().allowed_paths().is_empty());
        }

        let green = compile_policy(base_document(BaseTemplate::Green)).unwrap();
        assert_eq!(
            green
                .dry_run(&fs_read("/home/nobody/.ssh/id_ed25519"))
                .reason_code,
            ReasonCode::IntentCapabilityDenied
        );

        let yellow = compile_policy(base_document(BaseTemplate::Yellow)).unwrap();
        for (capability, path) in [
            (Capability::FsRead, "/home/nobody/.ssh/id_ed25519"),
            (Capability::FsWriteNew, "/home/nobody/.ssh/authorized_keys"),
            (Capability::TransferRead, "/srv/app/archive.tar"),
            (Capability::TransferWrite, "/srv/app/release.bin"),
        ] {
            let mut intent = fs_read(path);
            intent.capability = capability;
            assert_eq!(
                yellow.dry_run(&intent).reason_code,
                ReasonCode::IntentCapabilityDenied,
                "{capability:?} unexpectedly acquired beta path authority"
            );
        }

        let mut expansion = base_document(BaseTemplate::Yellow);
        expansion.capabilities = Some(vec![Capability::TransferWrite]);
        assert_eq!(
            compile_policy(expansion).unwrap_err().code(),
            ReasonCode::CapabilityExpandsBase
        );
    }

    #[test]
    fn intent_shape_deadline_budget_and_counts_fail_closed() {
        let policy = compile_policy(base_document(BaseTemplate::Green)).unwrap();

        let mut wrong_shape = process_inspect();
        wrong_shape.program = Some("whoami".into());
        assert_eq!(
            policy.dry_run(&wrong_shape).reason_code,
            ReasonCode::IntentShapeMismatch
        );

        let mut no_deadline = process_inspect();
        no_deadline.deadline_ms = 0;
        assert_eq!(
            policy.dry_run(&no_deadline).reason_code,
            ReasonCode::IntentDeadlineInvalid
        );

        let mut late = process_inspect();
        late.deadline_ms = 60_001;
        assert_eq!(
            policy.dry_run(&late).reason_code,
            ReasonCode::IntentDeadlineExceeded
        );

        let mut over_budget = process_inspect();
        over_budget.budget.parallel = 2;
        assert_eq!(
            policy.dry_run(&over_budget).reason_code,
            ReasonCode::IntentBudgetExceeded
        );

        let mut too_many_args = process("whoami");
        too_many_args.argv = vec!["x".into(); MAX_ARG_COUNT + 1];
        let red = compile_policy(base_document(BaseTemplate::Red)).unwrap();
        assert_eq!(
            red.dry_run(&too_many_args).reason_code,
            ReasonCode::IntentArgumentLimitExceeded
        );
    }

    #[test]
    fn intent_and_nested_objects_reject_unknown_fields() {
        let unknown_intent = br#"{
            "schema_version":1,
            "capability":"fs_read",
            "run_as":{"kind":"user","name":"deploy","extra":true},
            "argv":[],"env":[],"paths":[],
            "budget":{"bytes":0,"output_bytes":1,"parallel":1,"operations":1},
            "deadline_ms":1
        }"#;
        assert!(serde_json::from_slice::<TypedIntent>(unknown_intent).is_err());

        let unknown_budget = br#"{
            "schema_version":1,
            "capability":"process_inspect",
            "run_as":{"kind":"user","name":"deploy"},
            "argv":[],"env":[],"paths":[],
            "budget":{"bytes":0,"output_bytes":1,"parallel":1,"operations":1,"extra":1},
            "deadline_ms":1
        }"#;
        assert!(serde_json::from_slice::<TypedIntent>(unknown_budget).is_err());
    }

    #[test]
    fn control_characters_are_rejected_across_argv_env_and_identity() {
        let policy = compile_policy(base_document(BaseTemplate::Red)).unwrap();
        let mut argument = process("whoami");
        argument.argv.push("bad\nargument".into());
        assert_eq!(
            policy.dry_run(&argument).reason_code,
            ReasonCode::InvariantControlCharacter
        );

        let mut environment = process("whoami");
        environment.env.push(EnvVar {
            name: "LANG".into(),
            value: "bad\rvalue".into(),
        });
        assert_eq!(
            policy.dry_run(&environment).reason_code,
            ReasonCode::InvariantControlCharacter
        );

        let mut identity = process("whoami");
        identity.run_as = user("bad\nuser");
        assert_eq!(
            policy.dry_run(&identity).reason_code,
            ReasonCode::InvariantControlCharacter
        );
    }
}
