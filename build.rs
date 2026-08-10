use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const GIT_REPOSITORY_OVERRIDE_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
];

const GIT_STATUS_ARGS: &[&str] = &[
    "status",
    "--porcelain=v1",
    "-z",
    "--untracked-files=normal",
    "--ignore-submodules=none",
    "--",
];
const GIT_METADATA_PATHS: &[&str] = &[
    "HEAD",
    "index",
    "packed-refs",
    "config",
    "config.worktree",
    "info/attributes",
    "info/exclude",
];

#[cfg(windows)]
const GIT_NULL_CONFIG: &str = "NUL";
#[cfg(not(windows))]
const GIT_NULL_CONFIG: &str = "/dev/null";

#[cfg(windows)]
fn git_compatible_path(path: PathBuf) -> PathBuf {
    let rendered = path.to_string_lossy();
    if let Some(rest) = rendered.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = rendered.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path
}

#[cfg(not(windows))]
fn git_compatible_path(path: PathBuf) -> PathBuf {
    path
}

fn filesystem_repository_candidate(work_dir: &Path) -> Option<PathBuf> {
    let mut candidate = work_dir.canonicalize().ok()?;
    loop {
        if candidate.join(".git").exists() {
            return Some(git_compatible_path(candidate));
        }
        if !candidate.pop() {
            return None;
        }
    }
}

fn configured_git_command(work_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.current_dir(work_dir);
    // A caller-controlled alternate repository, work tree, or index can make
    // modified build inputs appear clean. Always discover the repository from
    // CARGO_MANIFEST_DIR instead of inheriting those Git process overrides.
    for name in GIT_REPOSITORY_OVERRIDE_ENV {
        command.env_remove(name);
    }
    if let Some(candidate) = filesystem_repository_candidate(work_dir) {
        let mut safe_directory = OsString::from("safe.directory=");
        safe_directory.push(&candidate);
        command.arg("-c").arg(safe_directory);

        // A repository-local core.worktree is equivalent to an inherited
        // GIT_WORK_TREE override: it can redirect all provenance queries to a
        // clean tree while Cargo compiles CARGO_MANIFEST_DIR. Git's dedicated
        // --work-tree option takes precedence during repository setup, unlike
        // a later `-c core.worktree=...` value on some Windows Git versions.
        let mut worktree = OsString::from("--work-tree=");
        worktree.push(candidate);
        command.arg(worktree);
    }
    // Read-only provenance queries must not refresh the watched index;
    // otherwise build.rs invalidates its own Cargo fingerprint forever.
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Replacement refs/grafts can make status compare the worktree with a
        // forged replacement for HEAD while rev-parse still reports the
        // original commit identifier.
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        // Do not let HOME/XDG or caller-selected global/system config redirect
        // the worktree, hide untracked inputs, or enable an external monitor.
        // Repository-local config remains available for legitimate worktrees.
        .env("GIT_CONFIG_GLOBAL", GIT_NULL_CONFIG)
        .env("GIT_CONFIG_SYSTEM", GIT_NULL_CONFIG)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .args(args);
    command
}

fn run_git_command(work_dir: &Path, args: &[&str]) -> Option<Output> {
    configured_git_command(work_dir, args).output().ok()
}

fn run_git(work_dir: &Path, args: &[&str]) -> Option<Output> {
    let output = run_git_command(work_dir, args)?;
    output.status.success().then_some(output)
}

fn git_text(work_dir: &Path, args: &[&str]) -> Option<String> {
    let output = run_git(work_dir, args)?;
    let value = String::from_utf8(output.stdout).ok()?;
    Some(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn resolve_git_path(work_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        work_dir.join(path)
    }
}

fn git_path(work_dir: &Path, name: &str) -> Option<PathBuf> {
    let absolute = run_git(
        work_dir,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )
    .and_then(|output| String::from_utf8(output.stdout).ok())
    .map(|value| value.trim_end_matches(['\r', '\n']).to_owned());
    let value = absolute.or_else(|| git_text(work_dir, &["rev-parse", "--git-path", name]))?;
    (!value.is_empty()).then(|| resolve_git_path(work_dir, &value))
}

fn path_from_git_bytes(value: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(value.to_vec()))
    }

    #[cfg(not(unix))]
    {
        use std::ffi::OsString;
        PathBuf::from(OsString::from(String::from_utf8_lossy(value).into_owned()))
    }
}

fn discovered_repository_root(work_dir: &Path) -> Option<PathBuf> {
    let value = git_text(work_dir, &["rev-parse", "--show-toplevel"])?;
    (!value.is_empty()).then(|| resolve_git_path(work_dir, &value))
}

fn repository_contains_work_dir(repository_root: &Path, work_dir: &Path) -> bool {
    let Ok(repository_root) = repository_root.canonicalize() else {
        return false;
    };
    let Ok(work_dir) = work_dir.canonicalize() else {
        return false;
    };
    work_dir.starts_with(repository_root)
}

fn repository_root(work_dir: &Path) -> Option<PathBuf> {
    let root = discovered_repository_root(work_dir)?;
    repository_contains_work_dir(&root, work_dir).then_some(root)
}

fn listed_files(work_dir: &Path, args: &[&str]) -> Option<Vec<PathBuf>> {
    let root = repository_root(work_dir)?;
    let output = run_git(&root, args)?;
    Some(
        output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|value| !value.is_empty())
            .map(path_from_git_bytes)
            .map(|path| root.join(path))
            .collect(),
    )
}

fn tracked_files(work_dir: &Path) -> Option<Vec<PathBuf>> {
    listed_files(work_dir, &["ls-files", "-z", "--cached"])
}

#[derive(Debug, PartialEq, Eq)]
struct IndexStageZeroEntry {
    mode: Vec<u8>,
    oid: Vec<u8>,
    path: PathBuf,
}

fn index_stage_zero_entries(work_dir: &Path) -> Option<Vec<IndexStageZeroEntry>> {
    let root = repository_root(work_dir)?;
    let output = run_git(&root, &["ls-files", "--stage", "-z", "--cached"])?;
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let separator = entry.iter().position(|byte| *byte == b'\t')?;
            let mut header = entry[..separator].split(|byte| *byte == b' ');
            let mode = header.next()?.to_vec();
            let oid = header.next()?.to_vec();
            let stage = header.next()?;
            if header.next().is_some()
                || stage != b"0"
                || !oid.iter().all(u8::is_ascii_hexdigit)
                || !matches!(
                    mode.as_slice(),
                    b"100644" | b"100755" | b"120000" | b"160000"
                )
            {
                return None;
            }
            Some(IndexStageZeroEntry {
                mode,
                oid,
                path: root.join(path_from_git_bytes(&entry[separator + 1..])),
            })
        })
        .collect()
}

fn raw_worktree_oid(repository_root: &Path, path: &Path) -> Option<Vec<u8>> {
    let relative = path.strip_prefix(repository_root).ok()?;
    let output = configured_git_command(repository_root, &["hash-object", "--no-filters"])
        .arg("--")
        .arg(relative)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut oid = output.stdout.as_slice();
    while oid.last().is_some_and(|byte| matches!(byte, b'\r' | b'\n')) {
        oid = &oid[..oid.len() - 1];
    }
    (!oid.is_empty() && oid.iter().all(u8::is_ascii_hexdigit)).then(|| oid.to_vec())
}

fn raw_tracked_worktree_is_clean(work_dir: &Path) -> Option<bool> {
    let root = repository_root(work_dir)?;
    for entry in index_stage_zero_entries(&root)? {
        // A gitlink is not a worktree blob, so there is no raw file OID to
        // compare. This project has no submodules; fail dirty if one appears
        // instead of allowing a newly introduced provenance blind spot.
        if entry.mode == b"160000" {
            return Some(false);
        }
        if raw_worktree_oid(&root, &entry.path)? != entry.oid {
            return Some(false);
        }
    }
    Some(true)
}

fn untracked_files(work_dir: &Path) -> Option<Vec<PathBuf>> {
    listed_files(
        work_dir,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    )
}

fn combine_worktree_files(
    tracked: Option<Vec<PathBuf>>,
    untracked: Option<Vec<PathBuf>>,
) -> (Vec<PathBuf>, bool) {
    let complete = tracked.is_some() && untracked.is_some();
    let mut files = tracked.unwrap_or_default();
    files.extend(untracked.unwrap_or_default());
    (files, complete)
}

#[derive(Debug, PartialEq, Eq)]
enum HeadReference {
    Attached(String),
    Detached,
    Failed,
}

fn classify_head_reference(
    success: bool,
    status_code: Option<i32>,
    stdout: Option<String>,
) -> HeadReference {
    if success {
        return stdout
            .filter(|reference| !reference.is_empty())
            .map(HeadReference::Attached)
            .unwrap_or(HeadReference::Failed);
    }
    // `git symbolic-ref -q HEAD` documents exit status 1 for a detached HEAD.
    // Every other failure (including inability to execute Git) is incomplete
    // provenance, not evidence that the repository is detached.
    if status_code == Some(1) {
        HeadReference::Detached
    } else {
        HeadReference::Failed
    }
}

fn head_reference(work_dir: &Path) -> HeadReference {
    let Some(output) = run_git_command(work_dir, &["symbolic-ref", "-q", "HEAD"]) else {
        return HeadReference::Failed;
    };
    let stdout = String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim_end_matches(['\r', '\n']).to_owned());
    classify_head_reference(output.status.success(), output.status.code(), stdout)
}

fn provenance_enumeration_complete(
    root_present: bool,
    files_complete: bool,
    metadata_complete: bool,
) -> bool {
    root_present && files_complete && metadata_complete
}

fn existing_metadata_watch_path(path: PathBuf) -> Option<PathBuf> {
    let mut candidate = Some(path.as_path());
    while let Some(current) = candidate {
        if current.exists() {
            return Some(current.to_owned());
        }
        candidate = current.parent();
    }
    None
}

struct GitRerunPaths {
    paths: Vec<PathBuf>,
    complete: bool,
}

fn git_rerun_paths(work_dir: &Path) -> GitRerunPaths {
    let mut paths = Vec::new();
    let mut metadata_complete = true;

    for name in GIT_METADATA_PATHS {
        match git_path(work_dir, name).and_then(existing_metadata_watch_path) {
            Some(path) => paths.push(path),
            None => metadata_complete = false,
        }
    }

    match head_reference(work_dir) {
        HeadReference::Attached(reference) => {
            match git_path(work_dir, &reference).and_then(existing_metadata_watch_path) {
                Some(path) => paths.push(path),
                None => metadata_complete = false,
            }
        }
        HeadReference::Detached => {}
        HeadReference::Failed => metadata_complete = false,
    }

    let root = repository_root(work_dir);
    let (worktree_files, files_complete) =
        combine_worktree_files(tracked_files(work_dir), untracked_files(work_dir));
    for path in worktree_files {
        // Watching an existing non-root parent makes creation/removal of untracked files rerun
        // the script. The repository root is deliberately excluded because Cargo scans watched
        // directories recursively and target/ would invalidate every build. Root-level build
        // inputs are tracked and watched directly; an arbitrary new root-level untracked file
        // that is not a build input is observed the next time another watched input changes.
        if let (Some(root), Some(parent)) = (root.as_ref(), path.parent()) {
            if let Some(existing_parent) =
                existing_metadata_watch_path(parent.to_owned()).filter(|parent| parent != root)
            {
                paths.push(existing_parent);
            }
        }
        // Cargo treats a missing rerun-if-changed path as perpetually dirty. A deleted tracked
        // file is already covered by its existing non-root parent directory.
        if path.exists() {
            paths.push(path);
        }
    }

    paths.sort_unstable();
    paths.dedup();
    GitRerunPaths {
        paths,
        complete: provenance_enumeration_complete(
            root.is_some(),
            files_complete,
            metadata_complete,
        ),
    }
}

fn working_tree_is_dirty(work_dir: &Path) -> Option<bool> {
    let output = run_git(work_dir, GIT_STATUS_ARGS)?;
    let hidden_index_flags = run_git(work_dir, &["ls-files", "-v", "-z", "--cached"])?;
    let raw_tracked_clean = raw_tracked_worktree_is_clean(work_dir)?;
    Some(
        !output.stdout.is_empty()
            || index_has_hidden_worktree_flags(&hidden_index_flags.stdout)
            || !raw_tracked_clean,
    )
}

fn index_has_hidden_worktree_flags(output: &[u8]) -> bool {
    output
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.first().copied())
        // `git ls-files -v` lower-cases the tag for assume-unchanged
        // entries and uses `S` for skip-worktree entries. Either flag can hide
        // a modified tracked build input from porcelain status.
        .any(|tag| tag.is_ascii_lowercase() || tag == b'S')
}

fn decorate_commit(commit: Option<String>, dirty: Option<bool>, force_dirty: bool) -> String {
    let commit_missing = commit.as_ref().is_none_or(String::is_empty);
    let mut commit = commit
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    if force_dirty || commit_missing || dirty.unwrap_or(true) {
        commit.push_str("-dirty");
    }
    commit
}

fn validated_commit_id(commit: Option<String>) -> Option<String> {
    commit.filter(|value| {
        (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn build_commit(work_dir: &Path, force_dirty: bool) -> String {
    let Some(root) = repository_root(work_dir) else {
        return decorate_commit(None, None, true);
    };
    decorate_commit(
        validated_commit_id(git_text(&root, &["rev-parse", "--short=12", "HEAD"])),
        working_tree_is_dirty(&root),
        force_dirty,
    )
}

fn cargo_path_character_is_safe(value: char) -> bool {
    if matches!(value, '\\' | '\'' | '"') {
        return true;
    }
    let mut escaped = value.escape_debug();
    escaped.next() == Some(value) && escaped.next().is_none()
}

fn rerun_path_text(path: &Path) -> Option<&str> {
    path.to_str()
        .filter(|value| value.chars().all(cargo_path_character_is_safe))
}

fn emit_rerun_path(path: &Path) -> bool {
    if let Some(path) = rerun_path_text(path) {
        println!("cargo:rerun-if-changed={path}");
        true
    } else {
        println!("cargo:warning=not watching a non-UTF-8 or terminal-unsafe Git path");
        false
    }
}

fn main() {
    let work_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    // Cargo otherwise only reruns a build script when the script itself changes. Git's index
    // does not change for an unstaged edit, so every tracked path must be watched explicitly.
    let mut complete = emit_rerun_path(&work_dir.join("build.rs"));
    let rerun = git_rerun_paths(&work_dir);
    complete &= rerun.complete;
    for path in rerun.paths {
        complete &= emit_rerun_path(&path);
    }
    if !complete {
        println!(
            "cargo:warning=Git provenance enumeration was incomplete; build provenance is forced dirty"
        );
    }

    let commit = build_commit(&work_dir, !complete);
    println!("cargo:rustc-env=SERCTL_BUILD_COMMIT={commit}");
}

#[cfg(test)]
mod tests {
    use super::{
        build_commit, classify_head_reference, combine_worktree_files, configured_git_command,
        decorate_commit, discovered_repository_root, git_path, provenance_enumeration_complete,
        raw_tracked_worktree_is_clean, repository_root, rerun_path_text, run_git,
        validated_commit_id, working_tree_is_dirty, HeadReference, GIT_METADATA_PATHS,
        GIT_NULL_CONFIG, GIT_REPOSITORY_OVERRIDE_ENV, GIT_STATUS_ARGS,
    };
    use std::{
        ffi::OsStr,
        fs,
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempFixture(PathBuf);

    impl TempFixture {
        fn new() -> Self {
            let id = TEMP_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "serctl-build-provenance-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated Git fixture");
            Self(path)
        }
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_git_output(work_dir: &Path, args: &[&str]) -> std::process::Output {
        let output = configured_git_command(work_dir, args)
            .output()
            .expect("execute Git fixture command");
        assert!(
            output.status.success(),
            "Git fixture command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn fixture_git(work_dir: &Path, args: &[&str]) {
        let _ = fixture_git_output(work_dir, args);
    }

    fn fixture_git_text(work_dir: &Path, args: &[&str]) -> String {
        let output = fixture_git_output(work_dir, args);
        String::from_utf8(output.stdout)
            .expect("Git fixture output is not UTF-8")
            .trim()
            .to_owned()
    }

    fn committed_fixture() -> (TempFixture, PathBuf) {
        let git_version = Command::new("git")
            .arg("--version")
            .output()
            .expect("Git is required for provenance fixture tests");
        assert!(
            git_version.status.success(),
            "Git is required for provenance fixture tests: {}",
            String::from_utf8_lossy(&git_version.stderr)
        );

        let fixture = TempFixture::new();
        let repository = fixture.0.join("repository");
        fs::create_dir(&repository).expect("create fixture repository");
        let init = Command::new("git")
            .current_dir(&repository)
            .args(["init", "--quiet"])
            .output()
            .expect("initialize Git fixture");
        assert!(
            init.status.success(),
            "Git fixture init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        fixture_git(&repository, &["config", "user.name", "serctl test"]);
        fixture_git(
            &repository,
            &["config", "user.email", "serctl-test@example.invalid"],
        );
        fs::write(repository.join("tracked.txt"), "clean\n").expect("write tracked fixture input");
        fixture_git(&repository, &["add", "--", "tracked.txt"]);
        fixture_git(&repository, &["commit", "--quiet", "-m", "initial"]);
        (fixture, repository)
    }

    #[test]
    fn incomplete_git_enumeration_forces_dirty_provenance() {
        let (files, complete) =
            combine_worktree_files(None, Some(vec![PathBuf::from("untracked-source.rs")]));
        assert!(!complete);
        assert_eq!(files, [PathBuf::from("untracked-source.rs")]);
        assert_eq!(
            decorate_commit(Some("0123456789ab".into()), Some(false), !complete),
            "0123456789ab-dirty"
        );
    }

    #[test]
    fn complete_clean_enumeration_preserves_clean_commit() {
        let (_, complete) = combine_worktree_files(Some(Vec::new()), Some(Vec::new()));
        assert!(complete);
        assert_eq!(
            decorate_commit(Some("0123456789ab".into()), Some(false), !complete),
            "0123456789ab"
        );
        assert_eq!(decorate_commit(None, Some(false), false), "unknown-dirty");
        assert_eq!(
            decorate_commit(Some(String::new()), Some(false), false),
            "unknown-dirty"
        );
    }

    #[test]
    fn commit_id_is_terminal_safe_before_reaching_cargo_output() {
        assert_eq!(
            validated_commit_id(Some("0123456789ab".into())).as_deref(),
            Some("0123456789ab")
        );
        for invalid in [
            "0123456789a",
            "0123456789ab\n",
            "0123456789ab\u{1b}",
            "0123456789ab\u{202e}",
            "not-a-commit",
        ] {
            assert_eq!(validated_commit_id(Some(invalid.into())), None);
        }
    }

    #[test]
    fn detached_head_is_distinct_from_symbolic_ref_failure() {
        assert_eq!(
            classify_head_reference(false, Some(1), Some(String::new())),
            HeadReference::Detached
        );
        assert_eq!(
            classify_head_reference(false, Some(128), Some(String::new())),
            HeadReference::Failed
        );
        assert_eq!(
            classify_head_reference(true, Some(0), Some("refs/heads/main".into())),
            HeadReference::Attached("refs/heads/main".into())
        );
        assert_eq!(
            classify_head_reference(true, Some(0), Some(String::new())),
            HeadReference::Failed
        );
    }

    #[test]
    fn missing_required_metadata_forces_incomplete_provenance() {
        assert!(provenance_enumeration_complete(true, true, true));
        assert!(!provenance_enumeration_complete(false, true, true));
        assert!(!provenance_enumeration_complete(true, false, true));
        assert!(!provenance_enumeration_complete(true, true, false));

        let complete = provenance_enumeration_complete(true, true, false);
        assert_eq!(
            decorate_commit(Some("0123456789ab".into()), Some(false), !complete),
            "0123456789ab-dirty"
        );
    }

    #[test]
    fn unrepresentable_cargo_watch_paths_are_incomplete() {
        let normal = PathBuf::from("normal/path");
        let windows_separator = PathBuf::from(r"normal\path");
        let newline = PathBuf::from("bad\npath");
        let escape = PathBuf::from("bad\u{1b}]52;c;payload");
        let bidi = PathBuf::from("bad\u{202e}txt");
        let line_separator = PathBuf::from("bad\u{2028}path");
        assert_eq!(rerun_path_text(&normal), Some("normal/path"));
        assert_eq!(rerun_path_text(&windows_separator), Some(r"normal\path"));
        assert!(rerun_path_text(&newline).is_none());
        assert!(rerun_path_text(&escape).is_none());
        assert!(rerun_path_text(&bidi).is_none());
        assert!(rerun_path_text(&line_separator).is_none());
    }

    #[test]
    fn provenance_queries_reject_repository_environment_overrides() {
        for required in [
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_NO_REPLACE_OBJECTS",
        ] {
            assert!(
                GIT_REPOSITORY_OVERRIDE_ENV.contains(&required),
                "missing Git provenance override: {required}"
            );
        }

        let command = configured_git_command(std::path::Path::new("."), &["status"]);
        let environment = command.get_envs().collect::<Vec<_>>();
        let value = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| *value)
        };
        assert_eq!(value("GIT_DIR"), Some(None));
        assert_eq!(
            value("GIT_CONFIG_GLOBAL"),
            Some(Some(OsStr::new(GIT_NULL_CONFIG)))
        );
        assert_eq!(
            value("GIT_CONFIG_SYSTEM"),
            Some(Some(OsStr::new(GIT_NULL_CONFIG)))
        );
        assert_eq!(value("GIT_CONFIG_NOSYSTEM"), Some(Some(OsStr::new("1"))));
        assert_eq!(value("GIT_NO_REPLACE_OBJECTS"), Some(Some(OsStr::new("1"))));
        let arguments = command.get_args().collect::<Vec<_>>();
        assert!(arguments
            .windows(2)
            .any(|pair| { pair == [OsStr::new("-c"), OsStr::new("core.fsmonitor=false")] }));
        assert!(arguments.iter().any(|argument| {
            argument.to_string_lossy().starts_with("--work-tree=")
                && argument != &OsStr::new("--work-tree=")
        }));
    }

    #[test]
    fn dirty_status_includes_modified_submodules() {
        assert!(GIT_STATUS_ARGS.contains(&"--ignore-submodules=none"));
        assert!(!GIT_STATUS_ARGS.contains(&"--ignore-submodules=dirty"));
    }

    #[test]
    fn provenance_watches_git_configuration_that_can_change_status() {
        for required in [
            "config",
            "config.worktree",
            "info/attributes",
            "info/exclude",
        ] {
            assert!(GIT_METADATA_PATHS.contains(&required));
        }
    }

    #[test]
    fn repository_core_worktree_cannot_redirect_provenance_to_a_clean_tree() {
        let (fixture, repository) = committed_fixture();
        let clean_tree = fixture.0.join("redirected-clean-tree");
        fs::create_dir(&clean_tree).expect("create redirected worktree");
        fs::write(clean_tree.join("tracked.txt"), "clean\n").expect("write clean redirected input");
        fs::write(repository.join("tracked.txt"), "dirty manifest input\n")
            .expect("dirty real manifest input");
        let clean_tree = clean_tree.to_string_lossy().into_owned();
        fixture_git(
            &repository,
            &["config", "core.worktree", clean_tree.as_str()],
        );

        let raw = discovered_repository_root(&repository).expect("raw repository root");
        assert_eq!(
            raw.canonicalize().expect("canonical raw root"),
            repository.canonicalize().expect("canonical fixture root"),
            "configured Git still honored the repository core.worktree"
        );
        let discovered = repository_root(&repository).expect("validated repository root");
        assert_eq!(
            discovered
                .canonicalize()
                .expect("canonical discovered root"),
            repository.canonicalize().expect("canonical fixture root")
        );
        assert_eq!(working_tree_is_dirty(&repository), Some(true));
        assert!(build_commit(&repository, false).ends_with("-dirty"));
    }

    #[test]
    fn assume_unchanged_cannot_hide_a_modified_tracked_input() {
        let (_fixture, repository) = committed_fixture();
        fixture_git(
            &repository,
            &["update-index", "--assume-unchanged", "--", "tracked.txt"],
        );
        fs::write(repository.join("tracked.txt"), "hidden dirty input\n")
            .expect("modify assume-unchanged input");

        let porcelain = run_git(&repository, GIT_STATUS_ARGS).expect("read porcelain status");
        assert!(
            porcelain.stdout.is_empty(),
            "fixture no longer demonstrates porcelain hiding"
        );
        assert_eq!(working_tree_is_dirty(&repository), Some(true));
        assert!(build_commit(&repository, false).ends_with("-dirty"));
    }

    #[test]
    fn clean_filter_cannot_hide_modified_tracked_input() {
        let (_fixture, repository) = committed_fixture();
        fixture_git(
            &repository,
            &["config", "filter.provenance-mask.clean", "git show HEAD:%f"],
        );
        fixture_git(
            &repository,
            &["config", "filter.provenance-mask.required", "true"],
        );
        let attributes = git_path(&repository, "info/attributes")
            .expect("resolve repository-local attributes path");
        fs::create_dir_all(attributes.parent().expect("attributes parent"))
            .expect("create attributes parent");
        fs::write(&attributes, "tracked.txt filter=provenance-mask\n")
            .expect("install clean-filter attribute");
        // Keep the raw size equal to the committed `clean\n` blob so Git must
        // consult the clean filter instead of short-circuiting on stat size.
        fs::write(repository.join("tracked.txt"), "evil!\n")
            .expect("modify filtered tracked input");

        let attribute =
            fixture_git_text(&repository, &["check-attr", "filter", "--", "tracked.txt"]);
        assert!(
            attribute.ends_with("provenance-mask"),
            "clean-filter attribute was not active: {attribute:?}"
        );
        let filtered_oid = fixture_git_text(
            &repository,
            &["hash-object", "--path=tracked.txt", "--", "tracked.txt"],
        );
        let index_oid = fixture_git_text(&repository, &["rev-parse", ":tracked.txt"]);
        assert_eq!(
            filtered_oid, index_oid,
            "clean filter did not mask the edit"
        );

        let porcelain = run_git(&repository, GIT_STATUS_ARGS).expect("read filtered status");
        assert!(
            porcelain.stdout.is_empty(),
            "fixture no longer demonstrates a clean filter hiding the edit: {}",
            String::from_utf8_lossy(&porcelain.stdout)
        );
        assert_eq!(raw_tracked_worktree_is_clean(&repository), Some(false));
        assert_eq!(working_tree_is_dirty(&repository), Some(true));
        assert!(build_commit(&repository, false).ends_with("-dirty"));
    }

    #[test]
    fn lf_attributes_keep_autocrlf_checkout_raw_clean() {
        let (_fixture, repository) = committed_fixture();
        fixture_git(&repository, &["config", "core.autocrlf", "true"]);
        fs::write(repository.join(".gitattributes"), "* text=auto eol=lf\n")
            .expect("write LF checkout policy");
        fixture_git(&repository, &["add", "--", ".gitattributes"]);
        fixture_git(&repository, &["commit", "--quiet", "--amend", "--no-edit"]);

        fs::remove_file(repository.join("tracked.txt")).expect("remove tracked checkout copy");
        fixture_git(&repository, &["checkout", "--", "tracked.txt"]);
        assert_eq!(
            fs::read(repository.join("tracked.txt")).expect("read checked-out text"),
            b"clean\n",
            "eol=lf must override core.autocrlf in the worktree"
        );
        let porcelain = run_git(&repository, GIT_STATUS_ARGS).expect("read clean checkout status");
        assert!(
            porcelain.stdout.is_empty(),
            "autocrlf fixture checkout is not clean: {}",
            String::from_utf8_lossy(&porcelain.stdout)
        );
        assert_eq!(raw_tracked_worktree_is_clean(&repository), Some(true));
        assert_eq!(working_tree_is_dirty(&repository), Some(false));
        assert!(!build_commit(&repository, false).ends_with("-dirty"));
    }

    #[test]
    fn gitlink_entry_is_never_treated_as_raw_clean() {
        let (_fixture, repository) = committed_fixture();
        let dependency = repository.join("dependency");
        fs::create_dir(&dependency).expect("create nested repository");
        let init = Command::new("git")
            .current_dir(&dependency)
            .args(["init", "--quiet"])
            .output()
            .expect("initialize nested Git fixture");
        assert!(
            init.status.success(),
            "nested Git fixture init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        fixture_git(&dependency, &["config", "user.name", "serctl test"]);
        fixture_git(
            &dependency,
            &["config", "user.email", "serctl-test@example.invalid"],
        );
        fs::write(dependency.join("input.txt"), "dependency\n")
            .expect("write nested repository input");
        fixture_git(&dependency, &["add", "--", "input.txt"]);
        fixture_git(&dependency, &["commit", "--quiet", "-m", "dependency"]);
        let dependency_oid = fixture_git_text(&dependency, &["rev-parse", "HEAD"]);
        let cache_info = format!("160000,{dependency_oid},dependency");
        fixture_git(
            &repository,
            &["update-index", "--add", "--cacheinfo", cache_info.as_str()],
        );
        fixture_git(&repository, &["commit", "--quiet", "-m", "add gitlink"]);

        let staged = fixture_git_text(&repository, &["ls-files", "--stage", "--", "dependency"]);
        assert!(
            staged.starts_with("160000 "),
            "fixture did not create a gitlink: {staged:?}"
        );
        let porcelain = run_git(&repository, GIT_STATUS_ARGS).expect("read gitlink status");
        assert!(
            porcelain.stdout.is_empty(),
            "fixture no longer demonstrates a porcelain-clean gitlink: {}",
            String::from_utf8_lossy(&porcelain.stdout)
        );
        assert_eq!(raw_tracked_worktree_is_clean(&repository), Some(false));
        assert_eq!(working_tree_is_dirty(&repository), Some(true));
        assert!(build_commit(&repository, false).ends_with("-dirty"));
    }

    #[test]
    fn replacement_refs_cannot_make_modified_inputs_look_clean() {
        let (_fixture, repository) = committed_fixture();
        let original = fixture_git_text(&repository, &["rev-parse", "HEAD"]);
        fs::write(
            repository.join("tracked.txt"),
            "replacement-visible input\n",
        )
        .expect("modify replacement fixture input");
        fixture_git(&repository, &["add", "--", "tracked.txt"]);
        let tree = fixture_git_text(&repository, &["write-tree"]);
        let replacement = fixture_git_text(
            &repository,
            &[
                "commit-tree",
                tree.as_str(),
                "-p",
                original.as_str(),
                "-m",
                "replacement",
            ],
        );
        let replacement_ref = format!("refs/replace/{original}");
        fixture_git(
            &repository,
            &["update-ref", replacement_ref.as_str(), replacement.as_str()],
        );

        let mut unprotected = Command::new("git");
        unprotected.current_dir(&repository);
        for name in GIT_REPOSITORY_OVERRIDE_ENV {
            unprotected.env_remove(name);
        }
        let raw_status = unprotected
            .env("GIT_CONFIG_GLOBAL", GIT_NULL_CONFIG)
            .env("GIT_CONFIG_SYSTEM", GIT_NULL_CONFIG)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(GIT_STATUS_ARGS)
            .output()
            .expect("run unprotected replacement-ref status");
        assert!(raw_status.status.success());
        assert!(
            raw_status.stdout.is_empty(),
            "fixture no longer demonstrates replacement-ref status hiding"
        );

        assert_eq!(working_tree_is_dirty(&repository), Some(true));
        assert!(build_commit(&repository, false).ends_with("-dirty"));
    }
}
