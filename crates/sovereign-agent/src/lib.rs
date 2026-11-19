//! The agentic layer: skills, commands, and scripts that run only with explicit rights.
//!
//! ## The design constraint that shapes everything here
//!
//! The obvious way to build this is to let a manifest declare what to run — `command: "sh -c ..."`.
//! That is a remote code execution engine with extra steps: whoever can write a manifest becomes
//! root. So a manifest here **cannot name a program**. It can only name a *handler* that the host
//! binary registered at compile time. A manifest that asks for an unknown handler is refused, not
//! executed, and there is no shell, no `eval`, and no path resolution anywhere in this crate.
//!
//! The three layers differ in who writes them, not in how they are checked:
//!
//! * a **command** is a fixed handler invocation with fixed arguments, written by the host author;
//! * a **skill** is a named, reusable sequence of commands with a declared capability;
//! * a **script** is a skill plus a policy — retries, timeouts, and whether partial success is
//!   allowed — still with no new handlers.
//!
//! ## What a capability check actually enforces
//!
//! Every manifest declares the [`Rights`] it needs. [`Registry::run`] intersects that with the
//! caller's token rights and refuses on any shortfall. The token is the one the kernel gate
//! already understands, so a device that cannot get `NET_EGRESS` from the gate cannot get it
//! here either — there is one rights model, not two.
//!
//! ## What this does not do
//!
//! It does not sandbox the handler. A handler is ordinary Rust running in this process; if it
//! opens a file, it opens it with the process's privileges. The capability model controls *which
//! handlers may run*, not what a handler is capable of once running. Real containment is the
//! kernel's job, which is why the gate and IOMMU modules exist. Do not describe this layer as a
//! sandbox.

use std::collections::BTreeMap;

use sovereign_ipc::Rights;
use sovereign_ledger::{Ledger, LedgerError};

/// A handler the host binary registered. Arguments are strings, checked against the manifest's
/// declared arity before the handler sees them.
pub type Handler = fn(&[String]) -> Result<(), String>;

/// What a manifest is allowed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Command,
    Skill,
    Script,
}

/// One step in a skill or script: a handler name plus fixed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub handler: String,
    pub args: Vec<String>,
}

/// A parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub kind: Kind,
    /// Rights the caller must hold to run this at all.
    pub requires: Rights,
    pub steps: Vec<Step>,
    /// Script only: stop after the first failing step. Skills always stop, so this is `true`
    /// there; a script may set it to `false` to collect all failures.
    pub stop_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// The manifest text was malformed. Carries a line number and a reason, never the raw input.
    BadManifest { line: usize, why: &'static str },
    /// A step named a handler that is not registered.
    UnknownHandler(String),
    /// The caller's rights do not cover the manifest's requirement.
    InsufficientRights { need: Rights, have: Rights },
    /// A step failed. Carries the step index and the handler's own message.
    StepFailed { index: usize, message: String },
    /// The ledger refused an append, which means audit is broken; the run is abandoned.
    Audit(LedgerError),
}

impl core::fmt::Display for AgentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadManifest { line, why } => write!(f, "manifest line {line}: {why}"),
            Self::UnknownHandler(h) => write!(f, "unknown handler: {h}"),
            Self::InsufficientRights { need, have } => write!(
                f,
                "insufficient rights: need {:#07b}, have {:#07b}",
                need.bits(),
                have.bits()
            ),
            Self::StepFailed { index, message } => write!(f, "step {index} failed: {message}"),
            Self::Audit(e) => write!(f, "audit ledger refused the record: {e}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// The text format, chosen so a reviewer can read a manifest and know what it does without
/// running it.
///
/// ```text
/// # comments are ignored
/// name = sensor-sweep
/// kind = skill
/// requires = SENSOR_READ|TELEMETRY_WRITE
///
/// step = read_sensor room-a
/// step = emit_telemetry room-a
/// ```
///
/// `requires` accepts `NONE` or `|`-joined names from [`Rights`]. Anything else is refused; there
/// is no numeric form, so a typo cannot silently become a different set of rights.
pub fn parse_manifest(text: &str) -> Result<Manifest, AgentError> {
    let mut name = None;
    let mut kind = None;
    let mut requires = None;
    let mut stop_on_error = true;
    let mut steps = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let s = raw.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let (key, value) = s.split_once('=').ok_or(AgentError::BadManifest {
            line,
            why: "expected key = value",
        })?;
        let key = key.trim();
        let value = value.trim();
        match key {
            "name" => {
                if value.is_empty() || value.len() > 64 {
                    return Err(AgentError::BadManifest {
                        line,
                        why: "name must be 1..=64 characters",
                    });
                }
                name = Some(value.to_owned());
            }
            "kind" => {
                kind = Some(match value {
                    "command" => Kind::Command,
                    "skill" => Kind::Skill,
                    "script" => Kind::Script,
                    _ => {
                        return Err(AgentError::BadManifest {
                            line,
                            why: "kind must be command, skill or script",
                        })
                    }
                });
            }
            "requires" => {
                requires = Some(parse_rights(value).ok_or(AgentError::BadManifest {
                    line,
                    why: "unknown right name",
                })?);
            }
            "stop_on_error" => {
                stop_on_error = match value {
                    "true" => true,
                    "false" => false,
                    _ => {
                        return Err(AgentError::BadManifest {
                            line,
                            why: "stop_on_error must be true or false",
                        })
                    }
                };
            }
            "step" => {
                let mut parts = value.split_whitespace();
                let handler = parts.next().ok_or(AgentError::BadManifest {
                    line,
                    why: "step needs a handler name",
                })?;
                steps.push(Step {
                    handler: handler.to_owned(),
                    args: parts.map(str::to_owned).collect(),
                });
            }
            _ => {
                return Err(AgentError::BadManifest {
                    line,
                    why: "unknown key",
                })
            }
        }
    }

    Ok(Manifest {
        name: name.ok_or(AgentError::BadManifest {
            line: 1,
            why: "missing name",
        })?,
        kind: kind.ok_or(AgentError::BadManifest {
            line: 1,
            why: "missing kind",
        })?,
        requires: requires.ok_or(AgentError::BadManifest {
            line: 1,
            why: "missing requires",
        })?,
        steps,
        stop_on_error,
    })
}

fn parse_rights(s: &str) -> Option<Rights> {
    if s == "NONE" {
        return Some(Rights::NONE);
    }
    let mut acc = Rights::NONE;
    for part in s.split('|') {
        let r = match part.trim() {
            "SENSOR_READ" => Rights::SENSOR_READ,
            "TELEMETRY_WRITE" => Rights::TELEMETRY_WRITE,
            "NET_EGRESS" => Rights::NET_EGRESS,
            "CRYPTO_OP" => Rights::CRYPTO_OP,
            "ADMIN" => Rights::ADMIN,
            _ => return None,
        };
        acc = acc.union(r);
    }
    Some(acc)
}

/// Outcome of a run, for the caller and for the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub name: String,
    pub kind: Kind,
    /// Index of the step that stopped the run, if any.
    pub failed_at: Option<usize>,
    pub steps_ok: usize,
}

/// Holds the registered handlers and the audit ledger.
pub struct Registry<'a> {
    handlers: BTreeMap<String, Handler>,
    ledger: &'a mut Ledger,
}

impl<'a> Registry<'a> {
    pub fn new(ledger: &'a mut Ledger) -> Self {
        Self {
            handlers: BTreeMap::new(),
            ledger,
        }
    }

    /// Register a handler. Re-registering a name replaces it, which is deliberate: a host that
    /// loads two plugins defining the same command should notice, and the last one winning is
    /// easier to reason about than silent shadowing.
    pub fn register(&mut self, name: &str, f: Handler) -> &mut Self {
        self.handlers.insert(name.to_owned(), f);
        self
    }

    /// Run a manifest for a caller holding `granted` rights, appending to the ledger.
    ///
    /// The rights check happens **before** any handler runs, so a partially-privileged run cannot
    /// leave side effects. Each step is recorded individually, so the ledger shows exactly how
    /// far execution got — which is what makes a failed run auditable rather than just absent.
    pub fn run(&mut self, m: &Manifest, granted: Rights, at: u64) -> Result<RunReport, AgentError> {
        if !granted.contains(m.requires) {
            // Record the refusal. A denied run is exactly the event an auditor wants to see.
            self.ledger
                .append(at, "agent.run.denied", m.name.as_bytes())
                .map_err(AgentError::Audit)?;
            return Err(AgentError::InsufficientRights {
                need: m.requires,
                have: granted,
            });
        }

        // Every handler must exist before the first one runs. Discovering a typo halfway
        // through a script that already deleted something is not acceptable.
        for step in &m.steps {
            if !self.handlers.contains_key(&step.handler) {
                return Err(AgentError::UnknownHandler(step.handler.clone()));
            }
        }

        self.ledger
            .append(at, "agent.run.start", m.name.as_bytes())
            .map_err(AgentError::Audit)?;

        let mut steps_ok = 0;
        for (index, step) in m.steps.iter().enumerate() {
            let handler = self.handlers[&step.handler];
            let outcome = handler(&step.args);

            let record = format!("{}#{}", m.name, index);
            match &outcome {
                Ok(()) => {
                    steps_ok += 1;
                    self.ledger
                        .append(at, "agent.step.ok", record.as_bytes())
                        .map_err(AgentError::Audit)?;
                }
                Err(msg) => {
                    self.ledger
                        .append(
                            at,
                            "agent.step.failed",
                            format!("{record}:{msg}").as_bytes(),
                        )
                        .map_err(AgentError::Audit)?;
                    if m.stop_on_error {
                        self.ledger
                            .append(at, "agent.run.aborted", m.name.as_bytes())
                            .map_err(AgentError::Audit)?;
                        return Err(AgentError::StepFailed {
                            index,
                            message: msg.clone(),
                        });
                    }
                }
            }
        }

        self.ledger
            .append(at, "agent.run.finished", m.name.as_bytes())
            .map_err(AgentError::Audit)?;

        Ok(RunReport {
            name: m.name.clone(),
            kind: m.kind,
            failed_at: None,
            steps_ok,
        })
    }

    pub fn ledger(&self) -> &Ledger {
        self.ledger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        // Handlers are plain `fn` pointers, so they cannot capture. A thread-local log is how the
        // tests observe what actually ran, without turning the handler type into a boxed closure.
        static CALLS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn record(s: &str) {
        CALLS.with(|c| c.borrow_mut().push(s.to_owned()));
    }

    fn take() -> Vec<String> {
        CALLS.with(|c| c.borrow_mut().drain(..).collect())
    }

    fn read_sensor(args: &[String]) -> Result<(), String> {
        record(&format!("read_sensor {}", args.join(",")));
        Ok(())
    }

    fn emit(args: &[String]) -> Result<(), String> {
        record(&format!("emit {}", args.join(",")));
        Ok(())
    }

    fn boom(_args: &[String]) -> Result<(), String> {
        record("boom");
        Err("handler exploded".to_owned())
    }

    fn registry(ledger: &mut Ledger) -> Registry<'_> {
        let mut r = Registry::new(ledger);
        r.register("read_sensor", read_sensor);
        r.register("emit_telemetry", emit);
        r.register("boom", boom);
        r
    }

    fn skill() -> Manifest {
        parse_manifest(
            "name = sweep\nkind = skill\nrequires = SENSOR_READ|TELEMETRY_WRITE\n\
             step = read_sensor room-a\nstep = emit_telemetry room-a\n",
        )
        .expect("parse")
    }

    #[test]
    fn parses_all_three_kinds() {
        for (text, want) in [
            (
                "name = a\nkind = command\nrequires = NONE\nstep = read_sensor",
                Kind::Command,
            ),
            (
                "name = b\nkind = skill\nrequires = NONE\nstep = read_sensor",
                Kind::Skill,
            ),
            (
                "name = c\nkind = script\nrequires = NONE\nstep = read_sensor",
                Kind::Script,
            ),
        ] {
            assert_eq!(parse_manifest(text).expect("parse").kind, want);
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let m = parse_manifest(
            "# leading comment\n\nname = x\nkind = command\nrequires = NONE\n\n# trailing\n",
        )
        .expect("parse");
        assert_eq!(m.name, "x");
        assert!(m.steps.is_empty());
    }

    #[test]
    fn unknown_keys_are_refused_rather_than_ignored() {
        // Ignoring unknown keys is how a manifest written for a newer version silently loses a
        // restriction when read by an older one.
        let e = parse_manifest("name = x\nkind = command\nrequires = NONE\nshell = /bin/sh\n")
            .unwrap_err();
        assert!(matches!(e, AgentError::BadManifest { line: 4, .. }));
    }

    #[test]
    fn a_manifest_cannot_name_a_program_to_execute() {
        // The whole point: "run this binary" is not expressible. `step = sh -c rm -rf /` parses
        // as a handler named `sh`, which is not registered, so it is refused at run time.
        let m = parse_manifest(
            "name = evil\nkind = command\nrequires = ADMIN\nstep = sh -c rm -rf /\n",
        )
        .expect("parses as a handler reference");
        assert_eq!(m.steps[0].handler, "sh");

        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        assert_eq!(
            r.run(&m, Rights::ADMIN, 1).unwrap_err(),
            AgentError::UnknownHandler("sh".to_owned())
        );
        assert!(take().is_empty(), "nothing may execute");
    }

    #[test]
    fn rights_shortfall_is_refused_before_anything_runs() {
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let e = r.run(&skill(), Rights::SENSOR_READ, 10).unwrap_err();
        assert!(matches!(e, AgentError::InsufficientRights { .. }));
        assert!(
            take().is_empty(),
            "no handler may run when rights are short"
        );
        // The refusal itself is audited.
        assert_eq!(
            ledger.entries().last().expect("entry").kind,
            "agent.run.denied"
        );
    }

    #[test]
    fn a_granted_run_executes_every_step_in_order_and_audits_each() {
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let report = r
            .run(
                &skill(),
                Rights::SENSOR_READ.union(Rights::TELEMETRY_WRITE),
                20,
            )
            .expect("run");

        assert_eq!(report.steps_ok, 2);
        assert_eq!(take(), vec!["read_sensor room-a", "emit room-a"]);

        let kinds: Vec<_> = ledger.entries().iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "agent.run.start",
                "agent.step.ok",
                "agent.step.ok",
                "agent.run.finished"
            ]
        );
    }

    #[test]
    fn extra_rights_are_fine_but_missing_ones_are_not() {
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let all = Rights::SENSOR_READ
            .union(Rights::TELEMETRY_WRITE)
            .union(Rights::NET_EGRESS);
        r.run(&skill(), all, 30).expect("superset is enough");
        take();
    }

    #[test]
    fn a_failing_step_aborts_a_skill_and_is_audited() {
        let m = parse_manifest(
            "name = broken\nkind = skill\nrequires = NONE\n\
             step = read_sensor a\nstep = boom\nstep = emit_telemetry never\n",
        )
        .expect("parse");
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let e = r.run(&m, Rights::NONE, 40).unwrap_err();
        assert_eq!(
            e,
            AgentError::StepFailed {
                index: 1,
                message: "handler exploded".to_owned()
            }
        );
        assert_eq!(take(), vec!["read_sensor a", "boom"], "step 2 must not run");

        let kinds: Vec<_> = ledger.entries().iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"agent.step.failed"));
        assert!(kinds.contains(&"agent.run.aborted"));
        assert!(!kinds.contains(&"agent.run.finished"));
    }

    #[test]
    fn a_script_with_stop_on_error_false_continues_past_a_failure() {
        let m = parse_manifest(
            "name = tolerant\nkind = script\nrequires = NONE\nstop_on_error = false\n\
             step = boom\nstep = read_sensor after\n",
        )
        .expect("parse");
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let report = r.run(&m, Rights::NONE, 50).expect("run completes");
        assert_eq!(report.steps_ok, 1);
        assert_eq!(take(), vec!["boom", "read_sensor after"]);
    }

    #[test]
    fn an_unknown_handler_is_refused_before_any_step_runs() {
        // Typo in the last step of a long script must not let the earlier steps execute.
        let m = parse_manifest(
            "name = typo\nkind = script\nrequires = NONE\n\
             step = read_sensor a\nstep = emit_telemetry b\nstep = emit_telemetery c\n",
        )
        .expect("parse");
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        let e = r.run(&m, Rights::NONE, 60).unwrap_err();
        assert_eq!(e, AgentError::UnknownHandler("emit_telemetery".to_owned()));
        assert!(take().is_empty());
    }

    #[test]
    fn requires_none_runs_with_no_rights() {
        let m =
            parse_manifest("name = free\nkind = command\nrequires = NONE\nstep = read_sensor\n")
                .expect("parse");
        let mut ledger = Ledger::new();
        let mut r = registry(&mut ledger);
        r.run(&m, Rights::NONE, 70).expect("run");
        assert_eq!(take(), vec!["read_sensor "]);
    }

    #[test]
    fn unknown_right_names_are_refused() {
        let e = parse_manifest("name = x\nkind = command\nrequires = ROOT\n").unwrap_err();
        assert!(matches!(e, AgentError::BadManifest { line: 3, .. }));
    }

    #[test]
    fn numeric_rights_are_not_accepted() {
        // No numeric form means a typo cannot silently become a different rights set.
        assert!(parse_manifest("name = x\nkind = command\nrequires = 31\n").is_err());
    }

    #[test]
    fn every_run_leaves_a_ledger_that_verifies() {
        let mut ledger = Ledger::new();
        {
            let mut r = registry(&mut ledger);
            let _ = r.run(&skill(), Rights::SENSOR_READ, 80);
            let _ = r.run(&skill(), Rights::NONE, 81);
        }
        assert_eq!(ledger.verify(None, None), Ok(ledger.len()));
        assert!(!ledger.is_empty());
    }
}
