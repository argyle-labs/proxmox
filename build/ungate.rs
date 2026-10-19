use std::collections::BTreeSet;

pub fn parse_allowlist(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

pub struct Rewrite {
    pub source: String,
    pub unused: BTreeSet<String>,
    pub gets: usize,
    pub rewritten: usize,
}

pub fn classify_gets(src: &str, allow: &BTreeSet<String>, gated: &BTreeSet<String>) -> Rewrite {
    if let Some(both) = allow.intersection(gated).next() {
        panic!("{both} is both read-allowlisted and gated");
    }
    let mut source = String::with_capacity(src.len());
    let mut unused: BTreeSet<String> = allow.union(gated).cloned().collect();
    let (mut gets, mut rewritten) = (0, 0);
    let mut pending: Option<&str> = None;
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix("/// Auto-generated from `") {
            pending = rest.strip_prefix("GET ").and_then(|r| r.strip_suffix("`."));
            gets += usize::from(pending.is_some());
        } else if line.starts_with("#[orca_tool(") {
            if let Some(path) = pending.take() {
                let attrs = line
                    .strip_suffix(")]")
                    .unwrap_or_else(|| panic!("multi-line orca_tool attribute: {line}"));
                for key in ["execute_gated", "data_mutation"] {
                    assert!(
                        !attrs.contains(&format!("{key} =")),
                        "GET {path} already sets {key}: {line}"
                    );
                }
                let spec_admin = attrs.contains("role = \"admin\"");
                assert!(
                    spec_admin || !attrs.contains("role ="),
                    "GET {path} already sets role other than admin: {line}"
                );
                assert!(
                    !(spec_admin && allow.contains(path)),
                    "GET {path} is x-orca-admin in the spec and read-allowlisted"
                );
                unused.remove(path);
                let (role, execute_gated) = if allow.contains(path) {
                    ("read", false)
                } else {
                    ("admin", gated.contains(path))
                };
                rewritten += 1;
                source.push_str(attrs);
                if !spec_admin {
                    source.push_str(&format!(", role = \"{role}\""));
                }
                source.push_str(&format!(
                    ", execute_gated = {execute_gated}, data_mutation = false)]\n"
                ));
                continue;
            }
        } else if !line.starts_with("#[") && !line.starts_with("///") {
            pending = None;
        }
        source.push_str(line);
        source.push('\n');
    }
    Rewrite {
        source,
        unused,
        gets,
        rewritten,
    }
}

pub fn check_unused(
    unused: &BTreeSet<String>,
    gated: &BTreeSet<String>,
    no_tool: &BTreeSet<String>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for path in unused {
        assert!(
            gated.contains(path) && no_tool.contains(path),
            "read_allowlist.txt / gated_gets.txt name a path with no surfaced GET: {path}"
        );
        warnings.push(format!(
            "gated GET {path} has no tool (x-orca-no-tool); gate kept"
        ));
    }
    warnings
}
