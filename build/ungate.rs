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
                for key in ["role", "execute_gated", "data_mutation"] {
                    assert!(
                        !attrs.contains(&format!("{key} =")),
                        "GET {path} already sets {key}: {line}"
                    );
                }
                unused.remove(path);
                let (role, execute_gated) = if allow.contains(path) {
                    ("read", false)
                } else {
                    ("admin", gated.contains(path))
                };
                rewritten += 1;
                source.push_str(attrs);
                source.push_str(&format!(
                    ", role = \"{role}\", execute_gated = {execute_gated}, data_mutation = false)]\n"
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
