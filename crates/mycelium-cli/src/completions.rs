use std::collections::{BTreeMap, BTreeSet};

use myceliumd::client::ClientError;

pub fn command(args: &[String], usage: &str) -> Result<Vec<String>, ClientError> {
    let shell = args
        .first()
        .ok_or_else(|| usage_error("completions needs zsh, bash, or fish"))?;
    let tree = command_tree(usage);
    let rendered = match shell.as_str() {
        "zsh" => render_zsh(&tree),
        "bash" => render_bash(&tree),
        "fish" => render_fish(&tree),
        other => return Err(usage_error(&format!("unsupported shell `{other}`"))),
    };
    Ok(rendered.lines().map(str::to_owned).collect())
}

fn command_tree(usage: &str) -> BTreeMap<Vec<String>, BTreeSet<String>> {
    let mut tree = BTreeMap::<Vec<String>, BTreeSet<String>>::new();
    for path in command_paths(usage) {
        for index in 0..path.len() {
            tree.entry(path[..index].to_vec())
                .or_default()
                .insert(path[index].clone());
        }
    }
    tree
}

fn command_paths(usage: &str) -> BTreeSet<Vec<String>> {
    let mut paths = BTreeSet::new();
    for line in usage.lines().map(str::trim) {
        let Some(expression) = line.strip_prefix("mycelium ") else {
            continue;
        };
        let tokens = expression.split_whitespace().collect::<Vec<_>>();
        let mut prefixes = vec![Vec::<String>::new()];
        let mut index = 0;
        while index < tokens.len() {
            let raw = tokens[index];
            if raw.starts_with("[--") || raw.starts_with("(--") || raw.starts_with("--") {
                break;
            }
            if raw.starts_with('[') {
                let mut group = Vec::new();
                let mut depth = 0isize;
                while index < tokens.len() {
                    let token = tokens[index];
                    depth += token.chars().filter(|character| *character == '[').count() as isize;
                    depth -= token.chars().filter(|character| *character == ']').count() as isize;
                    group.push(token);
                    index += 1;
                    if depth <= 0 {
                        break;
                    }
                }
                let alternatives = optional_commands(&group);
                if alternatives.is_empty() {
                    break;
                }
                for prefix in prefixes.clone() {
                    paths.insert(prefix.clone());
                    for alternative in &alternatives {
                        let mut path = prefix.clone();
                        path.push(alternative.clone());
                        paths.insert(path);
                    }
                }
                break;
            }
            let token = clean(raw);
            if !is_command_atom(token) {
                break;
            }
            let alternatives = token.split('|').collect::<Vec<_>>();
            prefixes = prefixes
                .into_iter()
                .flat_map(|prefix| {
                    alternatives.iter().map(move |alternative| {
                        let mut path = prefix.clone();
                        path.push((*alternative).to_owned());
                        path
                    })
                })
                .collect();
            index += 1;
        }
        paths.extend(prefixes);
    }
    paths
}

fn optional_commands(tokens: &[&str]) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    let mut at_alternative_start = true;
    for raw in tokens {
        for part in clean(raw).split('|') {
            if part.is_empty() {
                at_alternative_start = true;
            } else if at_alternative_start && is_command_atom(part) {
                commands.insert(part.to_owned());
                at_alternative_start = false;
            }
        }
        if raw.contains('|') {
            at_alternative_start = true;
        }
    }
    commands
}

fn clean(token: &str) -> &str {
    token.trim_matches(|character| matches!(character, '[' | ']' | '(' | ')' | ','))
}

fn is_command_atom(token: &str) -> bool {
    !token.is_empty()
        && token.split('|').all(|part| {
            part.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
}

fn render_zsh(tree: &BTreeMap<Vec<String>, BTreeSet<String>>) -> String {
    let cases = render_cases(tree, "    ", "_values 'subcommand'");
    format!(
        "#compdef mycelium\n_mycelium() {{\n  local context=${{(j: :)words[2,$((CURRENT-1))]}}\n  case \"$context\" in\n{cases}  esac\n}}\ncompdef _mycelium mycelium\n"
    )
}

fn render_bash(tree: &BTreeMap<Vec<String>, BTreeSet<String>>) -> String {
    let mut cases = String::new();
    for (prefix, children) in tree {
        let key = prefix.join(" ");
        let values = children.iter().cloned().collect::<Vec<_>>().join(" ");
        cases.push_str(&format!("    '{key}') candidates='{values}' ;;\n"));
    }
    format!(
        "_mycelium() {{\n  local current context candidates\n  current=${{COMP_WORDS[COMP_CWORD]}}\n  context=${{COMP_WORDS[*]:1:COMP_CWORD-1}}\n  case \"$context\" in\n{cases}  esac\n  COMPREPLY=($(compgen -W \"$candidates\" -- \"$current\"))\n}}\ncomplete -F _mycelium mycelium\n"
    )
}

fn render_fish(tree: &BTreeMap<Vec<String>, BTreeSet<String>>) -> String {
    let mut output = String::from(
        "function __mycelium_has_prefix\n  set -l tokens (commandline -opc)\n  set -e tokens[1]\n  set -l expected $argv\n  test (count $tokens) -eq (count $expected); or return 1\n  for index in (seq (count $expected))\n    test \"$tokens[$index]\" = \"$expected[$index]\"; or return 1\n  end\nend\ncomplete -c mycelium -f\n",
    );
    for (prefix, children) in tree {
        let condition = if prefix.is_empty() {
            "__mycelium_has_prefix".to_owned()
        } else {
            format!("__mycelium_has_prefix {}", prefix.join(" "))
        };
        let values = children.iter().cloned().collect::<Vec<_>>().join(" ");
        output.push_str(&format!(
            "complete -c mycelium -n '{condition}' -a '{values}'\n"
        ));
    }
    output
}

fn render_cases(
    tree: &BTreeMap<Vec<String>, BTreeSet<String>>,
    indent: &str,
    action: &str,
) -> String {
    let mut output = String::new();
    for (prefix, children) in tree {
        let key = prefix.join(" ");
        let values = children.iter().cloned().collect::<Vec<_>>().join(" ");
        output.push_str(&format!("{indent}'{key}') {action} {values} ;;\n"));
    }
    output
}

fn usage_error(message: &str) -> ClientError {
    ClientError::Protocol(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "usage:\n  mycelium daemon status|start|stop\n  mycelium resources [show ID | watch [--once]] [--json]\n  mycelium access ssh issue --grant ID\n  mycelium scan\n";

    #[test]
    fn derives_nested_and_alternative_commands() {
        let tree = command_tree(SAMPLE);
        assert_eq!(
            tree.get(&Vec::<String>::new()).unwrap(),
            &BTreeSet::from([
                "access".into(),
                "daemon".into(),
                "resources".into(),
                "scan".into(),
            ])
        );
        assert_eq!(
            tree.get(&vec!["daemon".into()]).unwrap(),
            &BTreeSet::from(["start".into(), "status".into(), "stop".into()])
        );
        assert_eq!(
            tree.get(&vec!["resources".into()]).unwrap(),
            &BTreeSet::from(["show".into(), "watch".into()])
        );
        assert_eq!(
            tree.get(&vec!["access".into(), "ssh".into()]).unwrap(),
            &BTreeSet::from(["issue".into()])
        );
    }

    #[test]
    fn renders_all_supported_shells() {
        let tree = command_tree(SAMPLE);
        assert!(render_zsh(&tree).contains("#compdef mycelium"));
        assert!(render_bash(&tree).contains("complete -F _mycelium mycelium"));
        assert!(render_fish(&tree).contains("complete -c mycelium"));
    }
}
