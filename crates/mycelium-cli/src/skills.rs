use std::path::{Path, PathBuf};

use myceliumd::client::ClientError;

struct BundledSkill {
    name: &'static str,
    skill: &'static str,
    openai: &'static str,
}

const SKILLS: &[BundledSkill] = &[
    BundledSkill {
        name: "mycelium-network-operator",
        skill: include_str!("../../../skills/mycelium-network-operator/SKILL.md"),
        openai: include_str!("../../../skills/mycelium-network-operator/agents/openai.yaml"),
    },
    BundledSkill {
        name: "mycelium-fleet-security",
        skill: include_str!("../../../skills/mycelium-fleet-security/SKILL.md"),
        openai: include_str!("../../../skills/mycelium-fleet-security/agents/openai.yaml"),
    },
    BundledSkill {
        name: "mycelium-driver-development",
        skill: include_str!("../../../skills/mycelium-driver-development/SKILL.md"),
        openai: include_str!("../../../skills/mycelium-driver-development/agents/openai.yaml"),
    },
];

pub fn run(args: &[String]) -> Result<Vec<String>, ClientError> {
    let action = args.first().map(String::as_str).unwrap_or("list");
    let json = args.iter().any(|arg| arg == "--json");
    if action == "list" {
        if json {
            return Ok(vec![serde_json::json!({
                "skills": SKILLS.iter().map(|skill| skill.name).collect::<Vec<_>>()
            })
            .to_string()]);
        }
        return Ok(std::iter::once("bundled Mycelium skills:".into())
            .chain(SKILLS.iter().map(|skill| format!("  {}", skill.name)))
            .collect());
    }
    if action != "install" && action != "sync" {
        return Err(usage("skills supports list, install, and sync"));
    }
    let write = args.iter().any(|arg| arg == "--write");
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    if !write && !dry_run {
        return Err(usage("skill installation requires --write or --dry-run"));
    }
    let value_after = |flag: &str| {
        args.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    };
    let root = value_after("--path")
        .map(PathBuf::from)
        .unwrap_or(skill_root(value_after("--target").as_deref())?);
    let requested = args
        .iter()
        .skip(1)
        .find(|arg| !arg.starts_with('-') && !is_option_value(args, arg))
        .map(String::as_str);
    let selected = SKILLS
        .iter()
        .filter(|skill| action == "sync" || requested.is_none_or(|name| name == skill.name))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(usage("unknown bundled skill"));
    }
    let mut installed = Vec::new();
    for skill in selected {
        let destination = root.join(skill.name);
        if write && !dry_run {
            atomic_write(&destination.join("SKILL.md"), skill.skill.as_bytes())?;
            atomic_write(
                &destination.join("agents/openai.yaml"),
                skill.openai.as_bytes(),
            )?;
        }
        installed.push(serde_json::json!({
            "name": skill.name,
            "path": destination,
            "dry_run": dry_run,
        }));
    }
    if json {
        return Ok(vec![serde_json::Value::Array(installed).to_string()]);
    }
    Ok(installed
        .iter()
        .map(|item| {
            format!(
                "{} {} -> {}",
                if dry_run {
                    "would install"
                } else {
                    "installed"
                },
                item["name"].as_str().unwrap_or("?"),
                item["path"].as_str().unwrap_or("?"),
            )
        })
        .collect())
}

fn is_option_value(args: &[String], candidate: &str) -> bool {
    args.windows(2)
        .any(|pair| matches!(pair[0].as_str(), "--target" | "--path") && pair[1] == candidate)
}

fn skill_root(target: Option<&str>) -> Result<PathBuf, ClientError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| usage("HOME is unavailable; pass --path"))?;
    match target.unwrap_or("codex") {
        "codex" => Ok(std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"))
            .join("skills")),
        "agents" => Ok(home.join(".agents/skills")),
        "claude" => Ok(home.join(".claude/skills")),
        other => Err(usage(&format!("unknown skill target `{other}`"))),
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ClientError> {
    let parent = path
        .parent()
        .ok_or_else(|| usage("skill path has no parent"))?;
    std::fs::create_dir_all(parent).map_err(ClientError::Io)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, bytes).map_err(ClientError::Io)?;
    std::fs::rename(temporary, path).map_err(ClientError::Io)
}

fn usage(message: &str) -> ClientError {
    ClientError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_skills_have_matching_frontmatter_names() {
        for skill in SKILLS {
            assert!(skill.skill.starts_with("---\nname: "));
            assert!(skill.skill.contains(&format!("\nname: {}\n", skill.name)));
            assert!(skill.openai.contains("default_prompt:"));
        }
    }
}
