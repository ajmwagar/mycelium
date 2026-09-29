use std::collections::BTreeMap;

pub fn fields(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let key = key.trim().to_ascii_lowercase().replace(' ', "_");
            let value = value.trim();
            (!key.is_empty() && !value.is_empty()).then(|| (key, value.to_owned()))
        })
        .collect()
}

pub fn slug(value: &str) -> String {
    let mut out = String::new();
    for character in value.to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mca_info_without_binding_to_field_order() {
        let parsed = fields(
            "Model: UAP-AC-Pro-Gen2\nVersion: 6.6.77.15402\nMAC Address: 24:a4:3c:00:00:01\nStatus: Connected (http://192.168.1.2:8080/inform)\n",
        );
        assert_eq!(parsed["model"], "UAP-AC-Pro-Gen2");
        assert_eq!(parsed["mac_address"], "24:a4:3c:00:00:01");
        assert!(parsed["status"].starts_with("Connected"));
    }

    #[test]
    fn slug_is_stable_for_device_ids() {
        assert_eq!(slug("UAP AC Pro / Office"), "uap-ac-pro-office");
    }
}
