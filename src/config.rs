use std::ffi::CStr;

#[derive(Debug, Clone)]
pub struct ModuleConfig {
    pub debug: bool,
    pub prompt: String,
    pub max_tries: u32,
    pub timeout_secs: u64,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self {
            debug: false,
            prompt: "Password or fingerprint: ".to_string(),
            max_tries: 3,
            timeout_secs: 30,
        }
    }
}

impl ModuleConfig {
    pub fn parse(args: &[&CStr]) -> Self {
        let mut config = Self::default();

        for arg in args {
            if let Ok(s) = arg.to_str() {
                let trimmed = s.trim();
                if trimmed == "debug" {
                    config.debug = true;
                } else if let Some(val) = trimmed.strip_prefix("prompt=") {
                    let unquoted = val.trim_matches('"').trim_matches('\'');
                    config.prompt = unquoted.to_string();
                } else if let Some(val) = trimmed.strip_prefix("max_tries=")
                    && let Ok(n) = val.parse::<u32>()
                    && n > 0
                {
                    config.max_tries = n;
                } else if let Some(val) = trimmed.strip_prefix("timeout=")
                    && let Ok(n) = val.parse::<u64>()
                    && n > 0
                {
                    config.timeout_secs = n;
                }
            }
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_default_config() {
        let config = ModuleConfig::parse(&[]);
        assert!(!config.debug);
        assert_eq!(config.prompt, "Password or fingerprint: ");
        assert_eq!(config.max_tries, 3);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_custom_config() {
        let c1 = CString::new("debug").unwrap();
        let c2 = CString::new("prompt=\"Enter password or swipe: \"").unwrap();
        let c3 = CString::new("max_tries=5").unwrap();
        let c4 = CString::new("timeout=15").unwrap();

        let args = vec![c1.as_c_str(), c2.as_c_str(), c3.as_c_str(), c4.as_c_str()];
        let config = ModuleConfig::parse(&args);

        assert!(config.debug);
        assert_eq!(config.prompt, "Enter password or swipe: ");
        assert_eq!(config.max_tries, 5);
        assert_eq!(config.timeout_secs, 15);
    }

    #[test]
    fn test_invalid_and_fallback_values() {
        let c1 = CString::new("max_tries=invalid").unwrap();
        let c2 = CString::new("timeout=0").unwrap();
        let c3 = CString::new("unknown_flag").unwrap();

        let args = vec![c1.as_c_str(), c2.as_c_str(), c3.as_c_str()];
        let config = ModuleConfig::parse(&args);

        assert!(!config.debug);
        assert_eq!(config.max_tries, 3);
        assert_eq!(config.timeout_secs, 30);
    }
}
