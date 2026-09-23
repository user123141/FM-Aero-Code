//! Persistent settings stored as JSON next to the executable.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Settings {
    pub cipher_kind: u8,
    pub compression: u8,
    pub resilience: u8,
    pub border: bool,
    pub theme_dark: bool,
    pub recent_files: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cipher_kind: 1,
            compression: 2,
            resilience: 0,
            border: false,
            theme_dark: true,
            recent_files: Vec::new(),
        }
    }
}

impl Settings {
    pub fn path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fm_settings.json")))
            .unwrap_or_else(|| PathBuf::from("fm_settings.json"))
    }

    pub fn load() -> Self {
        let path = Self::path();
        let Ok(text) = std::fs::read_to_string(&path) else { return Self::default() };
        let mut s = Self::default();
        for line in text.lines() {
            let line = line.trim().trim_end_matches(',');
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().trim_matches('"');
                let v = v.trim().trim_matches('"');
                match k {
                    "cipher_kind" => if let Ok(n) = v.parse() { s.cipher_kind = n; },
                    "compression" => if let Ok(n) = v.parse() { s.compression = n; },
                    "resilience" => if let Ok(n) = v.parse() { s.resilience = n; },
                    "border" => s.border = v == "true",
                    "theme_dark" => s.theme_dark = v == "true",
                    "recent_files" => {
                        for f in v.split('|') {
                            if !f.is_empty() { s.recent_files.push(f.to_string()); }
                        }
                    }
                    _ => {}
                }
            }
        }
        s
    }

    pub fn save(&self) {
        let recent = self.recent_files.join("|");
        let json = format!(
            "{{\n  \"cipher_kind\": {},\n  \"compression\": {},\n  \"resilience\": {},\n  \"border\": {},\n  \"theme_dark\": {},\n  \"recent_files\": \"{}\"\n}}\n",
            self.cipher_kind, self.compression, self.resilience,
            self.border, self.theme_dark, recent,
        );
        let _ = std::fs::write(Self::path(), json);
    }

    pub fn add_recent(&mut self, path: &str) {
        self.recent_files.retain(|f| f != path);
        self.recent_files.insert(0, path.to_string());
        if self.recent_files.len() > 5 { self.recent_files.truncate(5); }
    }
}