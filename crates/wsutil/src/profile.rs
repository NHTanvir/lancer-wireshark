//! Per-user / global profile support (`--global-profile`, `-C <profile>`).
//!
//! A profile is a directory of preference / disabled-protocols / decode-as
//! / colorfilters / display-filter files. We support saving and listing
//! profiles; per-pref schema lives in `epan::register`.

use std::path::{Path, PathBuf};

pub struct Profile {
    pub name: String,
    pub dir: PathBuf,
    pub is_global: bool,
}

impl Profile {
    pub fn user_default() -> Option<Self> {
        let base = user_profiles_dir()?;
        Some(Profile {
            name: "default".into(),
            dir: base.join("default"),
            is_global: false,
        })
    }

    pub fn user_named(name: &str) -> Option<Self> {
        let base = user_profiles_dir()?;
        Some(Profile {
            name: name.into(),
            dir: base.join(name),
            is_global: false,
        })
    }

    pub fn global_named(name: &str) -> Option<Self> {
        let base = global_profiles_dir()?;
        Some(Profile {
            name: name.into(),
            dir: base.join(name),
            is_global: true,
        })
    }

    pub fn ensure_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)
    }

    pub fn pref_file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

pub fn user_profiles_dir() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("io", "Lancer", "lancer-wireshark")?;
    Some(dirs.config_dir().join("profiles"))
}

pub fn global_profiles_dir() -> Option<PathBuf> {
    // /etc/lancer-wireshark/profiles or %PROGRAMDATA%\lancer-wireshark\profiles
    if cfg!(windows) {
        std::env::var_os("ProgramData").map(|p| Path::new(&p).join("lancer-wireshark").join("profiles"))
    } else {
        Some(PathBuf::from("/etc/lancer-wireshark/profiles"))
    }
}

pub fn list_profiles() -> Vec<String> {
    let mut out = Vec::new();
    if let Some(d) = user_profiles_dir() {
        if let Ok(entries) = std::fs::read_dir(&d) {
            for e in entries.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    if let Some(name) = e.file_name().to_str() {
                        out.push(name.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    out
}
