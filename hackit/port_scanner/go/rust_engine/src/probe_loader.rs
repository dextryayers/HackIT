use crate::probe_engine::{LoadedProbes, ProbeDefinition};
use std::fs;
use std::path::Path;

pub fn load_probes_from_path(path: &Path) -> Result<LoadedProbes, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    let mut defs: Vec<ProbeDefinition> = Vec::new();

    if meta.is_dir() {
        let entries = fs::read_dir(path).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                continue;
            }
            if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                let ext_l = ext.to_lowercase();
                if ext_l == "json" || ext_l == "yaml" || ext_l == "yml" {
                    let loaded = load_probes_from_file(&p)?;
                    defs.extend(loaded);
                }
            }
        }
    } else {
        defs.extend(load_probes_from_file(path)?);
    }

    Ok(LoadedProbes::new(defs))
}

pub fn load_probes_from_file(path: &Path) -> Result<Vec<ProbeDefinition>, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "yaml" || ext == "yml" {
        // Accept either a single definition or a list
        if let Ok(list) = serde_yaml::from_str::<Vec<ProbeDefinition>>(&content) {
            return Ok(list);
        }
        let single = serde_yaml::from_str::<ProbeDefinition>(&content).map_err(|e| e.to_string())?;
        return Ok(vec![single]);
    }

    // JSON
    if let Ok(list) = serde_json::from_str::<Vec<ProbeDefinition>>(&content) {
        return Ok(list);
    }
    let single = serde_json::from_str::<ProbeDefinition>(&content).map_err(|e| e.to_string())?;
    Ok(vec![single])
}
