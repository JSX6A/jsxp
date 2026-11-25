use memmap2::Mmap;
use rayon::prelude::*;
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use thiserror::Error;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules, Scanner};

const CLEAN_CACHE: TableDefinition<&str, &str> = TableDefinition::new("clean_cache");
const MALICIOUS_HASHES: TableDefinition<&str, &str> = TableDefinition::new("malicious_hashes");

#[derive(Debug, Error)]
pub enum JsxpError {
    #[error("Error de entrada/salida: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error de base de datos redb: {0}")] /*  */ Db(#[from] redb::Error),
    #[error("Error de transaccion redb: {0}")]
    DbTransaction(#[from] redb::TransactionError),
    #[error("Error de tabla redb: {0}")]
    DbTable(#[from] redb::TableError),
    #[error("Error de compromiso de escritura redb: {0}")]
    DbCommit(#[from] redb::CommitError),
    #[error("Error de base de datos redb: {0}")]
    DbDatabase(#[from] redb::DatabaseError),
    #[error("Error de almacenamiento redb: {0}")]
    DbStorage(#[from] redb::StorageError),
    #[error("Error compilando reglas YARA-X: {0}")]
    YaraCompile(String),
    #[error("Error escaneando con YARA-X: {0}")]
    YaraScan(String),
    #[error("Error serializando metadatos: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_file_size_bytes: u64,
    pub excluded_paths: Vec<PathBuf>,
    pub use_clean_cache: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 128 * 1024 * 1024,
            excluded_paths: Vec::new(),
            use_clean_cache: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DetectionReason {
    MaliciousHash(String),
    YaraRule(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub path: PathBuf,
    pub blake3_hash: String,
    pub reason: DetectionReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub cached_clean_files: usize,
    pub threats: Vec<ThreatFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub blake3_hash: String,
    pub reason: DetectionReason,
    pub xor_key: u8,
}

pub struct JsxpEngine {
    db: Arc<Database>,
    rules: Arc<Rules>,
    config: ScanConfig,
}

impl JsxpEngine {
    pub fn new(
        db_path: &Path,
        rules_dir: Option<&Path>,
        config: ScanConfig,
    ) -> Result<Self, JsxpError> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let db = Database::create(db_path)?;

        {
            let write_txn = db.begin_write()?;
            let _ = write_txn.open_table(CLEAN_CACHE)?;
            let _ = write_txn.open_table(MALICIOUS_HASHES)?;
            write_txn.commit()?;
        }

        let rules = Self::compile_rules(rules_dir)?;

        Ok(Self {
            db: Arc::new(db),
            rules: Arc::new(rules),
            config,
        })
    }

    fn compile_rules(rules_dir: Option<&Path>) -> Result<Rules, JsxpError> {
        let mut compiler = Compiler::new();
        let mut loaded_any = false;

        if let Some(dir) = rules_dir {
            if dir.exists() && dir.is_dir() {
                for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                            if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                                let content = fs::read_to_string(p)?;
                                compiler.add_source(content.as_str()).map_err(|e| {
                                    JsxpError::YaraCompile(format!("{}: {}", p.display(), e))
                                })?;
                                loaded_any = true;
                            }
                        }
                    }
                }
            }
        }

        if !loaded_any {
            let fallback_rule = r#"
                rule JSXP_Default_Check {
                    strings:
                        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                    condition:
                        $a
                }
            "#;
            compiler
                .add_source(fallback_rule)
                .map_err(|e| JsxpError::YaraCompile(e.to_string()))?;
        }

        Ok(compiler.build())
    }

    pub fn add_malicious_hash(&self, blake3_hex: &str, label: &str) -> Result<(), JsxpError> {
        let normalized = blake3_hex.trim().to_lowercase();
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(MALICIOUS_HASHES)?;
            table.insert(normalized.as_str(), label)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.config
            .excluded_paths
            .iter()
            .any(|excl| path.starts_with(excl))
    }

    fn file_fingerprint(metadata: &fs::Metadata) -> String {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{}:{}", modified, metadata.len())
    }

    fn hash_file_stream(path: &Path, size: u64) -> Result<String, JsxpError> {
        if size == 0 {
            let hash = blake3::hash(b"");
            return Ok(hash.to_hex().to_string());
        }

        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let hash = blake3::hash(&mmap);
        Ok(hash.to_hex().to_string())
    }

    pub fn scan_file(&self, path: &Path) -> Result<Option<ThreatFinding>, JsxpError> {
        if self.is_excluded(path) || !path.is_file() {
            return Ok(None);
        }

        let metadata = fs::metadata(path)?;
        let size = metadata.len();
        if size > self.config.max_file_size_bytes {
            return Ok(None);
        }

        let fingerprint = Self::file_fingerprint(&metadata);
        let hash_hex = Self::hash_file_stream(path, size)?;

        {
            let read_txn = self.db.begin_read()?;
            let mal_table = read_txn.open_table(MALICIOUS_HASHES)?;
            if let Some(guard) = mal_table.get(hash_hex.as_str())? {
                let label = guard.value().to_string();
                return Ok(Some(ThreatFinding {
                    path: path.to_path_buf(),
                    blake3_hash: hash_hex,
                    reason: DetectionReason::MaliciousHash(label),
                }));
            }

            if self.config.use_clean_cache {
                let clean_table = read_txn.open_table(CLEAN_CACHE)?;
                if let Some(cached_fp) = clean_table.get(hash_hex.as_str())? {
                    if cached_fp.value() == fingerprint {
                        return Ok(None);
                    }
                }
            }
        }

        let mut matched_rule: Option<String> = None;
        if size > 0 {
            let file = File::open(path)?;
            let mmap = unsafe { Mmap::map(&file)? };
            let mut scanner = Scanner::new(&self.rules);
            let results = scanner
                .scan(&mmap)
                .map_err(|e| JsxpError::YaraScan(e.to_string()))?;

            if let Some(rule) = results.matching_rules().next() {
                matched_rule = Some(rule.identifier().to_string());
            }
        }

        if let Some(rule_name) = matched_rule {
            let _ = self.add_malicious_hash(&hash_hex, &format!("YARA:{}", rule_name));
            return Ok(Some(ThreatFinding {
                path: path.to_path_buf(),
                blake3_hash: hash_hex,
                reason: DetectionReason::YaraRule(rule_name),
            }));
        }

        if self.config.use_clean_cache {
            let write_txn = self.db.begin_write()?;
            {
                let mut clean_table = write_txn.open_table(CLEAN_CACHE)?;
                clean_table.insert(hash_hex.as_str(), fingerprint.as_str())?;
            }
            write_txn.commit()?;
        }

        Ok(None)
    }

    pub fn scan_directory(&self, root: &Path) -> Result<ScanReport, JsxpError> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        let mut skipped_files: usize = 0;

        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            let path = entry.path();
            if self.is_excluded(path) {
                skipped_files += 1;
                continue;
            }
            if path.is_file() {
                match fs::metadata(path) {
                    Ok(meta) if meta.len() <= self.config.max_file_size_bytes => {
                        candidates.push(path.to_path_buf());
                    }
                    _ => {
                        skipped_files += 1;
                    }
                }
            }
        }

        let scanned_files = candidates.len();
        let findings: Vec<ThreatFinding> = candidates
            .par_iter()
            .filter_map(|p| match self.scan_file(p) {
                Ok(Some(finding)) => Some(finding),
                _ => None,
            })
            .collect();

        let unique_threats: HashSet<PathBuf> = findings.iter().map(|f| f.path.clone()).collect();
        let _ = unique_threats.len();

        Ok(ScanReport {
            scanned_files,
            skipped_files,
            cached_clean_files: 0,
            threats: findings,
        })
    }

    pub fn quarantine_threat(
        &self,
        finding: &ThreatFinding,
        quarantine_dir: &Path,
    ) -> Result<QuarantineRecord, JsxpError> {
        fs::create_dir_all(quarantine_dir)?;

        let id = format!(
            "{}_{}",
            finding.blake3_hash.chars().take(12).collect::<String>(),
            std::process::id()
        );
        let q_file_path = quarantine_dir.join(format!("{}.jsxpq", id));
        let q_meta_path = quarantine_dir.join(format!("{}.json", id));

        let xor_key: u8 = u8::from_str_radix(&finding.blake3_hash[0..2], 16)
            .unwrap_or(0x5A)
            .max(0x13);

        let mut plain_bytes = Vec::new();
        {
            let mut f = File::open(&finding.path)?;
            f.read_to_end(&mut plain_bytes)?;
        }

        let obf_bytes: Vec<u8> = plain_bytes.iter().map(|b| b ^ xor_key).collect();

        {
            let mut out = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&q_file_path)?;
            out.write_all(&obf_bytes)?;
            out.flush()?;
        }

        fs::remove_file(&finding.path)?;

        let record = QuarantineRecord {
            id,
            original_path: finding.path.clone(),
            quarantined_path: q_file_path,
            blake3_hash: finding.blake3_hash.clone(),
            reason: finding.reason.clone(),
            xor_key,
        };

        let json_data = serde_json::to_string_pretty(&record)?;
        fs::write(&q_meta_path, json_data)?;

        Ok(record)
    }
}
