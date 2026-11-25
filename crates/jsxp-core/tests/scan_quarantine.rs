use jsxp_core::{DetectionReason, JsxpEngine, ScanConfig};
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const EICAR: &str = r#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("reloj del sistema")
        .as_nanos();
    std::env::temp_dir().join(format!("jsxp-core-test-{}-{}", process::id(), nanos))
}

#[test]
fn scan_eicar_and_quarantine_xor() {
    let root = temp_root();
    fs::create_dir_all(&root).expect("crear directorio temporal");

    let db_path = root.join("test.db");
    let eicar_path = root.join("eicar.txt");
    fs::write(&eicar_path, EICAR).expect("escribir archivo EICAR");

    let engine =
        JsxpEngine::new(&db_path, None, ScanConfig::default()).expect("inicializar motor JSXP");

    let finding = engine
        .scan_file(&eicar_path)
        .expect("escaneo no debe fallar")
        .expect("EICAR debe ser detectado");

    assert!(
        matches!(finding.reason, DetectionReason::YaraRule(_)),
        "se esperaba detección por regla YARA, se obtuvo {:?}",
        finding.reason
    );

    let qdir = root.join("quarantine");
    let record = engine
        .quarantine_threat(&finding, &qdir)
        .expect("cuarentena no debe fallar");

    assert!(!eicar_path.exists(), "el archivo original debe eliminarse");
    assert!(
        record.quarantined_path.exists(),
        "el archivo en cuarentena debe existir"
    );

    let obfuscated = fs::read(&record.quarantined_path).expect("leer archivo en cuarentena");
    let restored: Vec<u8> = obfuscated.iter().map(|b| b ^ record.xor_key).collect();
    assert_eq!(
        restored,
        EICAR.as_bytes(),
        "la descifrado XOR debe recuperar el original"
    );

    fs::remove_dir_all(&root).ok();
}
