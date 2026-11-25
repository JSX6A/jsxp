use jsxp_core::{JsxpEngine, ScanConfig};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn db_path() -> PathBuf {
    std::env::var("JSXP_DB")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("jsxp.db"))
}

fn print_usage() {
    eprintln!("Uso: jsxp-cli <comando> [argumentos]");
    eprintln!("Comandos:");
    eprintln!("  scan <ruta>                          escanea un archivo o directorio");
    eprintln!("  add-hash <blake3_hex> <etiqueta>     registra un hash malicioso");
    eprintln!("  quarantine <ruta> <dir_cuarentena>   escanea y pone en cuarentena amenazas");
}

fn print_finding(f: &jsxp_core::ThreatFinding) {
    println!(
        "amenaza: {} | hash: {} | motivo: {:?}",
        f.path.display(),
        f.blake3_hash,
        f.reason
    );
}

fn run_scan(engine: &JsxpEngine, path: &Path) -> Result<(), jsxp_core::JsxpError> {
    if path.is_dir() {
        let report = engine.scan_directory(path)?;
        println!(
            "escaneados: {} | omitidos: {} | amenazas: {}",
            report.scanned_files,
            report.skipped_files,
            report.threats.len()
        );
        for f in &report.threats {
            print_finding(f);
        }
    } else {
        match engine.scan_file(path)? {
            Some(f) => {
                print_finding(&f);
            }
            None => {
                println!("sin amenazas: {}", path.display());
            }
        }
    }
    Ok(())
}

fn run_quarantine(
    engine: &JsxpEngine,
    path: &Path,
    quarantine_dir: &Path,
) -> Result<(), jsxp_core::JsxpError> {
    if path.is_dir() {
        let report = engine.scan_directory(path)?;
        if report.threats.is_empty() {
            println!("sin amenazas en directorio: {}", path.display());
            return Ok(());
        }
        for f in &report.threats {
            let record = engine.quarantine_threat(f, quarantine_dir)?;
            println!(
                "cuarentena: {} -> {} | id: {}",
                f.path.display(),
                record.quarantined_path.display(),
                record.id
            );
        }
        return Ok(());
    }

    match engine.scan_file(path)? {
        Some(finding) => {
            let record = engine.quarantine_threat(&finding, quarantine_dir)?;
            println!(
                "cuarentena: {} -> {} | id: {}",
                finding.path.display(),
                record.quarantined_path.display(),
                record.id
            );
        }
        None => {
            println!("sin amenazas: {}", path.display());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        print_usage();
        return ExitCode::FAILURE;
    }

    let engine = match JsxpEngine::new(&db_path(), None, ScanConfig::default()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("Error inicializando motor: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = match args[0].as_str() {
        "scan" => {
            if args.len() < 2 {
                print_usage();
                return ExitCode::FAILURE;
            }
            run_scan(&engine, Path::new(&args[1]))
        }
        "add-hash" => {
            if args.len() < 3 {
                print_usage();
                return ExitCode::FAILURE;
            }
            engine.add_malicious_hash(&args[1], &args[2])
        }
        "quarantine" => {
            if args.len() < 3 {
                print_usage();
                return ExitCode::FAILURE;
            }
            run_quarantine(&engine, Path::new(&args[1]), Path::new(&args[2]))
        }
        _ => {
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
