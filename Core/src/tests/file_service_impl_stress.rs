use crate::services::file::FileServiceImpl;
use crate::core::FileService;
use crate::models::{SessionFile, SessionHeader, Argon2Params};
use std::env;
use std::fs;
use std::sync::Arc;
use std::thread;

fn unique_tmp_path(name: &str) -> String {
    env::temp_dir()
        .join(format!("{}_{}.vaultseed", name, uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

#[test]
fn concurrent_atomic_session_writes_same_path() {
    let svc = Arc::new(FileServiceImpl::new());
    let path = unique_tmp_path("stress_session");

    let _ = fs::remove_file(&path);

    let mut handles = Vec::new();
    for t in 0..8 {
        let svc = Arc::clone(&svc);
        let path = path.clone();
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let header = SessionHeader::new([t as u8; 32], Argon2Params { m_cost_kib: 1024, t_cost: 2, p_cost: 1 }, false, None);
                let session = SessionFile {
                    header,
                    nonce_global: [i as u8; 24],
                    ciphertext_global: vec![t as u8; 64],
                    session_hmac: None,
                };

                let _ = svc.save_session_file(&path, &session);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }

    let loaded = svc.load_session_file(&path).expect("load final session");
    assert_eq!(loaded.header.schema_version, 1);
    assert_eq!(loaded.ciphertext_global.len(), 64);

    let _ = fs::remove_file(&path);
}

#[test]
fn concurrent_xor_create_and_read() {
    let svc = Arc::new(FileServiceImpl::new());
    let mut handles = Vec::new();

    for i in 0..12 {
        let svc = Arc::clone(&svc);
        let a = unique_tmp_path(&format!("xor_a_{}", i));
        let b = unique_tmp_path(&format!("xor_b_{}", i));
        let k1 = format!("k1-{}", i);
        let k2 = format!("k2-{}", i);
        handles.push(thread::spawn(move || {
            svc.create_xor_files(&k1, &k2, &a, &b).expect("create xor");
            let (r1, r2) = svc.read_xor_files(&a, &b).expect("read xor");
            assert_eq!(r1, k1);
            assert_eq!(r2, k2);
            let _ = fs::remove_file(&a);
            let _ = fs::remove_file(&b);
        }));
    }

    for h in handles {
        let _ = h.join();
    }
}
