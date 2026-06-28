use std::fs;
use crate::services::file::FileServiceImpl;
use crate::core::FileService;
use crate::errors::XorError;

fn unique_paths(label: &str) -> (String, String) {
    let a = std::env::temp_dir().join(format!("xor_{}_a_{}.bin", label, uuid::Uuid::new_v4()));
    let b = std::env::temp_dir().join(format!("xor_{}_b_{}.bin", label, uuid::Uuid::new_v4()));
    (a.to_string_lossy().to_string(), b.to_string_lossy().to_string())
}

#[test]
fn xor_create_and_read_roundtrip() {
    let fs_impl = FileServiceImpl::new();
    let (path_a, path_b) = unique_paths("roundtrip");

    let k1 = "password-one";
    let k2 = "password-two";

    let _ = fs_impl.create_xor_files(k1, k2, &path_a, &path_b).expect("create xor files");

    let meta_a = fs::metadata(&path_a).expect("meta a");
    let meta_b = fs::metadata(&path_b).expect("meta b");
    assert_eq!(meta_a.len() as usize, 16 * 1024);
    assert_eq!(meta_b.len() as usize, 16 * 1024);

    let (r1, r2) = fs_impl.read_xor_files(&path_a, &path_b).expect("read xor files");
    assert_eq!(r1, k1);
    assert_eq!(r2, k2);

    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);
}

#[test]
fn xor_read_invalid_size_fails() {
    let fs_impl = FileServiceImpl::new();
    let (path_a, path_b) = unique_paths("invalid");

    fs::write(&path_a, b"too small").expect("write small a");
    fs::write(&path_b, b"also small").expect("write small b");

    let res = fs_impl.read_xor_files(&path_a, &path_b);
    assert!(matches!(res.unwrap_err(), XorError::InvalidSize { .. }));

    let _ = fs::remove_file(&path_a);
    let _ = fs::remove_file(&path_b);
}
