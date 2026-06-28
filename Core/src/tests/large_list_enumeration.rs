use crate::tests::common;
use crate::core::MasterKeyInput;

#[test]
fn large_list_enumeration_filters_correctly() {
    let vault = common::build_test_vault();
    let master = MasterKeyInput::new("big-k1".to_string(), "big-k2".to_string());

    let (_d0, _r0) = common::setup_basic_session(&vault, &master);

    let devices = 50usize;
    let restrictions_per_device = 3usize;
    let domains_per_restriction = 4usize;

    let mut created_devices = Vec::new();
    let mut created_restrictions = Vec::new();

    for i in 0..devices {
        let name = format!("BulkDevice-{}", i);
        let d = vault.add_device(&name, &master).expect("add device");
        created_devices.push(d);

        for j in 0..restrictions_per_device {
            let rname = format!("R-{}-{}", i, j);
            let r = vault.add_restriction(&rname, d, crate::models::GenerationParams::default()).expect("add restriction");
            created_restrictions.push((d, r));

            for k in 0..domains_per_restriction {
                let id = format!("{}.{}.{}", i, j, k);
                let _ = vault.add_domain(&id, r).expect("add domain");
            }
        }
    }

    let listed = vault.list_devices().expect("list devices");
    assert!(listed.len() >= devices + 1); // includes initial device

    let (device_uuid, _) = created_restrictions.first().cloned().expect("at least one restriction");
    let res = vault.list_restrictions(device_uuid).expect("list restrictions");
    // `add_device` creates a default restriction per device, so expect +1
    assert_eq!(res.len(), restrictions_per_device + 1);

    let (_, restriction_uuid) = created_restrictions.first().cloned().unwrap();
    let doms = vault.list_domains(restriction_uuid).expect("list domains");
    assert_eq!(doms.len(), domains_per_restriction);

    // Each device gets the default restriction during add_device.
    let lonely = vault.add_device("LonelyDevice", &master).expect("add lonely");
    let lon_res = vault.list_restrictions(lonely).expect("list restrictions lonely");
    assert_eq!(lon_res.len(), 1);
}
