//! Native link contract for the WS63 radio backend.
//!
//! The user-facing firmware depends on `hisi-rf`; archive selection, ROM/NVS
//! symbols, and the relocatable ROM patch object remain transitive details of
//! this chip backend.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Cursor,
    path::{Path, PathBuf},
};

fn metadata_list(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_else(|_| panic!("ws63-radio-sys did not export {name}"))
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn write_combined_archive(archives: &[PathBuf], object: Option<&Path>, output: &Path) {
    use ar_archive_writer::{ArchiveKind, DEFAULT_OBJECT_READER, NewArchiveMember};
    use object::read::archive::ArchiveFile;

    let mut members = Vec::new();
    for (archive_index, path) in archives.iter().enumerate() {
        let data = fs::read(path)
            .unwrap_or_else(|error| panic!("read native archive {}: {error}", path.display()));
        let archive = ArchiveFile::parse(&*data)
            .unwrap_or_else(|error| panic!("parse native archive {}: {error}", path.display()));
        for (member_index, member) in archive.members().enumerate() {
            let member = member
                .unwrap_or_else(|error| panic!("read member from {}: {error}", path.display()));
            let bytes = member
                .data(&*data)
                .unwrap_or_else(|error| panic!("read member data from {}: {error}", path.display()))
                .to_vec();
            let original = String::from_utf8_lossy(member.name());
            members.push(NewArchiveMember::new(
                bytes,
                &DEFAULT_OBJECT_READER,
                format!("{archive_index:02}_{member_index:04}_{original}"),
            ));
        }
    }
    if let Some(object) = object {
        members.push(NewArchiveMember::new(
            fs::read(object).unwrap_or_else(|error| panic!("read {}: {error}", object.display())),
            &DEFAULT_OBJECT_READER,
            "ws63_rom_patches.o".to_owned(),
        ));
    }

    let mut output_bytes = Cursor::new(Vec::new());
    ar_archive_writer::write_archive_to_stream(
        &mut output_bytes,
        &members,
        ArchiveKind::Gnu,
        false,
        None,
    )
    .unwrap_or_else(|error| panic!("build combined WS63 radio archive: {error}"));
    fs::write(output, output_bytes.into_inner())
        .unwrap_or_else(|error| panic!("write {}: {error}", output.display()));
}

fn valid_symbol(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'$'))
}

fn parse_rom_symbols(source: &Path) -> BTreeMap<String, String> {
    let source = fs::read_to_string(source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
    let mut symbols = BTreeMap::new();
    for line in source.lines() {
        let Some((name, value)) = line
            .trim()
            .strip_suffix(';')
            .and_then(|line| line.split_once(" = "))
        else {
            continue;
        };
        assert!(valid_symbol(name), "invalid ROM symbol: {name:?}");
        assert!(
            value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid ROM address for {name}: {value:?}"
        );
        assert!(
            symbols.insert(name.to_owned(), value.to_owned()).is_none(),
            "duplicate ROM symbol: {name}"
        );
    }
    symbols
}

fn collect_callable_rom_symbols(
    archives: &[PathBuf],
    rom_symbols: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    use object::read::archive::ArchiveFile;
    use object::{Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget};

    const R_RISCV_JAL: u32 = 17;
    const R_RISCV_CALL: u32 = 18;
    const R_RISCV_CALL_PLT: u32 = 19;

    let mut callable = BTreeSet::new();
    for archive_path in archives {
        let archive_data = fs::read(archive_path).unwrap_or_else(|error| {
            panic!(
                "read native archive {} for ROM call census: {error}",
                archive_path.display()
            )
        });
        let archive = ArchiveFile::parse(&*archive_data).unwrap_or_else(|error| {
            panic!(
                "parse native archive {} for ROM call census: {error}",
                archive_path.display()
            )
        });
        for member in archive.members() {
            let member = member.unwrap_or_else(|error| {
                panic!(
                    "read archive member from {} for ROM call census: {error}",
                    archive_path.display()
                )
            });
            let data = member.data(&*archive_data).unwrap_or_else(|error| {
                panic!(
                    "read archive member {}({}): {error}",
                    archive_path.display(),
                    String::from_utf8_lossy(member.name())
                )
            });
            let Ok(object) = object::File::parse(data) else {
                continue;
            };
            for section in object.sections() {
                for (_, relocation) in section.relocations() {
                    let RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                        continue;
                    };
                    let Ok(symbol) = object.symbol_by_index(symbol_index) else {
                        continue;
                    };
                    let Ok(name) = symbol.name() else {
                        continue;
                    };
                    if !rom_symbols.contains_key(name) {
                        continue;
                    }
                    let RelocationFlags::Elf { r_type } = relocation.flags() else {
                        panic!(
                            "{}({}) references ROM symbol {name} with a non-ELF relocation",
                            archive_path.display(),
                            String::from_utf8_lossy(member.name())
                        );
                    };
                    if matches!(r_type, R_RISCV_JAL | R_RISCV_CALL | R_RISCV_CALL_PLT) {
                        callable.insert(name.to_owned());
                    }
                }
            }
        }
    }
    callable
}

fn add_declared_callable_rom_symbols(
    callable: &mut BTreeSet<String>,
    source: &Path,
    rom_symbols: &BTreeMap<String, String>,
) {
    let source_text = fs::read_to_string(source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
    for name in source_text.lines().map(str::trim) {
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        assert!(valid_symbol(name), "invalid declared ROM call: {name:?}");
        assert!(
            rom_symbols.contains_key(name),
            "declared ROM call is absent from the WS63 symbol table: {name}"
        );
        callable.insert(name.to_owned());
    }
}

fn append_rom_fallbacks(
    assembly: &mut String,
    rom_symbols: &BTreeMap<String, String>,
    callable: &BTreeSet<String>,
    strong_roots: &[String],
) {
    let owns_strong_definition = |name: &str| {
        matches!(name, "memcpy_s" | "memset_s" | "snprintf_s")
            || strong_roots.iter().any(|root| root == name)
    };

    for (name, address) in rom_symbols {
        if owns_strong_definition(name) {
            continue;
        }
        if callable.contains(name) {
            // The symbol must live at an ordinary section-relative address:
            // rust-lld may preserve R_RISCV_CALL_PLT through LTO and interprets
            // an absolute assembler alias as a displacement. A weak veneer is
            // transitive through the rlib and tail-jumps to the fixed ROM
            // address; an application-owned strong implementation still wins.
            assembly.push_str(".pushsection .text.hisi_ws63_rom_veneer.");
            assembly.push_str(name);
            assembly.push_str(",\"ax\",@progbits\n.balign 2\n.weak ");
            assembly.push_str(name);
            assembly.push_str("\n.type ");
            assembly.push_str(name);
            assembly.push_str(",@function\n");
            assembly.push_str(name);
            assembly.push_str(":\n  li t0, ");
            assembly.push_str(address);
            assembly.push_str("\n  jr t0\n.size ");
            assembly.push_str(name);
            assembly.push_str(", .-");
            assembly.push_str(name);
            assembly.push_str("\n.popsection\n");
        } else {
            // Address-only references, including ROM function pointers and
            // fixed ROM/RAM data, retain their exact machine address.
            assembly.push_str(".weak ");
            assembly.push_str(name);
            assembly.push_str("\n.set ");
            assembly.push_str(name);
            assembly.push_str(", ");
            assembly.push_str(address);
            assembly.push('\n');
        }
    }
}

fn callback_target(name: &str) -> &str {
    match name {
        "__ashldi3" => "__ws63_ashldi3",
        "__udivdi3" => "__ws63_udivdi3",
        "__umoddi3" => "__ws63_umoddi3",
        "memcmp" => "__ws63_rom_memcmp",
        "memcpy" => "__ws63_rom_memcpy",
        "memmove" => "__ws63_rom_memmove",
        "memset" => "__ws63_rom_memset",
        "strlen" => "__ws63_rom_strlen",
        name if matches!(
            name,
            "log_event_print0"
                | "log_event_print1"
                | "log_event_print2"
                | "log_event_print3"
                | "log_event_print4"
                | "log_event_wifi_print0"
                | "log_event_wifi_print1"
                | "log_event_wifi_print2"
                | "log_event_wifi_print3"
                | "log_event_wifi_print4"
                | "osal_irq_clear"
                | "osal_irq_disable"
                | "osal_irq_enable"
                | "osal_irq_free"
                | "osal_irq_lock"
                | "osal_irq_request"
                | "osal_irq_restore"
                | "osal_irq_set_priority"
                | "osal_kfree"
                | "osal_kmalloc"
                | "osal_kthread_lock"
                | "osal_kthread_unlock"
                | "osal_timer_destroy"
                | "osal_timer_init"
                | "osal_timer_mod"
                | "osal_timer_stop"
                | "osal_udelay"
                | "osal_wait_uninterruptible"
                | "osal_wait_wakeup"
                | "panic"
        ) =>
        {
            name
        }
        _ => "__ws63_missing_rom_callback",
    }
}

fn append_callback_fallbacks(assembly: &mut String, source: &Path) {
    let source = fs::read_to_string(source)
        .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
    for name in source.lines().map(str::trim) {
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        assert!(valid_symbol(name), "invalid ROM callback: {name:?}");
        let target = callback_target(name);
        assert!(
            valid_symbol(target),
            "invalid ROM callback target: {target:?}"
        );
        assembly.push_str(".pushsection .text.hisi_ws63_callback_fallback.");
        assembly.push_str(name);
        assembly.push_str(",\"ax\",@progbits\n.balign 2\n.weak __real_");
        assembly.push_str(name);
        assembly.push_str("\n.type __real_");
        assembly.push_str(name);
        assembly.push_str(",@function\n__real_");
        assembly.push_str(name);
        assembly.push_str(":\n  tail ");
        assembly.push_str(target);
        assembly.push_str("\n.size __real_");
        assembly.push_str(name);
        assembly.push_str(", .-__real_");
        assembly.push_str(name);
        assembly.push_str("\n.popsection\n");
    }
}

fn write_link_contract(
    output: &Path,
    callbacks: &Path,
    roots: &[String],
    rom_symbols: &BTreeMap<String, String>,
    callable_rom_symbols: &BTreeSet<String>,
) {
    let mut assembly = String::from(
        ".weak __nv_storage_start\n\
         .set __nv_storage_start, 0x005fc000\n\
         .weak __nv_storage_length\n\
         .set __nv_storage_length, 0x00004000\n",
    );
    append_rom_fallbacks(&mut assembly, rom_symbols, callable_rom_symbols, roots);
    append_callback_fallbacks(&mut assembly, callbacks);
    assembly.push_str(
        ".section .rodata.hisi_ws63_rf_roots,\"a\",@progbits\n\
         .balign 4\n\
         .globl __hisi_ws63_rf_link_roots\n\
         .type __hisi_ws63_rf_link_roots,@object\n\
         __hisi_ws63_rf_link_roots:\n",
    );
    for root in roots {
        assert!(valid_symbol(root), "invalid Wi-Fi root symbol: {root:?}");
        assembly.push_str(".word ");
        assembly.push_str(root);
        assembly.push('\n');
    }
    assembly.push_str(
        ".size __hisi_ws63_rf_link_roots, .-__hisi_ws63_rf_link_roots\n\
         .section .note.GNU-stack,\"\",@progbits\n",
    );
    fs::write(output, assembly)
        .unwrap_or_else(|error| panic!("write {}: {error}", output.display()));
}

fn main() {
    let target = env::var("TARGET").expect("TARGET");
    if !target.starts_with("riscv32") {
        return;
    }

    // Internal firmware examples use hisi-riscv-rt's neutral entry script.
    // Declaring the complete link contract here keeps `cargo build --example
    // ...` self-contained; the runtime dependency supplies the script and the
    // selected memory profile. Relaxation must remain disabled because the
    // guarded ROM callback veneers have a fixed, link-asserted address order.
    println!("cargo:rustc-link-arg=-Thisi-riscv-link.x");
    println!("cargo:rustc-link-arg=--no-relax");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let lib_dir = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_SYS_LIB_DIR")
            .expect("ws63-radio-sys did not export its archive directory"),
    );
    let rom = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_SYS_ROM_SYMBOLS")
            .expect("ws63-radio-sys did not export ROM symbols"),
    );
    let rust_rom_calls = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("link/ws63-rom-call-symbols.txt");
    let callbacks = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_SYS_ROM_CALLBACKS")
            .expect("ws63-radio-sys did not export ROM callbacks"),
    );
    let patch_object = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_SYS_ROM_PATCH_OBJECT")
            .expect("ws63-radio-sys did not export its ROM patch object"),
    );
    let ble_init = env::var_os("CARGO_FEATURE_BLE_INIT").is_some();
    let mut combined_inputs = Vec::new();
    if ble_init {
        combined_inputs.extend(
            metadata_list("DEP_WS63_RADIO_SYS_BLE_ARCHIVES")
                .into_iter()
                .map(PathBuf::from),
        );
        combined_inputs.extend(
            metadata_list("DEP_WS63_RADIO_SYS_BLE_CONTROLLER_ARCHIVES")
                .into_iter()
                .map(PathBuf::from),
        );
    } else {
        for archive in metadata_list("DEP_WS63_RADIO_SYS_WIFI_ARCHIVES") {
            let (name, mode) = archive
                .split_once(':')
                .expect("invalid ws63-radio-sys archive metadata");
            if mode != "whole" {
                combined_inputs.push(lib_dir.join(format!("lib{name}.a")));
            }
        }
    }
    if let Some(archive) = env::var_os("DEP_WS63_RADIO_SYS_NATIVE_SUPPLICANT_ARCHIVE") {
        combined_inputs.push(PathBuf::from(archive));
    }
    if let Some(archive) = env::var_os("DEP_WS63_RADIO_SYS_NATIVE_AUTHENTICATOR_ARCHIVE") {
        combined_inputs.push(PathBuf::from(archive));
    }
    let combined_archive = out_dir.join("libws63_radio_closure.a");
    write_combined_archive(
        &combined_inputs,
        (!ble_init).then_some(patch_object.as_path()),
        &combined_archive,
    );

    let mut roots = if ble_init {
        metadata_list("DEP_WS63_RADIO_SYS_BLE_INIT_ROOT_SYMBOLS")
    } else {
        metadata_list("DEP_WS63_RADIO_SYS_WIFI_ROOT_SYMBOLS")
    };
    if !ble_init {
        roots.extend(metadata_list(
            "DEP_WS63_RADIO_SYS_ROM_CALLBACK_ROOT_SYMBOLS",
        ));
        roots.extend(metadata_list("DEP_WS63_RADIO_SYS_RUNTIME_COMPAT_SYMBOLS"));
    }
    if env::var_os("DEP_WS63_RADIO_SYS_NATIVE_SUPPLICANT_ARCHIVE").is_some() {
        roots.extend(metadata_list(
            "DEP_WS63_RADIO_SYS_NATIVE_SUPPLICANT_ROOT_SYMBOLS",
        ));
    }
    if env::var_os("DEP_WS63_RADIO_SYS_NATIVE_AUTHENTICATOR_ARCHIVE").is_some() {
        roots.extend(metadata_list(
            "DEP_WS63_RADIO_SYS_NATIVE_AUTHENTICATOR_ROOT_SYMBOLS",
        ));
    }
    if !ble_init {
        roots.push("__hisi_ws63_rom_patch_table".to_owned());
    }
    let rom_symbols = parse_rom_symbols(&rom);
    let mut census_archives = combined_inputs;
    if !ble_init {
        for archive in metadata_list("DEP_WS63_RADIO_SYS_WIFI_ARCHIVES") {
            let (name, mode) = archive
                .split_once(':')
                .expect("invalid ws63-radio-sys archive metadata");
            if mode == "whole" {
                census_archives.push(lib_dir.join(format!("lib{name}.a")));
            }
        }
    }
    if !ble_init {
        census_archives.push(lib_dir.join("librom_callback.a"));
    }
    let mut callable_rom_symbols = collect_callable_rom_symbols(&census_archives, &rom_symbols);
    add_declared_callable_rom_symbols(&mut callable_rom_symbols, &rust_rom_calls, &rom_symbols);
    let contract = out_dir.join("ws63-radio-link-contract.S");
    write_link_contract(
        &contract,
        &callbacks,
        &roots,
        &rom_symbols,
        &callable_rom_symbols,
    );

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    if env::var_os("CARGO_FEATURE_RF_ELOOP_DIAG").is_some() {
        for symbol in [
            "hmac_sta_wait_auth_seq2_rx_etc",
            "hmac_sta_auth_timeout_etc",
            "hmac_rx_mgmt_event_adapt",
            "hmac_tx_mgmt_send_event_etc",
            "dmac_rx_prepare_data_patch",
            "dmac_tx_complete_event_handler",
        ] {
            println!("cargo:rustc-link-arg=--wrap={symbol}");
        }
    } else if env::var_os("CARGO_FEATURE_DATA_PATH_DIAG").is_some() {
        for symbol in [
            "dmac_rx_prepare_data_patch",
            "dmac_tx_complete_event_handler",
            "hmac_rx_data_event_adapt",
            "hmac_rx_process_data_msg",
            "hmac_rx_data",
            "hmac_tx_lan_to_wlan_no_tcp_opt_etc",
            "hmac_tx_process_data",
            "hmac_tx_data_send",
            "frw_hmac_send_data",
            "dmac_tx_process_data_event",
        ] {
            println!("cargo:rustc-link-arg=--wrap={symbol}");
        }
    }
    println!("cargo:rustc-link-lib=static=ws63_radio_closure");
    if !ble_init {
        for archive in metadata_list("DEP_WS63_RADIO_SYS_WIFI_ARCHIVES") {
            let (name, mode) = archive
                .split_once(':')
                .expect("invalid ws63-radio-sys archive metadata");
            if mode == "whole" {
                println!("cargo:rustc-link-lib=static:+whole-archive={name}");
            }
        }
    }
    if !ble_init {
        println!("cargo:rustc-link-lib=static:+whole-archive=rom_callback");
    }

    println!("cargo:rerun-if-changed={}", rom.display());
    println!("cargo:rerun-if-changed={}", rust_rom_calls.display());
    println!("cargo:rerun-if-changed={}", callbacks.display());
    println!("cargo:rerun-if-changed={}", patch_object.display());
    println!("cargo:rerun-if-changed={}", lib_dir.display());
}
