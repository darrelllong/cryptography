//! Repository policy scrub tests.
//!
//! This file is a lightweight "policy CI" layer implemented as unit tests:
//! it scans selected source files with `include_str!` and fails when banned API
//! names, missing safety markers, or surface-contract regressions reappear.
//!
//! The goal is to catch architectural drift early (naming regressions, Ct policy
//! regressions, unsafe root exports) without introducing a separate lint tool.
//! Every check here reads text: it establishes what the sources say, not what
//! the compiled code does. The behavioural counterparts live in the ordinary
//! tests and in `tests/wipe_behaviour.rs`.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    // Shared helper for negative text assertions used by policy checks below.
    fn assert_none(label: &str, haystack: &str, forbidden: &[&str]) {
        for needle in forbidden {
            assert!(
                !haystack.contains(needle),
                "{label} contains forbidden pattern: {needle}"
            );
        }
    }

    #[test]
    fn legacy_pk_api_names_do_not_reappear() {
        let files = [
            ("public_key/mod.rs", include_str!("public_key/mod.rs")),
            ("public_key/dsa.rs", include_str!("public_key/dsa.rs")),
            ("public_key/ecdsa.rs", include_str!("public_key/ecdsa.rs")),
            (
                "public_key/elgamal.rs",
                include_str!("public_key/elgamal.rs"),
            ),
            (
                "public_key/ec_elgamal.rs",
                include_str!("public_key/ec_elgamal.rs"),
            ),
            ("public_key/ecdh.rs", include_str!("public_key/ecdh.rs")),
            (
                "public_key/edwards_dh.rs",
                include_str!("public_key/edwards_dh.rs"),
            ),
        ];
        let forbidden = [
            "sign_with_k(",
            "verify_raw(",
            "to_binary(",
            "from_binary(",
            "to_bytes(",
            "from_bytes(",
            "encrypt_with_ephemeral(",
            "encrypt_point_with_k(",
        ];
        for (label, content) in files {
            assert_none(label, content, &forbidden);
        }
    }

    #[test]
    fn explicit_agreement_names_stay_in_place() {
        let dh = include_str!("public_key/dh.rs");
        let ecdh = include_str!("public_key/ecdh.rs");
        let edwards = include_str!("public_key/edwards_dh.rs");
        assert!(dh.contains("agree_element("));
        assert!(ecdh.contains("agree_x_coordinate("));
        assert!(edwards.contains("agree_compressed_point("));
    }

    /// A spelling gate, nothing more: two idioms that turn a comparison into
    /// a branch-and-widen (`u8::from(a == b)`, and multiplying by it) may not
    /// appear in `ct.rs`. It proves nothing about the emitted code; the
    /// documentation of `constant_time_eq_mask` records what does.
    #[test]
    fn ct_rs_does_not_spell_comparisons_as_bool_casts() {
        let ct = include_str!("ct.rs");
        assert_none("ct.rs", ct, &["u8::from(a == b)", "wrapping_mul(u8::from("]);
        assert!(ct.contains("fn constant_time_eq_mask"));
    }

    #[test]
    fn removed_reference_generators_do_not_reappear() {
        let cprng_mod = include_str!("cprng/mod.rs");
        assert_none(
            "cprng/mod.rs",
            cprng_mod,
            &["blum_blum_shub", "blum_micali"],
        );
    }

    /// The crate root re-exports no public-key type. `vt` labels the
    /// variable-time surface, it does not gate it: `public_key` reaches the
    /// same types by their module paths. This checks only that the flat
    /// re-exports stay under `vt`, so the label is on every short path.
    #[test]
    fn public_key_types_have_no_root_level_reexport() {
        let lib = include_str!("lib.rs");
        assert!(lib.contains("pub mod vt"));
        assert_none("lib.rs", lib, &["pub use public_key::"]);
    }

    #[test]
    fn stream_and_aead_traits_remain_in_root_surface() {
        let lib = include_str!("lib.rs");
        assert!(lib.contains("pub trait StreamCipher"));
        assert!(lib.contains("pub trait Aead"));
        assert!(lib.contains("pub use modes::{"));
        assert!(lib.contains("ChaCha20Poly1305"));
    }

    #[test]
    fn hkdf_surface_remains_exported() {
        let hash_mod = include_str!("hash/mod.rs");
        let lib = include_str!("lib.rs");
        assert!(hash_mod.contains("pub mod hkdf;"));
        assert!(lib.contains("pub use hash::hkdf::Hkdf;"));
    }

    #[test]
    fn unsafe_code_stays_confined_to_audited_sites() {
        // Policy gate:
        // - the crate root must deny unsafe_code;
        // - ct.rs may contain exactly one unsafe block (zeroize_slice), active
        //   in every build;
        // - sha3.rs unsafe is allowed only behind the opt-in `arm-sha3`
        //   feature, so a default build is entirely safe Rust.
        let lib = include_str!("lib.rs");
        assert!(
            lib.contains("#![deny(unsafe_code)]"),
            "lib.rs must enforce #![deny(unsafe_code)]"
        );

        let ct = include_str!("ct.rs");
        assert_eq!(
            ct.matches("unsafe {").count(),
            1,
            "ct.rs must contain exactly one unsafe block (zeroize_slice)"
        );
        assert!(!ct.contains("unsafe fn"), "ct.rs must not add unsafe fns");

        let sha3 = include_str!("hash/sha3.rs");
        let gate = "#[cfg(all(target_arch = \"aarch64\", feature = \"arm-sha3\"))]";
        assert!(
            sha3.matches(gate).count() >= 2,
            "sha3.rs hardware path must be gated on the arm-sha3 feature (dispatch + impl)"
        );

        // - and no other Rust source in the repository may hold unsafe code
        //   or relax the lint. `fast/` is the exception: its two crates are
        //   the platform-intrinsics experiments (AES-NI, ARMv8 AES, SHA and
        //   SHA-3 instructions), unsafe by nature and outside the published
        //   package. `tests/wipe_behaviour.rs` is the other: it observes
        //   drop-time wiping by reading a dropped value's storage back, which
        //   only raw pointers can express.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let audited = [
            root.join("src").join("ct.rs"),
            root.join("src").join("hash").join("sha3.rs"),
            root.join("src").join("scrub.rs"),
            root.join("tests").join("wipe_behaviour.rs"),
            // Drop-observation tests on private types (`SubkeyTable`,
            // `TagState`, `NonceKeys`): `#[cfg(test)]` modules that read a
            // dropped value's storage back, the same instrument as
            // tests/wipe_behaviour.rs, kept in-tree because the types they
            // observe are private.
            root.join("src").join("modes").join("ghash.rs"),
            root.join("src").join("modes").join("poly1305.rs"),
            root.join("src").join("modes").join("gcm_siv.rs"),
            root.join("src").join("modes").join("ocb.rs"),
            root.join("tests").join("wipe_modes.rs"),
        ];
        let markers = [
            concat!("unsafe", " {"),
            concat!("unsafe", " fn"),
            concat!("unsafe", " impl"),
            concat!("unsafe", " trait"),
            concat!("unsafe", " extern"),
            concat!("allow(unsafe", "_code)"),
            concat!("expect(unsafe", "_code)"),
        ];
        let mut offenders = Vec::new();
        for path in repository_rust_sources()
            .iter()
            .filter(|p| !audited.contains(p))
        {
            let text = std::fs::read_to_string(path).expect("source is UTF-8");
            for marker in markers {
                if text.contains(marker) {
                    offenders.push(format!("{} contains `{marker}`", path.display()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "unsafe code outside the audited sites: {offenders:?}"
        );
    }

    /// Every Rust source file the unsafe gate covers: `src/`, `tests/`,
    /// `fuzz/` and `benchmarks/`, without their build directories. `fast/`
    /// is left out as the intrinsics crates (see the gate).
    fn repository_rust_sources() -> Vec<std::path::PathBuf> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut out = Vec::new();
        for dir in ["src", "tests", "fuzz", "benchmarks"] {
            let dir = root.join(dir);
            if dir.is_dir() {
                visit_rust_files(&dir, &mut out);
            }
        }
        out
    }

    fn visit_rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("directory is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                visit_rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Every Rust source file under `src/`, for policy gates that must hold
    /// crate-wide rather than for a hand-maintained list of files.
    fn rust_sources() -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        visit_rust_files(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    /// The keys and string or array values of one TOML inline table,
    /// `{ key = value, ... }`, as written in `Cargo.toml`.
    fn parse_inline_table(text: &str) -> std::collections::BTreeMap<String, String> {
        let inner = text
            .trim()
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
            .unwrap_or_else(|| panic!("not an inline table: {text}"));
        let mut entries = std::collections::BTreeMap::new();
        let mut depth = 0usize;
        let mut in_string = false;
        let mut field = String::new();
        let mut fields = Vec::new();
        for ch in inner.chars() {
            match ch {
                '"' => in_string = !in_string,
                '[' if !in_string => depth += 1,
                ']' if !in_string => depth -= 1,
                ',' if !in_string && depth == 0 => {
                    fields.push(std::mem::take(&mut field));
                    continue;
                }
                _ => {}
            }
            field.push(ch);
        }
        fields.push(field);
        for field in fields.iter().map(|f| f.trim()).filter(|f| !f.is_empty()) {
            let (key, value) = field
                .split_once('=')
                .unwrap_or_else(|| panic!("not a key = value pair: {field}"));
            entries.insert(key.trim().to_owned(), value.trim().to_owned());
        }
        entries
    }

    /// The strings of a TOML array of strings, `["a", "b"]`.
    fn parse_string_array(text: &str) -> Vec<String> {
        text.trim()
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or_else(|| panic!("not an array: {text}"))
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| {
                item.strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or_else(|| panic!("not a string: {item}"))
                    .to_owned()
            })
            .collect()
    }

    /// The keys defined in one `[section]` of a TOML file.
    fn section_keys(toml: &str, section: &str) -> Vec<String> {
        let header = format!("[{section}]");
        toml.lines()
            .map(str::trim)
            .skip_while(|line| *line != header)
            .skip(1)
            .take_while(|line| !line.starts_with('['))
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim().to_owned()))
            .collect()
    }

    /// Manifest gate: cryptographic code wipes its secrets in every build.
    /// rump keeps its limb wiping opt-in because it is general-purpose, so
    /// this crate's `rust-mp` dependency entry must enable rump's `wipe`
    /// feature, no cargo feature of this crate may control wiping, and no
    /// source may gate on one. This reads the manifest and the sources; that
    /// a dropped value's bytes are in fact zero is what
    /// `tests/wipe_behaviour.rs` observes.
    #[test]
    fn manifest_enables_rump_wipe_and_declares_no_wipe_feature() {
        let cargo = include_str!("../Cargo.toml");
        let dependency = cargo
            .lines()
            .find_map(|line| line.strip_prefix("rust-mp = "))
            .expect("Cargo.toml declares the rust-mp dependency");
        let entry = parse_inline_table(dependency);
        assert_eq!(
            entry.get("path").map(String::as_str),
            Some("\"../rump\""),
            "rust-mp is the sibling checkout: {dependency}"
        );
        let features = entry
            .get("features")
            .map(|list| parse_string_array(list))
            .unwrap_or_default();
        assert!(
            features.iter().any(|feature| feature == "wipe"),
            "the rust-mp dependency must enable rump's wipe feature: {dependency}"
        );
        assert!(
            !section_keys(cargo, "features")
                .iter()
                .any(|key| key == "wipe"),
            "no cargo feature may control wiping"
        );

        let needle = concat!("feature = ", "\"wipe\"");
        let hits: Vec<String> = rust_sources()
            .into_iter()
            .filter(|path| {
                std::fs::read_to_string(path)
                    .expect("source is UTF-8")
                    .contains(needle)
            })
            .map(|path| path.display().to_string())
            .collect();
        assert!(
            hits.is_empty(),
            "wiping must not be gated on a wipe feature: {hits:?}"
        );
    }

    #[test]
    fn cipher_modules_are_classified_for_ct_policy() {
        // Policy gate:
        // - each public cipher module must be explicitly categorized as either
        //   requiring a separate Ct variant, or exempt because the primitive
        //   is already table-free and the fast path is constant-time by design.
        // This makes "any new cipher needs a Ct path" mechanically enforced:
        // adding a new module without classifying it fails CI immediately.
        let ciphers_mod = include_str!("ciphers/mod.rs");
        let lib = include_str!("lib.rs");

        let mut public_modules = BTreeSet::<String>::new();
        for line in ciphers_mod.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("pub mod ") {
                let module = rest.trim_end_matches(';').trim().to_string();
                public_modules.insert(module);
            }
        }

        let required_ct_modules = BTreeSet::from([
            "aes",
            "camellia",
            "cast128",
            "des",
            "grasshopper",
            "magma",
            "present",
            "seed",
            "serpent",
            "sm4",
            "snow3g",
            "twofish",
            "zuc",
        ]);
        let ct_exempt_modules = BTreeSet::from(["chacha20", "rabbit", "salsa20", "simon", "speck"]);

        let mut classified = BTreeSet::new();
        classified.extend(required_ct_modules.iter().copied());
        classified.extend(ct_exempt_modules.iter().copied());

        for module in &public_modules {
            assert!(
                classified.contains(module.as_str()),
                "new cipher module `{module}` is not classified for Ct policy",
            );
        }

        for module in &required_ct_modules {
            assert!(
                public_modules.contains(*module),
                "Ct-required module `{module}` missing from ciphers/mod.rs",
            );
        }

        // Root export checks for Ct-required modules.
        for ct_export in [
            "Aes128Ct",
            "Camellia128Ct",
            "Cast128Ct",
            "DesCt",
            "GrasshopperCt",
            "MagmaCt",
            "Present128Ct",
            "Present80Ct",
            "SeedCt",
            "Serpent128Ct",
            "Sm4Ct",
            "Snow3gCt",
            "Twofish128Ct",
            "Zuc128Ct",
        ] {
            assert!(
                lib.contains(ct_export),
                "missing required Ct export `{ct_export}` in lib.rs"
            );
        }

        // Source-level ct implementation checks.
        //
        // Verifies that each Ct-required module's source contains at least one
        // ct S-box indicator — a function or primitive specific to the constant-
        // time path.  This is stronger than the export-name check above: it
        // would catch a module that exports a `*Ct` name but contains no ct
        // S-box implementation at all.
        //
        // Limitation: this does not prove that the Ct struct *dispatches* to
        // the ct path — it only proves a ct implementation exists in the file.
        // The per-cipher `ct_sboxes_match_tables` and `fast_and_ct_match` tests
        // provide the behavioral contract; this check catches gross structural
        // omissions (e.g. a new cipher added with an empty Ct stub).
        //
        // The indicators are intentionally cipher-specific because ct strategies
        // differ: generic ANF (`eval_byte_sbox`), generic table-scan
        // (`ct_lookup_u32`), custom ANF (`sbox_ct`, `pi_ct`), or synthesized
        // boolean circuit (`sbox_bool`).
        let ct_indicators: &[&str] = &[
            "eval_byte_sbox", // generic 8-bit ANF (Grasshopper, Camellia, SEED, SM4, SNOW 3G, ZUC)
            "eval_nibble_sbox", // generic 4-bit ANF (PRESENT)
            "apply_sbox_words", // word-parallel bitsliced ANF (Serpent)
            "ct_lookup_u32",  // full-table-scan 256-entry (CAST-128)
            "ct_lookup_u8_16", // full-table-scan 16-entry (Twofish)
            "sbox_bool",      // synthesized boolean circuit (AES)
            "sbox_ct",        // custom ANF per-S-box (DES)
            "nibble_monomials", // custom ANF per-S-box (Magma)
        ];

        let ct_module_sources: &[(&str, &str)] = &[
            ("aes", include_str!("ciphers/aes.rs")),
            ("camellia", include_str!("ciphers/camellia.rs")),
            ("cast128", include_str!("ciphers/cast128.rs")),
            ("des", include_str!("ciphers/des.rs")),
            ("grasshopper", include_str!("ciphers/grasshopper.rs")),
            ("magma", include_str!("ciphers/magma.rs")),
            ("present", include_str!("ciphers/present.rs")),
            ("seed", include_str!("ciphers/seed.rs")),
            ("serpent", include_str!("ciphers/serpent.rs")),
            ("sm4", include_str!("ciphers/sm4.rs")),
            ("snow3g", include_str!("ciphers/snow3g.rs")),
            ("twofish", include_str!("ciphers/twofish.rs")),
            ("zuc", include_str!("ciphers/zuc.rs")),
        ];

        for (name, src) in ct_module_sources {
            let has_ct_impl = ct_indicators.iter().any(|marker| src.contains(marker));
            assert!(
                has_ct_impl,
                "Ct-required module `{name}` contains no ct S-box indicator \
                 ({}) — Ct struct may be an empty stub",
                ct_indicators.join(", ")
            );
        }
    }
}
