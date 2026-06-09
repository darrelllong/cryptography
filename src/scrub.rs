//! Repository policy scrub tests.
//!
//! This file is a lightweight "policy CI" layer implemented as unit tests:
//! it scans selected source files with `include_str!` and fails when banned API
//! names, missing safety markers, or surface-contract regressions reappear.
//!
//! The goal is to catch architectural drift early (naming regressions, Ct policy
//! regressions, unsafe root exports) without introducing a separate lint tool.

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

    #[test]
    fn ct_mask_helper_stays_arithmetic_only() {
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

    #[test]
    fn root_exports_do_not_expose_variable_time_pk_directly() {
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
        // - ct.rs may contain exactly one unsafe block (volatile zeroization);
        // - sha3.rs unsafe is allowed only behind the opt-in `arm-sha3`
        //   feature, so a default build is pure safe Rust besides ct.rs.
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
            "eval_byte_sbox",   // generic 8-bit ANF (Grasshopper, Camellia, SEED, SM4, SNOW 3G, ZUC)
            "eval_nibble_sbox", // generic 4-bit ANF (PRESENT, Serpent)
            "ct_lookup_u32",    // full-table-scan 256-entry (CAST-128)
            "ct_lookup_u8_16",  // full-table-scan 16-entry (Twofish)
            "sbox_bool",        // synthesized boolean circuit (AES)
            "sbox_ct",          // custom ANF per-S-box (DES)
            "pi_ct",            // custom ANF per-S-box (Magma)
        ];

        let ct_module_sources: &[(&str, &str)] = &[
            ("aes",        include_str!("ciphers/aes.rs")),
            ("camellia",   include_str!("ciphers/camellia.rs")),
            ("cast128",    include_str!("ciphers/cast128.rs")),
            ("des",        include_str!("ciphers/des.rs")),
            ("grasshopper",include_str!("ciphers/grasshopper.rs")),
            ("magma",      include_str!("ciphers/magma.rs")),
            ("present",    include_str!("ciphers/present.rs")),
            ("seed",       include_str!("ciphers/seed.rs")),
            ("serpent",    include_str!("ciphers/serpent.rs")),
            ("sm4",        include_str!("ciphers/sm4.rs")),
            ("snow3g",     include_str!("ciphers/snow3g.rs")),
            ("twofish",    include_str!("ciphers/twofish.rs")),
            ("zuc",        include_str!("ciphers/zuc.rs")),
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
