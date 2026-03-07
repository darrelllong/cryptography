#[cfg(test)]
mod tests {
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
}
