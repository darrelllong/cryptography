//! The private-key `CHOICE` of the module-lattice algorithms in X.509:
//! RFC 9935 §6 for ML-KEM and RFC 9881 §6 for ML-DSA.
//!
//! Both RFCs define, for every parameter set, the same structure, differing
//! only in its sizes (their ASN.1 modules use implicit tags):
//!
//! ```text
//! PrivateKey ::= CHOICE {
//!   seed        [0] OCTET STRING (SIZE (seed length)),
//!   expandedKey     OCTET STRING (SIZE (expanded key length)),
//!   both            SEQUENCE {
//!                     seed        OCTET STRING (SIZE (seed length)),
//!                     expandedKey OCTET STRING (SIZE (expanded key length)) } }
//! ```
//!
//! It is the contents of a `OneAsymmetricKey`'s `privateKey` OCTET STRING.
//! Both RFCs direct a parser to tell the alternatives apart by their tag —
//! `[0]` primitive (0x80), OCTET STRING (0x04), SEQUENCE (0x30) — and not by
//! length, which [`PrivateKeyChoice::from_der`] does. Whether the alternatives
//! agree (the seed consistency check of RFC 9935 §8 and RFC 9881 §8.2) is the
//! algorithm module's to check, since only it can run key generation.

use crate::public_key::io::{
    context_tag, der_implicit_primitive, der_octet_string, der_sequence_of, tag, DerReader,
};
use crate::public_key::pkix::{AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey};
use crate::zeroize_slice;

/// The identifier octet of `seed`: context-specific `[0]`, primitive, since
/// the implicit tag replaces the OCTET STRING's own (X.690 §8.1.2, §8.14.4).
const SEED_TAG: u8 = context_tag(0, false);

/// The identifier octet of `expandedKey`: the universal OCTET STRING tag,
/// primitive (X.690 §8.1.2).
const EXPANDED_KEY_TAG: u8 = tag::OCTET_STRING;

/// The identifier octet of `both`: the universal SEQUENCE tag, constructed
/// (X.690 §8.1.2).
const BOTH_TAG: u8 = tag::SEQUENCE;

/// One alternative of the private-key `CHOICE`, as views of the key octets.
#[derive(Clone, Copy)]
pub(crate) enum PrivateKeyChoice<'a> {
    /// `seed`: the key-generation seed alone.
    Seed(&'a [u8]),
    /// `expandedKey`: the FIPS private-key encoding alone.
    ExpandedKey(&'a [u8]),
    /// `both`: the seed and the expanded key it generates.
    Both {
        /// The key-generation seed.
        seed: &'a [u8],
        /// The FIPS private-key encoding.
        expanded_key: &'a [u8],
    },
}

impl<'a> PrivateKeyChoice<'a> {
    /// Decode all of `der` as one alternative whose seed is `seed_len` octets
    /// and whose expanded key is `expanded_key_len` octets: the sizes of the
    /// parameter set the key's algorithm identifier names. The encoding must
    /// be strict DER even when the `OneAsymmetricKey` around it arrived in
    /// BER, since RFC 9935 §6 and RFC 9881 §6 fill the `privateKey` with
    /// "DER-encoded CHOICE structures".
    pub(crate) fn from_der(
        der: &'a [u8],
        seed_len: usize,
        expanded_key_len: usize,
    ) -> Option<Self> {
        let mut reader = DerReader::new(der);
        let choice = match reader.peek_tag()? {
            SEED_TAG => Self::Seed(reader.read_implicit_primitive(0)?),
            EXPANDED_KEY_TAG => Self::ExpandedKey(reader.read_octet_string()?),
            BOTH_TAG => {
                let mut fields = DerReader::new(reader.read_sequence()?);
                let seed = fields.read_octet_string()?;
                let expanded_key = fields.read_octet_string()?;
                if !fields.is_finished() {
                    return None;
                }
                Self::Both { seed, expanded_key }
            }
            _ => return None,
        };
        let sizes_match = match choice {
            Self::Seed(seed) => seed.len() == seed_len,
            Self::ExpandedKey(expanded_key) => expanded_key.len() == expanded_key_len,
            Self::Both { seed, expanded_key } => {
                seed.len() == seed_len && expanded_key.len() == expanded_key_len
            }
        };
        (reader.is_finished() && sizes_match).then_some(choice)
    }

    /// The DER encoding. It holds the private key, so the caller wipes it.
    pub(crate) fn to_der(self) -> Vec<u8> {
        match self {
            Self::Seed(seed) => der_implicit_primitive(0, seed),
            Self::ExpandedKey(expanded_key) => der_octet_string(expanded_key),
            // Sized exactly, each part wiped once copied.
            Self::Both { seed, expanded_key } => {
                der_sequence_of(vec![der_octet_string(seed), der_octet_string(expanded_key)])
            }
        }
    }
}

/// The DER `OneAsymmetricKey` of `private_key` under `algorithm`: version 1,
/// the parameters absent (RFC 9935 §3, RFC 9881 §2), and no public key. The
/// intermediate encoding is wiped; only the returned one holds the key.
pub(crate) fn private_key_to_pkcs8(
    algorithm: &ObjectIdentifier,
    private_key: PrivateKeyChoice<'_>,
) -> Vec<u8> {
    let mut contents = private_key.to_der();
    let der =
        OneAsymmetricKey::new(AlgorithmIdentifier::new(algorithm, None), &contents, None).to_der();
    zeroize_slice(contents.as_mut_slice());
    der
}

#[cfg(test)]
mod tests {
    use super::PrivateKeyChoice;

    const SEED: [u8; 4] = [0x11, 0x12, 0x13, 0x14];
    const EXPANDED: [u8; 8] = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

    fn decode(der: &[u8]) -> Option<PrivateKeyChoice<'_>> {
        PrivateKeyChoice::from_der(der, SEED.len(), EXPANDED.len())
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        [&[tag, u8::try_from(body.len()).expect("short")][..], body].concat()
    }

    #[test]
    fn each_alternative_is_chosen_by_its_tag_and_round_trips() {
        let seed = PrivateKeyChoice::Seed(&SEED).to_der();
        assert_eq!(seed, tlv(0x80, &SEED));
        assert!(matches!(decode(&seed), Some(PrivateKeyChoice::Seed(s)) if s == SEED));

        let expanded = PrivateKeyChoice::ExpandedKey(&EXPANDED).to_der();
        assert_eq!(expanded, tlv(0x04, &EXPANDED));
        assert!(
            matches!(decode(&expanded), Some(PrivateKeyChoice::ExpandedKey(e)) if e == EXPANDED)
        );

        let both = PrivateKeyChoice::Both {
            seed: &SEED,
            expanded_key: &EXPANDED,
        }
        .to_der();
        assert_eq!(
            both,
            tlv(0x30, &[tlv(0x04, &SEED), tlv(0x04, &EXPANDED)].concat())
        );
        assert!(matches!(
            decode(&both),
            Some(PrivateKeyChoice::Both { seed, expanded_key })
                if seed == SEED && expanded_key == EXPANDED
        ));
    }

    #[test]
    fn sizes_order_trailing_data_and_other_tags_are_refused() {
        let seed = tlv(0x04, &SEED);
        let expanded = tlv(0x04, &EXPANDED);
        let rejected = [
            // Each alternative with a size its parameter set does not have.
            tlv(0x80, &SEED[..3]),
            tlv(0x04, &[&EXPANDED[..], &[0]].concat()),
            tlv(0x30, &[tlv(0x04, &SEED[..3]), expanded.clone()].concat()),
            tlv(0x30, &[seed.clone(), tlv(0x04, &EXPANDED[..7])].concat()),
            // `both` with its fields swapped, with the seed under [0], with a
            // third field, or with one field.
            tlv(0x30, &[expanded.clone(), seed.clone()].concat()),
            tlv(0x30, &[tlv(0x80, &SEED), expanded.clone()].concat()),
            tlv(
                0x30,
                &[seed.clone(), expanded.clone(), vec![0x05, 0x00]].concat(),
            ),
            tlv(0x30, &seed),
            // A seed under a constructed [0], under [1], or bare, and an
            // expanded key as a BIT STRING.
            tlv(0xa0, &seed),
            tlv(0x81, &SEED),
            SEED.to_vec(),
            tlv(0x03, &[&[0][..], &EXPANDED].concat()),
            // Bytes after the alternative, a length in more octets than it
            // needs, and nothing at all.
            [tlv(0x80, &SEED), vec![0x00]].concat(),
            [&[0x80, 0x81, 0x04][..], &SEED].concat(),
            Vec::new(),
        ];
        for der in rejected {
            assert!(decode(&der).is_none(), "{der:02x?}");
        }
    }

    /// RFC 9935 §6 and RFC 9881 §6 fill the `privateKey` with "DER-encoded
    /// CHOICE structures". RFC 5958 §2 lets the `OneAsymmetricKey` around them
    /// be BER, and that does not relax the CHOICE: a BER container around a
    /// DER CHOICE reads, and a BER CHOICE is refused whatever surrounds it.
    #[test]
    fn the_choice_stays_der_inside_a_ber_container() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::{
            pkcs8_ber, AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey,
        };
        let ml_kem_512 = ObjectIdentifier::from_arcs(&[2, 16, 840, 1, 101, 3, 4, 4, 1]);
        let package = |choice: &[u8]| {
            OneAsymmetricKey::new(AlgorithmIdentifier::new(&ml_kem_512, None), choice, None)
                .to_der()
        };
        let choice_reads = |ber: &[u8]| {
            pkcs8_ber(ber, |der| {
                Some(decode(OneAsymmetricKey::from_der(der)?.private_key()).is_some())
            })
        };
        let seed = PrivateKeyChoice::Seed(&SEED).to_der();
        let both = PrivateKeyChoice::Both {
            seed: &SEED,
            expanded_key: &EXPANDED,
        }
        .to_der();
        for style in STYLES {
            assert_eq!(
                choice_reads(&reencode(&package(&seed), style)),
                Some(true),
                "{style:?}"
            );
            assert_eq!(
                choice_reads(&reencode(&package(&both), style)),
                Some(true),
                "{style:?}"
            );
            let both_ber = reencode(&both, style);
            assert_eq!(choice_reads(&package(&both_ber)), Some(false), "{style:?}");
            assert_eq!(
                choice_reads(&reencode(&package(&both_ber), style)),
                Some(false),
                "{style:?}"
            );
        }
    }
}
