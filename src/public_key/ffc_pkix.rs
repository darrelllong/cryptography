//! Standard encodings of finite-field keys: DSA and Diffie-Hellman keys and
//! their domain parameters, under the identifiers of RFC 3279.
//!
//! ## DSA
//!
//! - Public keys are `SubjectPublicKeyInfo`s with `id-dsa`
//!   (1.2.840.10040.4.1), whose parameters are `Dss-Parms ::= SEQUENCE { p,
//!   q, g }` and whose `subjectPublicKey` is the DER `DSAPublicKey ::=
//!   INTEGER`, `y` (RFC 3279 §2.3.2).
//! - Private keys are RFC 5958 `OneAsymmetricKey`s under the same identifier
//!   and parameters. RFC 5958 §2 gives their contents: for `privateKey`, "a
//!   DSA key is an INTEGER", `x`, and the same for a version 2 `publicKey`,
//!   `y`. RFC 5912's module leaves the DSA private-key format out ("Private
//!   key format not in this module"), so RFC 5958 is the published definition
//!   these encoders follow.
//! - `DsaParams` encode as `Dss-Parms`, which has no field for a FIPS 186-4
//!   seed record, so none is written.
//!
//! ## Diffie-Hellman
//!
//! - Public keys are `SubjectPublicKeyInfo`s with `dhpublicnumber`
//!   (1.2.840.10046.2.1), whose parameters are
//!
//!   ```text
//!   DomainParameters ::= SEQUENCE {
//!     p                INTEGER,           -- odd prime, p = jq + 1
//!     g                INTEGER,           -- generator
//!     q                INTEGER,           -- factor of p - 1
//!     j                INTEGER OPTIONAL,  -- subgroup factor
//!     validationParms  ValidationParms OPTIONAL }
//!   ValidationParms ::= SEQUENCE { seed BIT STRING, pgenCounter INTEGER }
//!   ```
//!
//!   and whose `subjectPublicKey` is the DER `DHPublicKey ::= INTEGER`, `y`
//!   (RFC 3279 §2.3.3). The order is `p`, `g`, `q`.
//! - Private keys have no published standard. RFC 3279 and RFC 5480 define
//!   only the public key, RFC 5912's module leaves the private-key format out,
//!   and RFC 5958 §2 describes RSA, DSA and elliptic-curve private keys but
//!   not Diffie-Hellman ones. These encoders follow the convention OpenSSL
//!   writes and reads, confirmed by running it as a black box: a
//!   `OneAsymmetricKey` under `dhpublicnumber` with the `DomainParameters`,
//!   whose `privateKey` is the DER `INTEGER` `x`, as RFC 5958 gives for DSA. A
//!   version 2 `publicKey` is read the same way, as the `INTEGER` `y`.
//! - `DhParams` encode as `DomainParameters`. The encoder writes no `j`, and
//!   writes `ValidationParms` exactly when the parameters carry a FIPS 186-4
//!   seed record: its `domain_parameter_seed` as `seed`, its `counter` as
//!   `pgenCounter`. `ValidationParms` has no field for the hash function or
//!   the A.2.3 `index` that FIPS 186-4 A.1.1.3 and A.2.4 need, so the decoder
//!   checks its shape and keeps no seed record. A present `j` must satisfy
//!   `p = jq + 1`.
//!
//! ## Validation
//!
//! A decoded key goes through the scheme's `from_serial_fields`, the
//! validation the crate-defined formats get (see the `public_key` module
//! docs): structural for public keys, complete for private keys. A version 2
//! `publicKey` must equal the `y` the private key yields. Decoded domain
//! parameters go through `DsaParams::new` or `DhParams::new`, the hardened
//! validation. Parameters must be present: RFC 3279 lets a certificate
//! inherit its issuer's, and a key read on its own has no issuer.

use crate::public_key::io::{der_bit_string, der_integer_biguint, der_sequence, tag, DerReader};
use crate::public_key::pkix::{
    AlgorithmIdentifier, ObjectIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo,
    DH_PUBLIC_NUMBER, ID_DSA,
};
use crate::zeroize_slice;
use rump::BigUint;

/// The two finite-field algorithms of RFC 3279.
#[derive(Clone, Copy)]
pub(crate) enum FfcAlgorithm {
    /// `id-dsa` with `Dss-Parms` (RFC 3279 §2.3.2).
    Dsa,
    /// `dhpublicnumber` with `DomainParameters` (RFC 3279 §2.3.3).
    Dh,
}

impl FfcAlgorithm {
    /// The algorithm's object identifier.
    fn identifier(self) -> &'static ObjectIdentifier {
        match self {
            Self::Dsa => &ID_DSA,
            Self::Dh => &DH_PUBLIC_NUMBER,
        }
    }

    /// The domain parameters as one complete DER value: `Dss-Parms`, or
    /// `DomainParameters` with `ValidationParms` when `validation`, a seed and
    /// counter, is given. `Dss-Parms` has no place for `validation`.
    pub(crate) fn parameters_der(
        self,
        p: &BigUint,
        q: &BigUint,
        g: &BigUint,
        validation: Option<(&[u8], u16)>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Self::Dsa => {
                for value in [p, q, g] {
                    body.extend(der_integer_biguint(value));
                }
            }
            Self::Dh => {
                for value in [p, g, q] {
                    body.extend(der_integer_biguint(value));
                }
                if let Some((seed, counter)) = validation {
                    let mut parms = der_bit_string(seed);
                    parms.extend(der_integer_biguint(&BigUint::from_u64(u64::from(counter))));
                    body.extend(der_sequence(&parms));
                }
            }
        }
        der_sequence(&body)
    }

    /// `(p, q, g)` from one complete parameters value, checked as the module
    /// docs describe but not yet validated as a group.
    pub(crate) fn decode_parameters(self, encoding: &[u8]) -> Option<(BigUint, BigUint, BigUint)> {
        let mut outer = DerReader::new(encoding);
        let body = outer.read_sequence()?;
        if !outer.is_finished() {
            return None;
        }
        let mut fields = DerReader::new(body);
        let first = fields.read_integer_biguint()?;
        let second = fields.read_integer_biguint()?;
        let third = fields.read_integer_biguint()?;
        let (p, q, g) = match self {
            Self::Dsa => (first, second, third),
            Self::Dh => {
                let (p, g, q) = (first, second, third);
                if fields.peek_tag() == Some(tag::INTEGER) {
                    let j = fields.read_integer_biguint()?;
                    if j.mul(&q).add(&BigUint::one()) != p {
                        return None;
                    }
                }
                if fields.peek_tag() == Some(tag::SEQUENCE)
                    && !validation_parms_are_der(fields.read_sequence()?)
                {
                    return None;
                }
                (p, q, g)
            }
        };
        fields.is_finished().then_some((p, q, g))
    }
}

/// The contents of `ValidationParms ::= SEQUENCE { seed BIT STRING,
/// pgenCounter INTEGER }`: any DER bit string, then a non-negative counter.
fn validation_parms_are_der(contents: &[u8]) -> bool {
    let mut fields = DerReader::new(contents);
    fields
        .read_element()
        .is_some_and(|seed| seed.first() == Some(&tag::BIT_STRING))
        && fields.read_integer_biguint().is_some()
        && fields.is_finished()
}

/// The value of `der`, which must be exactly one non-negative DER `INTEGER`.
fn single_integer(der: &[u8]) -> Option<BigUint> {
    let mut reader = DerReader::new(der);
    let value = reader.read_integer_biguint()?;
    reader.is_finished().then_some(value)
}

/// The `SubjectPublicKeyInfo` of the public value `y` in the group `(p, q, g)`.
pub(crate) fn spki_der(
    algorithm: FfcAlgorithm,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
) -> Vec<u8> {
    let parameters = algorithm.parameters_der(p, q, g, None);
    let public_key = der_integer_biguint(y);
    SubjectPublicKeyInfo::new(
        AlgorithmIdentifier::new(algorithm.identifier(), Some(&parameters)),
        &public_key,
    )
    .to_der()
}

/// The schema fields `[p, q, g, y]` of a `SubjectPublicKeyInfo`, for the
/// scheme to validate.
pub(crate) fn decode_spki(algorithm: FfcAlgorithm, der: &[u8]) -> Option<Vec<BigUint>> {
    let spki = SubjectPublicKeyInfo::from_der(der)?;
    if !spki.algorithm().is(algorithm.identifier()) {
        return None;
    }
    let (p, q, g) = algorithm.decode_parameters(spki.algorithm().parameters()?)?;
    let y = single_integer(spki.subject_public_key())?;
    Some(vec![p, q, g, y])
}

/// The `OneAsymmetricKey` (version 1) of the private value `x` in the group
/// `(p, q, g)`.
///
/// Three buffers hold `x` on the way to the returned encoding, and each is
/// wiped once copied out of: the big-endian magnitude `to_be_bytes` produces
/// (wiped inside `der_integer_biguint`), the DER `INTEGER` built from it
/// (`private_key` below, wiped here), and the `OCTET STRING` that
/// `OneAsymmetricKey::to_der` wraps it in, which `der_sequence_of` wipes as
/// it assembles the container at its exact size. Only the returned `Vec`
/// keeps `x`; the caller owns it, and `to_pkcs8_pem` wipes it after
/// armoring. rump wipes its own limb buffers under the `wipe` feature this
/// crate enables.
pub(crate) fn pkcs8_der(
    algorithm: FfcAlgorithm,
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    x: &BigUint,
) -> Vec<u8> {
    let parameters = algorithm.parameters_der(p, q, g, None);
    let mut private_key = der_integer_biguint(x);
    let out = OneAsymmetricKey::new(
        AlgorithmIdentifier::new(algorithm.identifier(), Some(&parameters)),
        &private_key,
        None,
    )
    .to_der();
    zeroize_slice(private_key.as_mut_slice());
    out
}

/// The schema fields `[p, q, g, x]` of a `OneAsymmetricKey`, for the scheme
/// to validate, and `y` from a version 2 `publicKey`.
pub(crate) fn decode_pkcs8(
    algorithm: FfcAlgorithm,
    der: &[u8],
) -> Option<(Vec<BigUint>, Option<BigUint>)> {
    let key = OneAsymmetricKey::from_der(der)?;
    if !key.algorithm().is(algorithm.identifier()) {
        return None;
    }
    let (p, q, g) = algorithm.decode_parameters(key.algorithm().parameters()?)?;
    let x = single_integer(key.private_key())?;
    let y = match key.public_key() {
        Some(octets) => Some(single_integer(octets)?),
        None => None,
    };
    Some((vec![p, q, g, x], y))
}

/// Emit `to_spki_*` / `from_spki_*` and `to_pkcs8_*` / `from_pkcs8_*` for a
/// finite-field key pair type whose keys keep `p`, `q`, `g` and `y` (and the
/// private key `x`) in fields of those names and rebuild themselves with
/// `from_serial_fields`. The two literals state the standard, or its absence,
/// for the public and the private encoding.
macro_rules! impl_ffc_key_encodings {
    ($public:ident, $private:ident, $algorithm:ident, $public_standard:literal, $private_standard:literal) => {
        impl $public {
            #[doc = concat!("Encode as a `SubjectPublicKeyInfo` in DER: ", $public_standard, ".")]
            #[must_use]
            pub fn to_spki_der(&self) -> Vec<u8> {
                crate::public_key::ffc_pkix::spki_der(
                    crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm,
                    &self.p,
                    &self.q,
                    &self.g,
                    &self.y,
                )
            }

            /// [`Self::to_spki_der`] under the RFC 7468 `PUBLIC KEY` label.
            #[must_use]
            pub fn to_spki_pem(&self) -> String {
                crate::public_key::pkix::pem_encode(
                    crate::public_key::pkix::PUBLIC_KEY_LABEL,
                    self.to_spki_der(),
                )
            }

            /// Decode a `SubjectPublicKeyInfo` in strict DER, as
            /// [`Self::to_spki_der`] writes it. The parameters must be present,
            /// and the key passes the structural validation the crate-defined
            /// formats apply.
            #[must_use]
            pub fn from_spki_der(der: &[u8]) -> Option<Self> {
                Self::from_serial_fields(crate::public_key::ffc_pkix::decode_spki(
                    crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm,
                    der,
                )?)
            }

            /// Decode a `PUBLIC KEY` textual encoding, read by RFC 7468 §2's
            /// parser rules. RFC 7468 §13 requires the contents to be BER
            /// ("DER preferred"), so any BER encoding of the container and its
            /// parameters is accepted. The `INTEGER` inside keeps the rule RFC
            /// 3279 gives it: a DSA public key "MUST be ASN.1 DER encoded"
            /// (§2.3.2), a Diffie-Hellman one only "ASN.1 encoded" (§2.3.3).
            /// The key is then checked as [`Self::from_spki_der`] checks it.
            #[must_use]
            pub fn from_spki_pem(pem: &str) -> Option<Self> {
                crate::public_key::pkix::pem_decode(
                    crate::public_key::pkix::PUBLIC_KEY_LABEL,
                    pem,
                    Self::from_spki_der,
                )
            }
        }

        impl $private {
            #[doc = concat!(
                "Encode as an RFC 5958 `OneAsymmetricKey` (PKCS #8 `PrivateKeyInfo`, version 1) in DER. ",
                $private_standard
            )]
            #[must_use]
            pub fn to_pkcs8_der(&self) -> Vec<u8> {
                crate::public_key::ffc_pkix::pkcs8_der(
                    crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm,
                    &self.p,
                    &self.q,
                    &self.g,
                    &self.x,
                )
            }

            /// [`Self::to_pkcs8_der`] under the RFC 7468 `PRIVATE KEY` label.
            #[must_use]
            pub fn to_pkcs8_pem(&self) -> String {
                crate::public_key::pkix::pem_encode(
                    crate::public_key::pkix::PRIVATE_KEY_LABEL,
                    self.to_pkcs8_der(),
                )
            }

            /// Decode a `OneAsymmetricKey` in strict DER, as
            /// [`Self::to_pkcs8_der`] writes it. The parameters must be present,
            /// the key passes the complete validation the crate-defined formats
            /// apply, and a version 2 `publicKey` must be the key's own `y`.
            #[must_use]
            pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
                let (fields, public) = crate::public_key::ffc_pkix::decode_pkcs8(
                    crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm,
                    der,
                )?;
                let key = Self::from_serial_fields(fields)?;
                if public.is_some_and(|y| y != key.y) {
                    return None;
                }
                Some(key)
            }

            /// Decode a `OneAsymmetricKey` in any X.690 BER encoding, DER
            /// included: RFC 5958 §2 says "receivers MUST support BER". The
            /// parameters and the private `INTEGER` may be BER as well; a
            /// version 2 `publicKey` keeps the rule of the public key
            /// (RFC 3279 §2.3.2 and §2.3.3). The key is then checked as
            /// [`Self::from_pkcs8_der`] checks it.
            #[must_use]
            pub fn from_pkcs8_ber(ber: &[u8]) -> Option<Self> {
                crate::public_key::pkix::pkcs8_ber(ber, Self::from_pkcs8_der)
            }

            /// Decode a `PRIVATE KEY` textual encoding, read by RFC 7468 §2's
            /// parser rules, its contents as [`Self::from_pkcs8_ber`] reads
            /// them: RFC 7468 §10 requires them to be BER ("DER preferred").
            #[must_use]
            pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
                crate::public_key::pkix::pem_decode(
                    crate::public_key::pkix::PRIVATE_KEY_LABEL,
                    pem,
                    Self::from_pkcs8_der,
                )
            }
        }
    };
}
pub(crate) use impl_ffc_key_encodings;

/// Emit `to_der` / `from_der` for a domain-parameter type with `new`,
/// `modulus`, `subgroup_order`, `generator` and `seed`. The literals document
/// the two methods.
macro_rules! impl_ffc_parameters_der {
    ($params:ident, $algorithm:ident, $to_doc:literal, $from_doc:literal) => {
        impl $params {
            #[doc = $to_doc]
            #[must_use]
            pub fn to_der(&self) -> Vec<u8> {
                let validation = self
                    .seed()
                    .map(|seed| (seed.domain_parameter_seed(), seed.counter()));
                crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm.parameters_der(
                    self.modulus(),
                    self.subgroup_order(),
                    self.generator(),
                    validation,
                )
            }

            #[doc = $from_doc]
            #[must_use]
            pub fn from_der(der: &[u8]) -> Option<Self> {
                let (p, q, g) =
                    crate::public_key::ffc_pkix::FfcAlgorithm::$algorithm.decode_parameters(der)?;
                Self::new(p, q, g)
            }
        }
    };
}
pub(crate) use impl_ffc_parameters_der;

#[cfg(test)]
mod tests {
    use super::FfcAlgorithm;
    use crate::public_key::dh::{DhParams, DhPrivateKey, DhPublicKey};
    use crate::public_key::dsa::{Dsa, DsaParams, DsaPrivateKey, DsaPublicKey};
    use crate::public_key::io::{
        der_bit_string, der_integer_biguint, der_integer_u8, der_sequence,
    };
    use crate::public_key::pkix::{
        pem_decode, AlgorithmIdentifier, OneAsymmetricKey, SubjectPublicKeyInfo, DH_PUBLIC_NUMBER,
        ID_DSA, NULL_PARAMETERS, PRIVATE_KEY_LABEL,
    };
    use crate::public_key::primes::cavp;
    use crate::test_utils::openssl3;
    use rump::BigUint;

    /// RFC 9500 §2.2's publicly known DLP key "testDLP1024", which the RFC
    /// offers "for DLP-based algorithms such as DSA, DH, and Elgamal".
    const DLP1024_P: &str = "030CDFC38FC3E4212790B0A41E45B4E4E880DE8ABFD3AECA0B238FB6CD730CC3\
        18769336D5B180B2802A01BE4BC1AB84FCE2FF489B50C2D29DE91EC0E65B6064\
        FD0DE537EABA1C6CDD27DC3030481E8BB960AA8B8AEF933530E6B1CC5160BBFA\
        AF850FF6578112337D53034E4163DC6503BDF8892581141FAB8255B6D9727BB3";
    const DLP1024_Q: &str = "EC41B9C0621D5BDCAF11D5198F7208882E65BBDF";
    const DLP1024_G: &str = "016487ACCFCD955051E06E1C5BEF452C1263C75D2B36504FB4275735C283320B\
        63AC91C6F4020932531CAB04B1CD72FDF29DE24E271797A7DD2197676931F933\
        1D1F59EEE5BA2C7D54AE135C7F794137D8D80EB629288E268A3BEBD21F16A403\
        F1D5DAD83C1C478017A3CD266F1BA49B890DC089212E72261DA367AF803B0250";
    const DLP1024_X: &str = "11ED99785A813A1B0E96ECD38D7F9BCE9EBFD6FA";
    const DLP1024_Y: &str = "0220B942C25C44DA52B0D17682EAC436EA7E81EC9F76E1057532AA67EADD04AD\
        B8FD6181BA0B25F284DAAAAA05F3C84034D417D37B6E0A63318A0A791F1D0DD4\
        F68AFAE335AA5DBEA3F2F6D6DD730926247FDC4D1B82DF8C2D87AE8D36ADB9DD\
        2513578E8B99AA6A0EDF675FFC2FDEB64B26E5BED8532DFD98110FCFC9EDF938";
    /// The same key as RFC 9500 prints it, in OpenSSL's `DSA PRIVATE KEY` form.
    const DLP1024_PEM: &str = "-----BEGIN DSA PRIVATE KEY-----\n\
        MIIBuQIBAAKBgAMM38OPw+QhJ5CwpB5FtOTogN6Kv9Ouygsjj7bNcwzDGHaTNtWx\n\
        gLKAKgG+S8GrhPzi/0ibUMLSnekewOZbYGT9DeU36rocbN0n3DAwSB6LuWCqi4rv\n\
        kzUw5rHMUWC7+q+FD/ZXgRIzfVMDTkFj3GUDvfiJJYEUH6uCVbbZcnuzAhUA7EG5\n\
        wGIdW9yvEdUZj3IIiC5lu98CgYABZIesz82VUFHgbhxb70UsEmPHXSs2UE+0J1c1\n\
        woMyC2Oskcb0AgkyUxyrBLHNcv3yneJOJxeXp90hl2dpMfkzHR9Z7uW6LH1UrhNc\n\
        f3lBN9jYDrYpKI4mijvr0h8WpAPx1drYPBxHgBejzSZvG6SbiQ3AiSEuciYdo2ev\n\
        gDsCUAKBgAIguULCXETaUrDRdoLqxDbqfoHsn3bhBXUyqmfq3QStuP1hgboLJfKE\n\
        2qqqBfPIQDTUF9N7bgpjMYoKeR8dDdT2ivrjNapdvqPy9tbdcwkmJH/cTRuC34wt\n\
        h66NNq253SUTV46LmapqDt9nX/wv3rZLJuW+2FMt/ZgRD8/J7fk4AhQR7Zl4WoE6\n\
        Gw6W7NONf5vOnr/W+g==\n\
        -----END DSA PRIVATE KEY-----\n";

    fn hex(value: &str) -> BigUint {
        BigUint::from_str_radix(value, 16).expect("hexadecimal")
    }

    fn u(value: u64) -> BigUint {
        BigUint::from_u64(value)
    }

    /// `(p, q, g, x, y)` of RFC 9500's DLP-1024 key.
    fn dlp1024() -> (BigUint, BigUint, BigUint, BigUint, BigUint) {
        (
            hex(DLP1024_P),
            hex(DLP1024_Q),
            hex(DLP1024_G),
            hex(DLP1024_X),
            hex(DLP1024_Y),
        )
    }

    /// OpenSSL's own textual labels for bare domain parameters. No standard
    /// defines them (RFC 7468 lists none for parameters); they are used here
    /// only to hand parameters to the `openssl` tool, which cannot decode
    /// X9.42 or DSA parameters from DER arriving on a pipe.
    const DSA_PARAMETERS_LABEL: &str = "DSA PARAMETERS";
    const DH_PARAMETERS_LABEL: &str = "X9.42 DH PARAMETERS";

    fn openssl_parameters_pem(label: &str, der: &[u8]) -> String {
        crate::public_key::pkix::pem_encode(label, der.to_vec())
    }

    fn spki(algorithm: AlgorithmIdentifier<'_>, key: &[u8]) -> Vec<u8> {
        SubjectPublicKeyInfo::new(algorithm, key).to_der()
    }

    fn pkcs8(algorithm: AlgorithmIdentifier<'_>, key: &[u8], public: Option<&[u8]>) -> Vec<u8> {
        OneAsymmetricKey::new(algorithm, key, public).to_der()
    }

    #[test]
    fn rfc9500_dlp1024_dsa_key_round_trips() {
        let (p, q, g, x, y) = dlp1024();
        let (public, private) = Dsa::from_secret_exponent(&p, &q, &g, &x).expect("RFC 9500 group");
        assert_eq!(public.public_component(), &y);
        assert_eq!(
            DsaPublicKey::from_spki_der(&public.to_spki_der()),
            Some(public.clone())
        );
        assert_eq!(
            DsaPublicKey::from_spki_pem(&public.to_spki_pem()),
            Some(public)
        );
        assert_eq!(
            DsaPrivateKey::from_pkcs8_der(&private.to_pkcs8_der()),
            Some(private.clone())
        );
        assert_eq!(
            DsaPrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private)
        );
    }

    /// OpenSSL turns RFC 9500's DLP-1024 key, published in OpenSSL's own
    /// `DSA PRIVATE KEY` form, into exactly the PKCS #8 and SPKI encodings
    /// written here, and reads them back.
    #[test]
    fn openssl_converts_rfc9500_dsa_key_to_the_same_encodings() {
        const TEST: &str = "openssl_converts_rfc9500_dsa_key_to_the_same_encodings";
        let (p, q, g, x, _) = dlp1024();
        let (public, private) = Dsa::from_secret_exponent(&p, &q, &g, &x).expect("RFC 9500 group");
        let Some(pkcs8) = openssl3(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            DLP1024_PEM.as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(pkcs8, private.to_pkcs8_der());
        let Some(spki) = openssl3(
            &["pkey", "-inform", "PEM", "-pubout", "-outform", "DER"],
            DLP1024_PEM.as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(spki, public.to_spki_der());
        let Some(reread) = openssl3(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            private.to_pkcs8_pem().as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(reread, pkcs8);
        let parameters = private.params().to_der();
        let Some(rewritten) = openssl3(
            &["dsaparam", "-outform", "DER"],
            openssl_parameters_pem(DSA_PARAMETERS_LABEL, &parameters).as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(rewritten, parameters);
    }

    /// A DSA key OpenSSL generates in a FIPS 186-4 group parses, and
    /// re-encodes as OpenSSL wrote it. OpenSSL 3 generates DSA keys only at
    /// FIPS 186-4 sizes, which RFC 9500's 1018-bit modulus is not, so the
    /// group is the CAVP 1024-bit one.
    #[test]
    fn openssl_generated_dsa_key_round_trips() {
        const TEST: &str = "openssl_generated_dsa_key_round_trips";
        let (p, q, g, _) = cavp::fips186_4_1024_parts(1);
        let parameters = DsaParams::new(p, q, g).expect("CAVP group").to_der();
        let parameters_pem = openssl_parameters_pem(DSA_PARAMETERS_LABEL, &parameters);
        let Some(generated) = openssl3(
            &["genpkey", "-paramfile", "/dev/stdin"],
            parameters_pem.as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        let pem = String::from_utf8(generated).expect("PEM is ASCII");
        let key = DsaPrivateKey::from_pkcs8_pem(&pem).expect("OpenSSL's DSA PKCS #8 key");
        let der = pem_decode(PRIVATE_KEY_LABEL, &pem, |der| Some(der.to_vec())).expect("PEM");
        assert_eq!(key.to_pkcs8_der(), der);
        let Some(spki) =
            openssl3(&["pkey", "-pubout", "-outform", "DER"], pem.as_bytes()).or_skip(TEST)
        else {
            return;
        };
        assert_eq!(key.to_public_key().to_spki_der(), spki);
    }

    /// The smallest group the size policy admits with `p = 2q + 1`:
    /// `q = 32771`, `p = 65543`, `g = 4` (order `q`); `x = 3`, `y = 64`.
    const P: u64 = 65543;
    const Q: u64 = 32771;
    const G: u64 = 4;

    #[test]
    fn dsa_decoders_follow_rfc3279_and_rfc5958() {
        let (public, private) =
            Dsa::from_secret_exponent(&u(P), &u(Q), &u(G), &u(3)).expect("toy group");
        let parameters = FfcAlgorithm::Dsa.parameters_der(&u(P), &u(Q), &u(G), None);
        let dh_order = FfcAlgorithm::Dh.parameters_der(&u(P), &u(Q), &u(G), None);
        let algorithm = AlgorithmIdentifier::new(&ID_DSA, Some(&parameters));
        let y = der_integer_biguint(&u(64));
        assert_eq!(
            DsaPublicKey::from_spki_der(&spki(algorithm, &y)),
            Some(public)
        );

        // Absent or NULL parameters, the DH field order, the DH identifier, a
        // y outside the subgroup, and a key that is not exactly one INTEGER.
        let mut trailing = y.clone();
        trailing.push(0);
        for der in [
            spki(AlgorithmIdentifier::new(&ID_DSA, None), &y),
            spki(AlgorithmIdentifier::new(&ID_DSA, Some(NULL_PARAMETERS)), &y),
            spki(AlgorithmIdentifier::new(&ID_DSA, Some(&dh_order)), &y),
            spki(
                AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(&parameters)),
                &y,
            ),
            spki(algorithm, &der_integer_biguint(&u(1))),
            spki(algorithm, &trailing),
            spki(algorithm, &[0x04, 0x01, 0x12]),
        ] {
            assert!(DsaPublicKey::from_spki_der(&der).is_none());
        }

        let x = der_integer_biguint(&u(3));
        assert_eq!(
            DsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &x, None)),
            Some(private.clone())
        );
        // RFC 5958 §2: a version 2 publicKey is the INTEGER y.
        assert_eq!(
            DsaPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &x, Some(&y))),
            Some(private)
        );
        for der in [
            pkcs8(algorithm, &x, Some(&der_integer_biguint(&u(G)))),
            pkcs8(algorithm, &der_integer_biguint(&u(0)), None),
            pkcs8(algorithm, &der_integer_biguint(&u(Q)), None),
            pkcs8(algorithm, &[0x04, 0x01, 0x03], None),
            pkcs8(AlgorithmIdentifier::new(&ID_DSA, None), &x, None),
        ] {
            assert!(DsaPrivateKey::from_pkcs8_der(&der).is_none());
        }
    }

    #[test]
    fn dsa_parameters_are_dss_parms() {
        let parameters = DsaParams::new(u(P), u(Q), u(G)).expect("toy group");
        let der = parameters.to_der();
        // p = 0x010007 (three octets), q = 0x8003 (a leading zero octet keeps
        // the INTEGER positive), g = 4.
        assert_eq!(
            der,
            [
                0x30, 0x0d, 0x02, 0x03, 0x01, 0x00, 0x07, 0x02, 0x03, 0x00, 0x80, 0x03, 0x02, 0x01,
                0x04
            ]
        );
        assert_eq!(DsaParams::from_der(&der), Some(parameters));
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(DsaParams::from_der(&trailing).is_none());
        // q and g swapped: q = 4 is not a prime-order subgroup.
        assert!(DsaParams::from_der(&[
            0x30, 0x0d, 0x02, 0x03, 0x01, 0x00, 0x07, 0x02, 0x01, 0x04, 0x02, 0x03, 0x00, 0x80,
            0x03
        ])
        .is_none());
        // A group below the size policy: p = 23, q = 11, g = 4.
        assert!(DsaParams::from_der(&[
            0x30, 0x09, 0x02, 0x01, 0x17, 0x02, 0x01, 0x0b, 0x02, 0x01, 0x04
        ])
        .is_none());
    }

    /// The DH key with `x = 3` in the toy group `p = 65543, q = 32771, g = 4`.
    fn toy_dh_key() -> (Vec<u8>, DhPrivateKey) {
        let parameters = FfcAlgorithm::Dh.parameters_der(&u(P), &u(Q), &u(G), None);
        let der = pkcs8(
            AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(&parameters)),
            &der_integer_biguint(&u(3)),
            None,
        );
        let key = DhPrivateKey::from_pkcs8_der(&der).expect("toy DH key");
        (der, key)
    }

    #[test]
    fn dh_decoders_follow_rfc3279() {
        let (der, private) = toy_dh_key();
        assert_eq!(private.to_pkcs8_der(), der);
        assert_eq!(
            DhPrivateKey::from_pkcs8_pem(&private.to_pkcs8_pem()),
            Some(private.clone())
        );
        let public = private.to_public_key();
        assert_eq!(public.public_component(), &u(64));
        assert_eq!(
            DhPublicKey::from_spki_pem(&public.to_spki_pem()),
            Some(public.clone())
        );

        let y = der_integer_biguint(&u(64));
        let with_parameters = |fields: &[Vec<u8>]| der_sequence(&fields.concat());
        let (p, g, q) = (
            der_integer_biguint(&u(P)),
            der_integer_biguint(&u(G)),
            der_integer_biguint(&u(Q)),
        );
        let j2 = der_integer_biguint(&u(2));
        let j3 = der_integer_biguint(&u(3));
        let validation = der_sequence(&[der_bit_string(&[0xa5]), der_integer_u8(7)].concat());
        let seed_with_unused_bits =
            der_sequence(&[vec![0x03, 0x02, 0x04, 0xf0], der_integer_u8(7)].concat());
        let swapped = der_sequence(&[der_integer_u8(7), der_bit_string(&[0xa5])].concat());
        let accepts = |parameters: &[u8]| {
            let algorithm = AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(parameters));
            DhPublicKey::from_spki_der(&spki(algorithm, &y))
        };
        // j = (p - 1) / q and well-formed ValidationParms are accepted.
        for parameters in [
            with_parameters(&[p.clone(), g.clone(), q.clone()]),
            with_parameters(&[p.clone(), g.clone(), q.clone(), j2.clone()]),
            with_parameters(&[p.clone(), g.clone(), q.clone(), validation.clone()]),
            with_parameters(&[
                p.clone(),
                g.clone(),
                q.clone(),
                j2.clone(),
                seed_with_unused_bits,
            ]),
        ] {
            assert_eq!(accepts(&parameters), Some(public.clone()));
        }
        // A wrong j, ValidationParms before j or out of shape, the DSA field
        // order, and the DSA identifier.
        for parameters in [
            with_parameters(&[p.clone(), g.clone(), q.clone(), j3]),
            with_parameters(&[p.clone(), g.clone(), q.clone(), validation.clone(), j2]),
            with_parameters(&[p.clone(), g.clone(), q.clone(), swapped]),
            with_parameters(&[p.clone(), q.clone(), g.clone()]),
        ] {
            assert!(accepts(&parameters).is_none());
        }
        let dh_parameters = with_parameters(&[p, g, q]);
        assert!(DhPublicKey::from_spki_der(&spki(
            AlgorithmIdentifier::new(&ID_DSA, Some(&dh_parameters)),
            &y
        ))
        .is_none());

        // A version 2 publicKey must be the key's y.
        let algorithm = AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(&dh_parameters));
        let x = der_integer_biguint(&u(3));
        assert_eq!(
            DhPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &x, Some(&y))),
            Some(private)
        );
        assert!(DhPrivateKey::from_pkcs8_der(&pkcs8(
            algorithm,
            &x,
            Some(&der_integer_biguint(&u(G)))
        ))
        .is_none());
        assert!(
            DhPrivateKey::from_pkcs8_der(&pkcs8(algorithm, &der_integer_biguint(&u(0)), None))
                .is_none()
        );
    }

    /// OpenSSL reads the RFC 9500 DLP-1024 group as a Diffie-Hellman key in
    /// the encodings written here and writes them back unchanged, and a key it
    /// generates in that group parses.
    #[test]
    fn openssl_agrees_on_rfc9500_group_as_dh_keys() {
        const TEST: &str = "openssl_agrees_on_rfc9500_group_as_dh_keys";
        let (p, q, g, x, y) = dlp1024();
        let parameters = FfcAlgorithm::Dh.parameters_der(&p, &q, &g, None);
        let der = pkcs8(
            AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(&parameters)),
            &der_integer_biguint(&x),
            None,
        );
        let private = DhPrivateKey::from_pkcs8_der(&der).expect("RFC 9500 group as DH");
        let public = private.to_public_key();
        assert_eq!(public.public_component(), &y);
        assert_eq!(private.to_pkcs8_der(), der);

        let Some(reread) =
            openssl3(&["pkey", "-inform", "DER", "-outform", "DER"], &der).or_skip(TEST)
        else {
            return;
        };
        assert_eq!(reread, der);
        let Some(spki) = openssl3(
            &["pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            &der,
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(spki, public.to_spki_der());
        assert_eq!(DhPublicKey::from_spki_der(&spki), Some(public));

        let domain = DhParams::new(p, q, g).expect("RFC 9500 group").to_der();
        let domain_pem = openssl_parameters_pem(DH_PARAMETERS_LABEL, &domain);
        let Some(generated) = openssl3(
            &["genpkey", "-paramfile", "/dev/stdin"],
            domain_pem.as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        let pem = String::from_utf8(generated).expect("PEM is ASCII");
        let key = DhPrivateKey::from_pkcs8_pem(&pem).expect("OpenSSL's DH PKCS #8 key");
        let generated_der =
            pem_decode(PRIVATE_KEY_LABEL, &pem, |der| Some(der.to_vec())).expect("PEM");
        assert_eq!(key.to_pkcs8_der(), generated_der);
    }

    /// `DhParams::to_der` writes the FIPS 186-4 seed and counter as
    /// `ValidationParms`; the decoder checks and drops them; OpenSSL rewrites
    /// the same `DomainParameters`.
    #[test]
    fn dh_parameters_carry_validation_parms() {
        const TEST: &str = "dh_parameters_carry_validation_parms";
        let (p, q, g, seed) = cavp::fips186_4_1024_parts(2);
        let seeded = DhParams::with_seed(p.clone(), q.clone(), g.clone(), seed.clone())
            .expect("CAVP parameters");
        let der = seeded.to_der();
        let validation = der_sequence(
            &[
                der_bit_string(seed.domain_parameter_seed()),
                der_integer_biguint(&u(u64::from(seed.counter()))),
            ]
            .concat(),
        );
        let expected = der_sequence(
            &[
                der_integer_biguint(&p),
                der_integer_biguint(&g),
                der_integer_biguint(&q),
                validation,
            ]
            .concat(),
        );
        assert_eq!(der, expected);
        let parsed = DhParams::from_der(&der).expect("DomainParameters");
        assert_eq!(parsed.modulus(), &p);
        assert_eq!(parsed.subgroup_order(), &q);
        assert_eq!(parsed.generator(), &g);
        assert!(parsed.seed().is_none());
        let unseeded = DhParams::new(p, q, g).expect("CAVP parameters");
        assert_eq!(parsed, unseeded);

        let Some(rewritten) = openssl3(
            &["dhparam", "-outform", "DER"],
            openssl_parameters_pem(DH_PARAMETERS_LABEL, &der).as_bytes(),
        )
        .or_skip(TEST) else {
            return;
        };
        assert_eq!(rewritten, der);
    }

    /// RFC 5958 §2 ("receivers MUST support BER"): `from_pkcs8_ber` and
    /// `PRIVATE KEY` text read DSA and DH keys in every BER form, the
    /// parameters and the private `INTEGER` included, where `from_pkcs8_der`
    /// does not. RFC 7468 §13 lets `PUBLIC KEY` text be BER too, but the
    /// `INTEGER` in the `subjectPublicKey` keeps RFC 3279's rule: a DSA key
    /// "MUST be ASN.1 DER encoded" (§2.3.2), a DH key only "ASN.1 encoded"
    /// (§2.3.3).
    #[test]
    fn ber_receivers_keep_the_integer_rules_of_rfc3279() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        use crate::public_key::pkix::{pem_encode, PUBLIC_KEY_LABEL};
        let (p, q, g, x, y) = dlp1024();
        let (dsa_public, dsa_private) =
            Dsa::from_secret_exponent(&p, &q, &g, &x).expect("RFC 9500 group");
        let dsa_parameters = FfcAlgorithm::Dsa.parameters_der(&p, &q, &g, None);
        let dh_parameters = FfcAlgorithm::Dh.parameters_der(&p, &q, &g, None);
        let dsa_algorithm = AlgorithmIdentifier::new(&ID_DSA, Some(&dsa_parameters));
        let dh_algorithm = AlgorithmIdentifier::new(&DH_PUBLIC_NUMBER, Some(&dh_parameters));
        let dh_der = pkcs8(dh_algorithm, &der_integer_biguint(&x), None);
        let dh_private = DhPrivateKey::from_pkcs8_der(&dh_der).expect("RFC 9500 group as DH");
        let dh_public = dh_private.to_public_key();
        for style in STYLES {
            let x_ber = reencode(&der_integer_biguint(&x), style);
            let dsa_ber = reencode(&pkcs8(dsa_algorithm, &x_ber, None), style);
            assert!(
                DsaPrivateKey::from_pkcs8_der(&dsa_ber).is_none(),
                "{style:?}"
            );
            assert_eq!(
                DsaPrivateKey::from_pkcs8_ber(&dsa_ber),
                Some(dsa_private.clone()),
                "{style:?}"
            );
            let dh_ber = reencode(&pkcs8(dh_algorithm, &x_ber, None), style);
            assert!(DhPrivateKey::from_pkcs8_der(&dh_ber).is_none(), "{style:?}");
            assert_eq!(
                DhPrivateKey::from_pkcs8_ber(&dh_ber),
                Some(dh_private.clone()),
                "{style:?}"
            );
            let dsa_spki = reencode(&dsa_public.to_spki_der(), style);
            assert!(
                DsaPublicKey::from_spki_der(&dsa_spki).is_none(),
                "{style:?}"
            );
            assert_eq!(
                DsaPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, dsa_spki)),
                Some(dsa_public.clone()),
                "{style:?}"
            );
        }
        assert_eq!(
            DsaPrivateKey::from_pkcs8_pem(&pem_encode(
                PRIVATE_KEY_LABEL,
                reencode(&dsa_private.to_pkcs8_der(), STYLES[3])
            )),
            Some(dsa_private)
        );

        let y_ber = reencode(&der_integer_biguint(&y), STYLES[1]);
        let dsa_spki = spki(dsa_algorithm, &y_ber);
        assert!(DsaPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, dsa_spki)).is_none());
        let dh_spki = spki(dh_algorithm, &y_ber);
        assert!(DhPublicKey::from_spki_der(&dh_spki).is_none());
        assert_eq!(
            DhPublicKey::from_spki_pem(&pem_encode(PUBLIC_KEY_LABEL, dh_spki)),
            Some(dh_public)
        );
    }

    /// OpenSSL reads the BER forms of the RFC 9500 DSA key's PKCS #8 encoding,
    /// the private `INTEGER` in BER too, as the key the DER form encodes.
    #[test]
    fn openssl_reads_the_ber_forms_of_a_dsa_key_as_the_same_key() {
        use crate::public_key::io::ber_forms::{reencode, STYLES};
        const TEST: &str = "openssl_reads_the_ber_forms_of_a_dsa_key_as_the_same_key";
        let (p, q, g, x, _) = dlp1024();
        let (_, private) = Dsa::from_secret_exponent(&p, &q, &g, &x).expect("RFC 9500 group");
        let parameters = FfcAlgorithm::Dsa.parameters_der(&p, &q, &g, None);
        let Some(expected) = openssl3(
            &["pkey", "-inform", "DER", "-outform", "DER"],
            &private.to_pkcs8_der(),
        )
        .or_skip(TEST) else {
            return;
        };
        for style in [STYLES[0], STYLES[1]] {
            let x_ber = reencode(&der_integer_biguint(&x), style);
            let ber = reencode(
                &pkcs8(
                    AlgorithmIdentifier::new(&ID_DSA, Some(&parameters)),
                    &x_ber,
                    None,
                ),
                style,
            );
            let Some(read) =
                openssl3(&["pkey", "-inform", "DER", "-outform", "DER"], &ber).or_skip(TEST)
            else {
                return;
            };
            assert_eq!(read, expected, "{style:?}");
        }
    }
}
