//! Modern RSA key externalization helpers.
//!
//! The raw `Rsa` primitive stores just enough information to derive standards
//! formats on demand:
//! - `SubjectPublicKeyInfo` (SPKI) for public keys
//! - `PKCS #8` (`PrivateKeyInfo`) for private keys
//!
//! Lower-level PKCS #1 RSA key structures are also exposed because they are the
//! inner payloads of those modern containers and remain useful for debugging or
//! interop with older tooling.

use crate::public_key::bigint::BigUint;
use crate::public_key::io::{pem_unwrap, pem_wrap, xml_unwrap, xml_wrap};
use crate::public_key::rsa::{Rsa, RsaPrivateKey, RsaPublicKey};

const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

impl RsaPublicKey {
    /// Encode the public key as the PKCS #1 `RSAPublicKey` structure in DER.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(der_integer_biguint(self.modulus()));
        body.extend(der_integer_biguint(self.exponent()));
        der_sequence(&body)
    }

    /// Encode the public key as `SubjectPublicKeyInfo` in DER.
    #[must_use]
    pub fn to_spki_der(&self) -> Vec<u8> {
        let pkcs1 = self.to_pkcs1_der();
        let mut alg = Vec::new();
        alg.extend(der_oid(RSA_ENCRYPTION_OID));
        alg.extend(der_null());

        let mut body = Vec::new();
        body.extend(der_sequence(&alg));
        body.extend(der_bit_string(&pkcs1));
        der_sequence(&body)
    }

    /// Encode the public key as the PKCS #1 `RSA PUBLIC KEY` PEM label.
    #[must_use]
    pub fn to_pkcs1_pem(&self) -> String {
        pem_wrap("RSA PUBLIC KEY", &self.to_pkcs1_der())
    }

    /// Encode the public key as `PUBLIC KEY` PEM (`SubjectPublicKeyInfo`).
    #[must_use]
    pub fn to_spki_pem(&self) -> String {
        pem_wrap("PUBLIC KEY", &self.to_spki_der())
    }

    /// Encode the public key as the crate's flat XML form.
    ///
    /// This is a convenience export that mirrors the in-memory Rust fields
    /// directly. Standards-based interchange should still prefer PKCS #1 or
    /// SPKI.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "RsaPublicKey",
            &[("e", self.exponent()), ("n", self.modulus())],
        )
    }

    /// Decode a PKCS #1 `RSAPublicKey` structure from DER.
    #[must_use]
    pub fn from_pkcs1_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_tlv(0x30)?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        let modulus = reader.read_integer_biguint()?;
        let public_exponent = reader.read_integer_biguint()?;
        if !reader.is_finished() || public_exponent <= BigUint::one() {
            return None;
        }

        Some(Self::from_components(public_exponent, modulus))
    }

    /// Decode `SubjectPublicKeyInfo` from DER.
    #[must_use]
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_tlv(0x30)?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        let alg_seq = reader.read_tlv(0x30)?;
        let bit_string = reader.read_tlv(0x03)?;
        if !reader.is_finished() || bit_string.is_empty() || bit_string[0] != 0 {
            return None;
        }

        let mut alg_reader = DerReader::new(alg_seq);
        let oid = alg_reader.read_tlv(0x06)?;
        let _null = alg_reader.read_tlv(0x05)?;
        if !alg_reader.is_finished() || oid != RSA_ENCRYPTION_OID {
            return None;
        }

        Self::from_pkcs1_der(&bit_string[1..])
    }

    /// Decode a PKCS #1 `RSA PUBLIC KEY` PEM document.
    #[must_use]
    pub fn from_pkcs1_pem(pem: &str) -> Option<Self> {
        let der = pem_unwrap("RSA PUBLIC KEY", pem)?;
        Self::from_pkcs1_der(&der)
    }

    /// Decode a `PUBLIC KEY` PEM document (`SubjectPublicKeyInfo`).
    #[must_use]
    pub fn from_spki_pem(pem: &str) -> Option<Self> {
        let der = pem_unwrap("PUBLIC KEY", pem)?;
        Self::from_spki_der(&der)
    }

    /// Decode the public key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("RsaPublicKey", &["e", "n"], xml)?.into_iter();
        let public_exponent = fields.next()?;
        let modulus = fields.next()?;
        if fields.next().is_some() || public_exponent <= BigUint::one() || modulus <= BigUint::one()
        {
            return None;
        }
        Some(Self::from_components(public_exponent, modulus))
    }
}

impl RsaPrivateKey {
    /// Encode the private key as the PKCS #1 `RSAPrivateKey` structure in DER.
    ///
    /// # Panics
    ///
    /// Panics only if the cached CRT values are internally inconsistent.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend(der_integer_u8(0));
        body.extend(der_integer_biguint(self.modulus()));
        body.extend(der_integer_biguint(self.public_exponent()));
        body.extend(der_integer_biguint(self.exponent()));
        body.extend(der_integer_biguint(self.prime1()));
        body.extend(der_integer_biguint(self.prime2()));
        body.extend(der_integer_biguint(self.crt_exponent1()));
        body.extend(der_integer_biguint(self.crt_exponent2()));
        body.extend(der_integer_biguint(self.crt_coefficient()));
        der_sequence(&body)
    }

    /// Encode the private key as `PrivateKeyInfo` (`PKCS #8`) in DER.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        let pkcs1 = self.to_pkcs1_der();

        let mut alg = Vec::new();
        alg.extend(der_oid(RSA_ENCRYPTION_OID));
        alg.extend(der_null());

        let mut body = Vec::new();
        body.extend(der_integer_u8(0));
        body.extend(der_sequence(&alg));
        body.extend(der_octet_string(&pkcs1));
        der_sequence(&body)
    }

    /// Encode the private key as PKCS #1 `RSA PRIVATE KEY` PEM.
    #[must_use]
    pub fn to_pkcs1_pem(&self) -> String {
        pem_wrap("RSA PRIVATE KEY", &self.to_pkcs1_der())
    }

    /// Encode the private key as `PRIVATE KEY` PEM (`PKCS #8`).
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        pem_wrap("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Encode the private key as the crate's flat XML form.
    ///
    /// The XML form mirrors the stored key fields directly. PKCS #1 / PKCS #8
    /// remain the preferred interoperable formats.
    #[must_use]
    pub fn to_xml(&self) -> String {
        xml_wrap(
            "RsaPrivateKey",
            &[
                ("e", self.public_exponent()),
                ("d", self.exponent()),
                ("n", self.modulus()),
                ("p", self.prime1()),
                ("q", self.prime2()),
            ],
        )
    }

    /// Decode a PKCS #1 `RSAPrivateKey` structure from DER.
    #[must_use]
    pub fn from_pkcs1_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_tlv(0x30)?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        let version = reader.read_integer_small()?;
        if version != 0 {
            return None;
        }

        let modulus = reader.read_integer_biguint()?;
        let public_exponent = reader.read_integer_biguint()?;
        let private_exponent = reader.read_integer_biguint()?;
        let prime1 = reader.read_integer_biguint()?;
        let prime2 = reader.read_integer_biguint()?;
        let exponent1 = reader.read_integer_biguint()?;
        let exponent2 = reader.read_integer_biguint()?;
        let coefficient = reader.read_integer_biguint()?;
        if !reader.is_finished() {
            return None;
        }

        let (public, private) = Rsa::from_primes_with_exponent(&prime1, &prime2, &public_exponent)?;
        if public.modulus() != &modulus || private.exponent() != &private_exponent {
            return None;
        }

        if exponent1 != *private.crt_exponent1() || exponent2 != *private.crt_exponent2() {
            return None;
        }
        if coefficient != *private.crt_coefficient() {
            return None;
        }

        Some(private)
    }

    /// Decode `PrivateKeyInfo` (`PKCS #8`) from DER.
    #[must_use]
    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        let mut outer = DerReader::new(der);
        let seq = outer.read_tlv(0x30)?;
        if !outer.is_finished() {
            return None;
        }

        let mut reader = DerReader::new(seq);
        let version = reader.read_integer_small()?;
        if version != 0 {
            return None;
        }

        let alg_seq = reader.read_tlv(0x30)?;
        let inner = reader.read_tlv(0x04)?;
        if !reader.is_finished() {
            return None;
        }

        let mut alg_reader = DerReader::new(alg_seq);
        let oid = alg_reader.read_tlv(0x06)?;
        let _null = alg_reader.read_tlv(0x05)?;
        if !alg_reader.is_finished() || oid != RSA_ENCRYPTION_OID {
            return None;
        }

        Self::from_pkcs1_der(inner)
    }

    /// Decode a PKCS #1 `RSA PRIVATE KEY` PEM document.
    #[must_use]
    pub fn from_pkcs1_pem(pem: &str) -> Option<Self> {
        let der = pem_unwrap("RSA PRIVATE KEY", pem)?;
        Self::from_pkcs1_der(&der)
    }

    /// Decode a `PRIVATE KEY` PEM document (`PKCS #8`).
    #[must_use]
    pub fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        let der = pem_unwrap("PRIVATE KEY", pem)?;
        Self::from_pkcs8_der(&der)
    }

    /// Decode the private key from the crate's flat XML form.
    #[must_use]
    pub fn from_xml(xml: &str) -> Option<Self> {
        let mut fields = xml_unwrap("RsaPrivateKey", &["e", "d", "n", "p", "q"], xml)?.into_iter();
        let public_exponent = fields.next()?;
        let private_exponent = fields.next()?;
        let modulus = fields.next()?;
        let prime1 = fields.next()?;
        let prime2 = fields.next()?;
        if fields.next().is_some() {
            return None;
        }

        let (public, private) = Rsa::from_primes_with_exponent(&prime1, &prime2, &public_exponent)?;
        if public.modulus() != &modulus || private.exponent() != &private_exponent {
            return None;
        }
        Some(private)
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len() + 5);
    out.push(tag);
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        // DER short-form length: the length octet is the value itself.
        return vec![u8::try_from(len).expect("short DER length fits in u8")];
    }

    let bytes = len.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|&byte| byte != 0)
        .expect("non-zero long DER length has a significant byte");
    let len_bytes = &bytes[first_nonzero..];

    let mut out = Vec::with_capacity(1 + len_bytes.len());
    out.push(0x80 | u8::try_from(len_bytes.len()).expect("usize length-of-length fits in u8"));
    out.extend_from_slice(len_bytes);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    der_tlv(0x04, content)
}

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + content.len());
    // DER BIT STRING prefixes the payload with the number of unused bits in
    // the final octet. Zero means the payload ends on a byte boundary.
    body.push(0);
    body.extend_from_slice(content);
    der_tlv(0x03, &body)
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

fn der_oid(content: &[u8]) -> Vec<u8> {
    der_tlv(0x06, content)
}

fn der_integer_u8(value: u8) -> Vec<u8> {
    der_integer_bytes(&[value])
}

fn der_integer_biguint(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    der_integer_bytes(&bytes)
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut body = if let Some(first_nonzero) = bytes.iter().position(|&byte| byte != 0) {
        bytes[first_nonzero..].to_vec()
    } else {
        vec![0]
    };

    // DER INTEGER is signed two's-complement, so prepend a zero byte when the
    // high bit would otherwise mark the value as negative.
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }

    der_tlv(0x02, &body)
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_finished(&self) -> bool {
        self.pos == self.data.len()
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Option<&'a [u8]> {
        let tag = *self.data.get(self.pos)?;
        self.pos += 1;
        if tag != expected_tag {
            return None;
        }

        let first = *self.data.get(self.pos)?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            // DER short-form length.
            usize::from(first)
        } else {
            // DER long-form length: the low seven bits say how many following
            // octets encode the content length in big-endian order.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > core::mem::size_of::<usize>() {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..count {
                len = (len << 8) | usize::from(*self.data.get(self.pos)?);
                self.pos += 1;
            }
            len
        };

        let end = self.pos.checked_add(len)?;
        let content = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(content)
    }

    fn read_integer_biguint(&mut self) -> Option<BigUint> {
        let content = self.read_tlv(0x02)?;
        if content.is_empty() {
            return None;
        }
        // Negative DER INTEGER encodings are not valid for RSA key material.
        if content[0] & 0x80 != 0 {
            return None;
        }

        let body = if content.len() > 1 && content[0] == 0 {
            // Positive DER INTEGERs may carry a sign-extension zero byte when
            // the true high bit is set; strip that back off for BigUint.
            &content[1..]
        } else {
            content
        };
        Some(BigUint::from_be_bytes(body))
    }

    fn read_integer_small(&mut self) -> Option<u8> {
        let value = self.read_integer_biguint()?;
        let bytes = value.to_be_bytes();
        if bytes.len() != 1 {
            return None;
        }
        Some(bytes[0])
    }
}

#[cfg(test)]
mod tests {
    use super::{RsaPrivateKey, RsaPublicKey};
    use crate::public_key::rsa::Rsa;
    use crate::vt::BigUint;

    #[test]
    fn spki_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, _) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        let der = public.to_spki_der();
        let parsed = RsaPublicKey::from_spki_der(&der).expect("parse SPKI");
        assert_eq!(parsed, public);

        let pem = public.to_spki_pem();
        let parsed = RsaPublicKey::from_spki_pem(&pem).expect("parse SPKI PEM");
        assert_eq!(parsed, public);
    }

    #[test]
    fn pkcs8_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (_, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        let der = private.to_pkcs8_der();
        let parsed = RsaPrivateKey::from_pkcs8_der(&der).expect("parse PKCS#8");
        assert_eq!(parsed, private);

        let pem = private.to_pkcs8_pem();
        let parsed = RsaPrivateKey::from_pkcs8_pem(&pem).expect("parse PKCS#8 PEM");
        assert_eq!(parsed, private);
    }

    #[test]
    fn xml_roundtrip() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        let public_xml = public.to_xml();
        let private_xml = private.to_xml();
        assert_eq!(RsaPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(RsaPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn generated_key_xml_roundtrip() {
        let mut drbg = crate::CtrDrbgAes256::new(&[0xc1; 48]);
        let (public, private) = Rsa::generate(&mut drbg, 64).expect("generated RSA key");

        let public_der = public.to_spki_der();
        let public_xml = public.to_xml();
        let private_xml = private.to_xml();

        assert_eq!(
            RsaPublicKey::from_spki_der(&public_der),
            Some(public.clone())
        );
        assert_eq!(RsaPublicKey::from_xml(&public_xml), Some(public));
        assert_eq!(RsaPrivateKey::from_xml(&private_xml), Some(private));
    }

    #[test]
    fn openssl_accepts_spki_pem() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (public, _) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        let Some(expected) = crate::ct::run_openssl(
            &[
                "pkey", "-pubin", "-inform", "PEM", "-pubout", "-outform", "DER",
            ],
            public.to_spki_pem().as_bytes(),
        ) else {
            return;
        };

        assert_eq!(expected, public.to_spki_der());
    }

    #[test]
    fn openssl_accepts_pkcs8_pem() {
        let p = BigUint::from_u64(61);
        let q = BigUint::from_u64(53);
        let (_, private) = Rsa::from_primes(&p, &q).expect("valid RSA key");

        let Some(expected) = crate::ct::run_openssl(
            &["pkey", "-inform", "PEM", "-outform", "DER"],
            private.to_pkcs8_pem().as_bytes(),
        ) else {
            return;
        };

        assert_eq!(expected, private.to_pkcs1_der());
    }
}
