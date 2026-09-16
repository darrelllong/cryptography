//! Helpers shared by the integration tests.
//!
//! Every file under `tests/` is its own crate and cannot see the library's
//! `#[cfg(test)]` helpers, so this module compiles the file the unit tests
//! use, `src/test_utils/vectors.rs`, rather than a copy of it: a known answer
//! decodes identically in unit and integration tests by construction.
//!
//! Each test crate compiles this module separately and calls only some of the
//! helpers, so the ones a given crate leaves unused are not dead code.

#[allow(dead_code)]
#[path = "../../src/test_utils/vectors.rs"]
mod vectors;

#[allow(unused_imports)]
pub(crate) use vectors::{
    decode_hex, decode_hex_array, encode_hex, parse_vector_map, vector_fields,
};
