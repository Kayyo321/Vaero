//! Argon2id key derivation for the `.crypt` container.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::format::FormatError;

/// Minimum accepted Argon2id memory cost, in KiB (8 MiB).
const MEMORY_KIB_MIN: u32 = 8_192;
/// Maximum accepted Argon2id memory cost, in KiB (1 GiB).
const MEMORY_KIB_MAX: u32 = 1_048_576;
/// Minimum accepted Argon2id iteration count.
const ITERATIONS_MIN: u32 = 1;
/// Maximum accepted Argon2id iteration count.
const ITERATIONS_MAX: u32 = 64;
/// Minimum accepted Argon2id parallelism.
const PARALLELISM_MIN: u32 = 1;
/// Maximum accepted Argon2id parallelism.
const PARALLELISM_MAX: u32 = 8;

/// Argon2id v1.3 cost parameters stored in the public container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB; accepted range 8 192..=1 048 576.
    pub memory_kib: u32,
    /// Iteration count; accepted range 1..=64.
    pub iterations: u32,
    /// Parallelism (lanes); accepted range 1..=8.
    pub parallelism: u32,
}

impl KdfParams {
    /// Writer defaults: 64 MiB memory, 3 iterations, 1 lane.
    pub const DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    /// Check the parameters against the documented bounds.
    ///
    /// Readers call this before allocating or deriving anything expensive so
    /// hostile containers cannot request dangerous resource levels.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::KdfBounds`] when any parameter is outside its
    /// accepted range.
    pub fn validate(&self) -> Result<(), FormatError> {
        let memory_ok = (MEMORY_KIB_MIN..=MEMORY_KIB_MAX).contains(&self.memory_kib);
        let iterations_ok = (ITERATIONS_MIN..=ITERATIONS_MAX).contains(&self.iterations);
        let parallelism_ok = (PARALLELISM_MIN..=PARALLELISM_MAX).contains(&self.parallelism);
        if memory_ok && iterations_ok && parallelism_ok {
            Ok(())
        } else {
            Err(FormatError::KdfBounds)
        }
    }
}

/// Derive the 32-byte key-encryption key from phrase entropy.
///
/// # Panics
///
/// Callers must run [`KdfParams::validate`] first; every parameter set inside
/// the documented bounds is accepted by Argon2, so construction and hashing
/// failures are impossible after successful validation.
pub(crate) fn derive_kek(
    entropy: &[u8],
    salt: &[u8; 32],
    params: &KdfParams,
) -> Zeroizing<[u8; 32]> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .expect("KDF parameters were validated against the format bounds");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(entropy, salt, kek.as_mut_slice())
        .expect("Argon2id with validated parameters and a 32-byte salt cannot fail");
    kek
}

#[cfg(test)]
mod tests {
    use super::{KdfParams, derive_kek};
    use crate::format::FormatError;

    /// Small in-bounds parameters keeping the test suite fast.
    const FAST: KdfParams = KdfParams {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn default_params_are_valid() {
        assert_eq!(KdfParams::DEFAULT.memory_kib, 65_536);
        assert_eq!(KdfParams::DEFAULT.iterations, 3);
        assert_eq!(KdfParams::DEFAULT.parallelism, 1);
        assert_eq!(KdfParams::DEFAULT.validate(), Ok(()));
    }

    #[test]
    fn validate_accepts_every_boundary() {
        for params in [
            KdfParams {
                memory_kib: 8_192,
                iterations: 1,
                parallelism: 1,
            },
            KdfParams {
                memory_kib: 1_048_576,
                iterations: 64,
                parallelism: 8,
            },
        ] {
            assert_eq!(params.validate(), Ok(()));
        }
    }

    #[test]
    fn validate_rejects_every_bound_violation() {
        let violations = [
            KdfParams {
                memory_kib: 8_191,
                ..FAST
            },
            KdfParams {
                memory_kib: 1_048_577,
                ..FAST
            },
            KdfParams {
                iterations: 0,
                ..FAST
            },
            KdfParams {
                iterations: 65,
                ..FAST
            },
            KdfParams {
                parallelism: 0,
                ..FAST
            },
            KdfParams {
                parallelism: 9,
                ..FAST
            },
        ];
        for params in violations {
            assert_eq!(params.validate(), Err(FormatError::KdfBounds));
        }
    }

    #[test]
    fn derive_is_deterministic_and_salt_sensitive() {
        let entropy = [7u8; 16];
        let salt_a = [1u8; 32];
        let salt_b = [2u8; 32];
        let first = derive_kek(&entropy, &salt_a, &FAST);
        let second = derive_kek(&entropy, &salt_a, &FAST);
        let third = derive_kek(&entropy, &salt_b, &FAST);
        assert_eq!(*first, *second);
        assert_ne!(*first, *third);
    }
}
