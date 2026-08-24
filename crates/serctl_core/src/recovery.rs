//! Profile recovery primitives for the v4 vault format.
//!
//! Recovery is deliberately 2-of-2: the vault retains one uniformly random
//! share and removable media retains the other.  Their XOR reconstructs only
//! an X25519 private scalar input; the resulting key is used exclusively to
//! unwrap profile [`KeyPackage`] values.  Recovery media is not an
//! authentication factor by itself.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const RECOVERY_MEDIA_VERSION: u32 = 1;

const RECOVERY_ID_BYTES: usize = 32;
const X25519_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const AEAD_TAG_BYTES: usize = 16;
const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_KEY_PACKAGE_BYTES: usize = 1024;
const MAX_RECOVERY_MEDIA_BYTES: usize = 1024;
const MAX_ENVELOPE_CIPHERTEXT_BYTES: usize = MAX_KEY_PACKAGE_BYTES + AEAD_TAG_BYTES;
const AAD_DOMAIN: &[u8] = b"serctl/recovery/profile-key-package/v2\0";
const HKDF_SALT: &[u8] = b"serctl/recovery/x25519-hkdf-sha256/v1\0";
const HKDF_INFO_DOMAIN: &[u8] = b"serctl/recovery/aead-key/v2\0";
const MEDIA_CHECKSUM_DOMAIN: &[u8] = b"serctl/recovery/media-checksum/v1\0";

/// The complete profile key package protected by both the profile passphrase
/// and the recovery envelope in vault v4.  It is intentionally non-Debug and
/// wipes its key bytes on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct KeyPackage {
    pub profile_id: [u8; 16],
    pub generation: u64,
    pub dek: [u8; 32],
    pub auth_seed: [u8; 32],
}

/// Public vault-wide recovery configuration.  The private scalar input is
/// never serialized as one value: it exists only while two shares are joined.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConfig {
    /// Canonical padded Base64 encoding of 32 random bytes.
    pub recovery_id: String,
    /// Canonical padded Base64 encoding of the 32-byte X25519 public key.
    pub public_key: String,
}

/// One profile key package sealed to [`RecoveryConfig::public_key`].
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEnvelope {
    /// Canonical padded Base64 encoding of the ephemeral X25519 public key.
    pub ephemeral_public: String,
    /// Canonical padded Base64 encoding of the 12-byte AEAD nonce.
    pub nonce: String,
    /// Canonical padded Base64 encoding of the bounded AEAD ciphertext.
    pub ct: String,
}

/// Portable removable-media half of the 2-of-2 recovery secret.
///
/// `checksum` detects accidentally selected or damaged media.  It is not a
/// MAC and must never be treated as proof that the media is trusted.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMedia {
    pub version: u32,
    pub recovery_id: String,
    /// Canonical padded Base64 encoding of one 32-byte XOR share.
    pub share: String,
    /// Canonical padded Base64 SHA-256 checksum of the preceding fields.
    pub checksum: String,
}

/// Generate a public recovery configuration, its vault-local XOR share, and
/// the canonical JSON bytes that must be written to new removable media.
pub type GeneratedRecovery = (
    RecoveryConfig,
    Zeroizing<[u8; X25519_KEY_BYTES]>,
    Zeroizing<Vec<u8>>,
);

pub fn generate_recovery() -> Result<GeneratedRecovery> {
    let mut private_input = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
    let mut local_share = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
    let mut media_share = Zeroizing::new([0_u8; X25519_KEY_BYTES]);

    // The chance of drawing a zero share is negligible, but rejecting it
    // makes the promised 2-of-2 property structural rather than probabilistic.
    loop {
        OsRng.fill_bytes(private_input.as_mut());
        canonicalize_x25519_private_input(&mut private_input);
        OsRng.fill_bytes(local_share.as_mut());
        for index in 0..X25519_KEY_BYTES {
            media_share[index] = private_input[index] ^ local_share[index];
        }
        if !is_all_zero(&local_share) && !is_all_zero(&media_share) {
            break;
        }
    }

    let recipient_public = MontgomeryPoint::mul_base_clamped(*private_input).to_bytes();
    let mut recovery_id = [0_u8; RECOVERY_ID_BYTES];
    OsRng.fill_bytes(&mut recovery_id);

    let config = RecoveryConfig {
        recovery_id: B64.encode(recovery_id),
        public_key: B64.encode(recipient_public),
    };
    recovery_id.zeroize();

    let mut media = RecoveryMedia {
        version: RECOVERY_MEDIA_VERSION,
        recovery_id: config.recovery_id.clone(),
        share: B64.encode(media_share.as_ref()),
        checksum: String::new(),
    };
    media.checksum = media_checksum(&media)?;
    let media_json = serialize_recovery_media(&media)?;
    validate_recovery_config(&config)?;
    Ok((config, local_share, media_json))
}

/// Seal a profile key package to the public recovery key.
pub fn seal_package(
    config: &RecoveryConfig,
    profile_name: &str,
    profile_id: &[u8; 16],
    generation: u64,
    package: &KeyPackage,
) -> Result<RecoveryEnvelope> {
    validate_recovery_config(config)?;
    validate_profile_name(profile_name)?;
    if package.profile_id != *profile_id || package.generation != generation {
        bail!("key-package identity does not match its recovery context");
    }

    let recipient_public = decode_base64_fixed::<X25519_KEY_BYTES>(
        "recovery recipient public key",
        &config.public_key,
    )?;
    let mut ephemeral_private = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
    OsRng.fill_bytes(ephemeral_private.as_mut());
    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral_private).to_bytes();
    let shared = Zeroizing::new(
        MontgomeryPoint(*recipient_public)
            .mul_clamped(*ephemeral_private)
            .to_bytes(),
    );
    reject_all_zero_shared(&shared)?;

    let aad = recovery_aad(
        config,
        profile_name,
        profile_id,
        generation,
        &ephemeral_public,
        &recipient_public,
    )?;
    let aead_key = derive_aead_key(&shared, &aad)?;
    let mut nonce_bytes = [0_u8; AEAD_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);

    let plaintext = serialize_key_package(package)?;
    let cipher = ChaCha20Poly1305::new_from_slice(aead_key.as_ref())
        .map_err(|_| anyhow!("initialize recovery envelope cipher"))?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| anyhow!("seal profile recovery key package"))?,
    );
    if ciphertext.len() > MAX_ENVELOPE_CIPHERTEXT_BYTES {
        nonce_bytes.zeroize();
        bail!("sealed profile recovery key package exceeds its size limit");
    }

    let envelope = RecoveryEnvelope {
        ephemeral_public: B64.encode(ephemeral_public),
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ciphertext.as_slice()),
    };
    nonce_bytes.zeroize();
    validate_recovery_envelope(&envelope)?;
    Ok(envelope)
}

/// Open a profile key package after reconstructing the recovery private input
/// from the vault-local share and canonical removable-media JSON.
pub fn open_package(
    config: &RecoveryConfig,
    profile_name: &str,
    profile_id: &[u8; 16],
    generation: u64,
    envelope: &RecoveryEnvelope,
    local_share: &[u8; X25519_KEY_BYTES],
    media_bytes: &[u8],
) -> Result<KeyPackage> {
    validate_recovery_config(config)?;
    validate_recovery_envelope(envelope)?;
    validate_profile_name(profile_name)?;
    if is_all_zero(local_share) {
        bail!("vault-local recovery share must not be all zero");
    }

    let media = parse_recovery_media(media_bytes)?;
    if media.recovery_id.as_bytes() != config.recovery_id.as_bytes() {
        bail!("recovery media does not belong to this recovery configuration");
    }
    let media_share =
        decode_base64_fixed::<X25519_KEY_BYTES>("recovery-media share", &media.share)?;
    let private_input = combine_xor_shares(local_share, &media_share)?;
    validate_canonical_x25519_private_input(&private_input)?;

    let recipient_public = decode_base64_fixed::<X25519_KEY_BYTES>(
        "recovery recipient public key",
        &config.public_key,
    )?;
    let derived_public = MontgomeryPoint::mul_base_clamped(*private_input).to_bytes();
    if !bool::from(derived_public.ct_eq(&*recipient_public)) {
        bail!("recovery shares do not reconstruct this recovery configuration");
    }

    let ephemeral_public = decode_base64_fixed::<X25519_KEY_BYTES>(
        "recovery ephemeral public key",
        &envelope.ephemeral_public,
    )?;
    let shared = Zeroizing::new(
        MontgomeryPoint(*ephemeral_public)
            .mul_clamped(*private_input)
            .to_bytes(),
    );
    reject_all_zero_shared(&shared)?;
    let aad = recovery_aad(
        config,
        profile_name,
        profile_id,
        generation,
        &ephemeral_public,
        &recipient_public,
    )?;
    let aead_key = derive_aead_key(&shared, &aad)?;
    let nonce =
        decode_base64_fixed::<AEAD_NONCE_BYTES>("recovery envelope nonce", &envelope.nonce)?;
    let ciphertext = decode_base64_bounded(
        "recovery envelope ciphertext",
        &envelope.ct,
        AEAD_TAG_BYTES,
        MAX_ENVELOPE_CIPHERTEXT_BYTES,
    )?;

    let cipher = ChaCha20Poly1305::new_from_slice(aead_key.as_ref())
        .map_err(|_| anyhow!("initialize recovery envelope cipher"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce.as_ref()),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| anyhow!("recovery envelope authentication failed"))?,
    );
    let package = parse_key_package(&plaintext)?;
    if package.profile_id != *profile_id || package.generation != generation {
        bail!("recovered key-package identity does not match its recovery context");
    }
    Ok(package)
}

/// Reconstruct a 32-byte secret from exactly two XOR shares.
pub fn combine_xor_shares(
    local_share: &[u8; X25519_KEY_BYTES],
    media_share: &[u8; X25519_KEY_BYTES],
) -> Result<Zeroizing<[u8; X25519_KEY_BYTES]>> {
    if is_all_zero(local_share) || is_all_zero(media_share) {
        bail!("recovery shares must not be all zero");
    }
    let mut combined = Zeroizing::new([0_u8; X25519_KEY_BYTES]);
    for index in 0..X25519_KEY_BYTES {
        combined[index] = local_share[index] ^ media_share[index];
    }
    Ok(combined)
}

pub fn validate_recovery_config(config: &RecoveryConfig) -> Result<()> {
    let _id = decode_base64_fixed::<RECOVERY_ID_BYTES>("recovery id", &config.recovery_id)?;
    let _public = decode_base64_fixed::<X25519_KEY_BYTES>(
        "recovery recipient public key",
        &config.public_key,
    )?;
    Ok(())
}

pub fn validate_recovery_envelope(envelope: &RecoveryEnvelope) -> Result<()> {
    let _ephemeral = decode_base64_fixed::<X25519_KEY_BYTES>(
        "recovery ephemeral public key",
        &envelope.ephemeral_public,
    )?;
    let _nonce =
        decode_base64_fixed::<AEAD_NONCE_BYTES>("recovery envelope nonce", &envelope.nonce)?;
    let _ciphertext = decode_base64_bounded(
        "recovery envelope ciphertext",
        &envelope.ct,
        AEAD_TAG_BYTES,
        MAX_ENVELOPE_CIPHERTEXT_BYTES,
    )?;
    Ok(())
}

pub fn validate_recovery_media(media: &RecoveryMedia) -> Result<()> {
    if media.version != RECOVERY_MEDIA_VERSION {
        bail!("unsupported recovery-media version {}", media.version);
    }
    let _id = decode_base64_fixed::<RECOVERY_ID_BYTES>("recovery id", &media.recovery_id)?;
    let share = decode_base64_fixed::<X25519_KEY_BYTES>("recovery-media share", &media.share)?;
    if is_all_zero(&share) {
        bail!("recovery-media share must not be all zero");
    }
    let provided = decode_base64_fixed::<32>("recovery-media checksum", &media.checksum)?;
    let expected_encoded = Zeroizing::new(media_checksum(media)?);
    let expected =
        decode_base64_fixed::<32>("expected recovery-media checksum", &expected_encoded)?;
    if !bool::from(provided.ct_eq(&*expected)) {
        bail!("recovery-media checksum mismatch");
    }
    Ok(())
}

/// Parse only the exact compact JSON representation emitted by
/// [`serialize_recovery_media`].  Whitespace, reordered/unknown fields,
/// trailing input, and alternate Base64 spellings are rejected.
pub fn parse_recovery_media(bytes: &[u8]) -> Result<RecoveryMedia> {
    if bytes.is_empty() || bytes.len() > MAX_RECOVERY_MEDIA_BYTES {
        bail!("recovery-media JSON is empty or exceeds its size limit");
    }
    let media: RecoveryMedia =
        serde_json::from_slice(bytes).context("parse recovery-media JSON")?;
    validate_recovery_media(&media)?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&media).context("serialize canonical recovery-media JSON")?,
    );
    if canonical.len() != bytes.len() || !bool::from(canonical.as_slice().ct_eq(bytes)) {
        bail!("recovery-media JSON is not in canonical form");
    }
    Ok(media)
}

pub fn serialize_recovery_media(media: &RecoveryMedia) -> Result<Zeroizing<Vec<u8>>> {
    validate_recovery_media(media)?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(media).context("serialize canonical recovery-media JSON")?,
    );
    if encoded.is_empty() || encoded.len() > MAX_RECOVERY_MEDIA_BYTES {
        bail!("recovery-media JSON is empty or exceeds its size limit");
    }
    Ok(encoded)
}

fn validate_profile_name(profile_name: &str) -> Result<()> {
    if profile_name.is_empty() || profile_name.len() > MAX_PROFILE_ID_BYTES {
        bail!("recovery profile id must contain 1 to {MAX_PROFILE_ID_BYTES} bytes");
    }
    if profile_name.chars().any(char::is_control) {
        bail!("recovery profile id must not contain control characters");
    }
    Ok(())
}

fn serialize_key_package(package: &KeyPackage) -> Result<Zeroizing<Vec<u8>>> {
    let encoded =
        Zeroizing::new(serde_json::to_vec(package).context("serialize recovery key package")?);
    if encoded.is_empty() || encoded.len() > MAX_KEY_PACKAGE_BYTES {
        bail!("recovery key package is empty or exceeds its size limit");
    }
    Ok(encoded)
}

fn parse_key_package(bytes: &[u8]) -> Result<KeyPackage> {
    if bytes.is_empty() || bytes.len() > MAX_KEY_PACKAGE_BYTES {
        bail!("recovery key package is empty or exceeds its size limit");
    }
    let package: KeyPackage =
        serde_json::from_slice(bytes).context("parse recovered key package")?;
    let canonical = serialize_key_package(&package)?;
    if canonical.len() != bytes.len() || !bool::from(canonical.as_slice().ct_eq(bytes)) {
        bail!("recovered key package is not canonically encoded");
    }
    Ok(package)
}

fn recovery_aad(
    config: &RecoveryConfig,
    profile_name: &str,
    profile_id: &[u8; 16],
    generation: u64,
    ephemeral_public: &[u8; X25519_KEY_BYTES],
    recipient_public: &[u8; X25519_KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>> {
    let recovery_id = decode_base64_fixed::<RECOVERY_ID_BYTES>("recovery id", &config.recovery_id)?;
    let mut aad = Zeroizing::new(Vec::with_capacity(
        AAD_DOMAIN.len()
            + 4
            + recovery_id.len()
            + 4
            + profile_name.len()
            + profile_id.len()
            + 8
            + X25519_KEY_BYTES * 2,
    ));
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&RECOVERY_MEDIA_VERSION.to_be_bytes());
    append_length_prefixed(&mut aad, recovery_id.as_ref())?;
    append_length_prefixed(&mut aad, profile_name.as_bytes())?;
    aad.extend_from_slice(profile_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient_public);
    Ok(aad)
}

fn derive_aead_key(shared: &[u8; X25519_KEY_BYTES], aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    reject_all_zero_shared(shared)?;
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut info = Zeroizing::new(Vec::with_capacity(HKDF_INFO_DOMAIN.len() + aad.len()));
    info.extend_from_slice(HKDF_INFO_DOMAIN);
    info.extend_from_slice(aad);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| anyhow!("derive recovery envelope key"))?;
    Ok(key)
}

fn media_checksum(media: &RecoveryMedia) -> Result<String> {
    if media.version != RECOVERY_MEDIA_VERSION {
        bail!("unsupported recovery-media version {}", media.version);
    }
    let recovery_id = decode_base64_fixed::<RECOVERY_ID_BYTES>("recovery id", &media.recovery_id)?;
    let share = decode_base64_fixed::<X25519_KEY_BYTES>("recovery-media share", &media.share)?;
    let mut input = Zeroizing::new(Vec::with_capacity(
        MEDIA_CHECKSUM_DOMAIN.len() + 4 + 4 + recovery_id.len() + 4 + share.len(),
    ));
    input.extend_from_slice(MEDIA_CHECKSUM_DOMAIN);
    input.extend_from_slice(&media.version.to_be_bytes());
    append_length_prefixed(&mut input, recovery_id.as_ref())?;
    append_length_prefixed(&mut input, share.as_ref())?;
    let mut digest: [u8; 32] = Sha256::digest(input.as_slice()).into();
    let encoded = B64.encode(digest);
    digest.zeroize();
    Ok(encoded)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length =
        u32::try_from(value.len()).map_err(|_| anyhow!("recovery context is too large"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_base64_fixed<const N: usize>(label: &str, encoded: &str) -> Result<Zeroizing<[u8; N]>> {
    let expected_encoded_len = N.div_ceil(3) * 4;
    if encoded.len() != expected_encoded_len {
        bail!("{label} must canonically encode exactly {N} bytes");
    }
    let decoded = Zeroizing::new(
        B64.decode(encoded)
            .with_context(|| format!("decode {label} as padded Base64"))?,
    );
    if decoded.len() != N {
        bail!("{label} must canonically encode exactly {N} bytes");
    }
    let canonical = Zeroizing::new(B64.encode(decoded.as_slice()));
    if canonical.as_bytes() != encoded.as_bytes() {
        bail!("{label} must use canonical padded Base64");
    }
    let mut value = Zeroizing::new([0_u8; N]);
    value.copy_from_slice(decoded.as_slice());
    Ok(value)
}

fn decode_base64_bounded(
    label: &str,
    encoded: &str,
    min_decoded: usize,
    max_decoded: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let max_encoded = max_decoded.div_ceil(3) * 4;
    if encoded.is_empty() || encoded.len() > max_encoded || !encoded.len().is_multiple_of(4) {
        bail!("{label} is empty, oversized, or not padded Base64");
    }
    let decoded = Zeroizing::new(
        B64.decode(encoded)
            .with_context(|| format!("decode {label} as padded Base64"))?,
    );
    if decoded.len() < min_decoded || decoded.len() > max_decoded {
        bail!("{label} decoded length is outside its allowed range");
    }
    let canonical = Zeroizing::new(B64.encode(decoded.as_slice()));
    if canonical.as_bytes() != encoded.as_bytes() {
        bail!("{label} must use canonical padded Base64");
    }
    Ok(decoded)
}

fn reject_all_zero_shared(shared: &[u8; X25519_KEY_BYTES]) -> Result<()> {
    if is_all_zero(shared) {
        bail!("X25519 produced an invalid all-zero shared secret");
    }
    Ok(())
}

fn canonicalize_x25519_private_input(value: &mut [u8; X25519_KEY_BYTES]) {
    // RFC 7748 clamping.  Persisting only this canonical representation is
    // important for 2-of-2 recovery: otherwise a wrong share that changes one
    // of the five ignored bits could still produce the same X25519 public key.
    value[0] &= 248;
    value[31] &= 127;
    value[31] |= 64;
}

fn validate_canonical_x25519_private_input(value: &[u8; X25519_KEY_BYTES]) -> Result<()> {
    let mut canonical = Zeroizing::new(*value);
    canonicalize_x25519_private_input(&mut canonical);
    if !bool::from(value.ct_eq(&*canonical)) {
        bail!("recovery shares do not reconstruct a canonical X25519 private key");
    }
    Ok(())
}

fn is_all_zero(value: &[u8; X25519_KEY_BYTES]) -> bool {
    bool::from(value.ct_eq(&[0_u8; X25519_KEY_BYTES]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_ID: [u8; 16] = [0x42; 16];

    fn package(generation: u64) -> KeyPackage {
        KeyPackage {
            profile_id: PROFILE_ID,
            generation,
            dek: [0x31; 32],
            auth_seed: [0xa7; 32],
        }
    }

    fn setup(
        profile: &str,
        generation: u64,
    ) -> (
        RecoveryConfig,
        Zeroizing<[u8; 32]>,
        Zeroizing<Vec<u8>>,
        RecoveryEnvelope,
    ) {
        let (config, local, media) = generate_recovery().unwrap();
        let envelope = seal_package(
            &config,
            profile,
            &PROFILE_ID,
            generation,
            &package(generation),
        )
        .unwrap();
        (config, local, media, envelope)
    }

    #[test]
    fn recovery_round_trip_preserves_the_key_package() {
        let (config, local, media, envelope) = setup("prod", 7);
        let opened =
            open_package(&config, "prod", &PROFILE_ID, 7, &envelope, &local, &media).unwrap();
        assert_eq!(opened.generation, 7);
        assert_eq!(opened.dek, [0x31; 32]);
        assert_eq!(opened.auth_seed, [0xa7; 32]);
    }

    #[test]
    fn wrong_local_share_is_rejected_before_decryption() {
        let (config, mut local, media, envelope) = setup("prod", 7);
        local[0] ^= 1;
        let error = open_package(&config, "prod", &PROFILE_ID, 7, &envelope, &local, &media)
            .err()
            .expect("wrong share must fail closed");
        assert!(error.to_string().contains("do not reconstruct"));
    }

    #[test]
    fn wrong_generation_context_cannot_open_an_envelope() {
        let (config, local, media, envelope) = setup("prod", 7);
        assert!(open_package(&config, "prod", &PROFILE_ID, 8, &envelope, &local, &media).is_err());
    }

    #[test]
    fn ciphertext_tampering_is_authenticated() {
        let (config, local, media, mut envelope) = setup("prod", 7);
        let mut ciphertext = B64.decode(&envelope.ct).unwrap();
        ciphertext[0] ^= 0x80;
        envelope.ct = B64.encode(&ciphertext);
        ciphertext.zeroize();
        let error = open_package(&config, "prod", &PROFILE_ID, 7, &envelope, &local, &media)
            .err()
            .expect("tampered ciphertext must fail closed");
        assert!(error.to_string().contains("authentication failed"));
    }

    #[test]
    fn all_zero_x25519_shared_secrets_are_rejected() {
        let (mut config, _, _, _) = setup("prod", 7);
        config.public_key = B64.encode([0_u8; 32]);
        let error = seal_package(&config, "prod", &PROFILE_ID, 7, &package(7))
            .err()
            .expect("low-order public point must fail closed");
        assert!(error.to_string().contains("all-zero shared secret"));
    }

    #[test]
    fn envelope_is_cryptographically_bound_to_one_profile() {
        let (config, local, media, envelope) = setup("prod", 7);
        assert!(open_package(&config, "stage", &PROFILE_ID, 7, &envelope, &local, &media).is_err());
    }

    #[test]
    fn media_and_envelopes_reject_noncanonical_encodings() {
        let (config, local, media, mut envelope) = setup("prod", 7);
        envelope.nonce.pop();
        assert!(validate_recovery_envelope(&envelope).is_err());

        let mut padded_json = media.to_vec();
        padded_json.push(b'\n');
        assert!(parse_recovery_media(&padded_json).is_err());

        let parsed = parse_recovery_media(&media).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&media).unwrap();
        value["share"] = serde_json::Value::String(parsed.share.trim_end_matches('=').to_owned());
        let noncanonical = serde_json::to_vec(&value).unwrap();
        assert!(open_package(
            &config,
            "prod",
            &PROFILE_ID,
            7,
            &envelope,
            &local,
            &noncanonical,
        )
        .is_err());
    }

    #[test]
    fn media_checksum_detects_the_wrong_removable_share() {
        let (_, _, media, _) = setup("prod", 7);
        let mut parsed: RecoveryMedia = serde_json::from_slice(&media).unwrap();
        let mut share = B64.decode(&parsed.share).unwrap();
        share[0] ^= 1;
        parsed.share = B64.encode(&share);
        share.zeroize();
        let modified = serde_json::to_vec(&parsed).unwrap();
        assert!(parse_recovery_media(&modified).is_err());
    }
}
