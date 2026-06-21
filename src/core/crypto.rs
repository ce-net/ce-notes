//! End-to-end encryption for CE Notes.
//!
//! Confidentiality is a pure **app-layer envelope**: the CE mesh, relays, and every other node see
//! only ciphertext plus an authenticated sender NodeId. Plaintext exists only inside an authorized
//! device. Two independent layers:
//!
//! * **Space content key** — one 32-byte XChaCha20-Poly1305 key per [`Space`](crate::core::Space).
//!   Every note/index CRDT update is sealed with it ([`seal`] / [`open`]). A 24-byte random nonce is
//!   generated per message, so reuse is statistically impossible.
//! * **Key wrapping** — the space key is wrapped *per member device* with an X25519 sealed box
//!   ([`wrap_key`] / [`unwrap_key`]): an ephemeral X25519 keypair does ECDH against the member's
//!   long-term X25519 public key, the shared secret is hashed to an AEAD key, and the space key is
//!   sealed under it. Only the holder of the member's X25519 secret can recover it.
//!
//! **Identity → X25519.** A device's CE NodeId is an Ed25519 public key. We derive an X25519
//! keypair from the *same* secret via the standard birational map (the `curve25519-dalek`
//! Ed25519→Montgomery conversion). The secret never leaves the device. The X25519 public key is
//! published in `MemberEntry` so others can wrap to it without ever seeing the Ed25519 secret.
//!
//! CE never decrypts anything here. Authenticity (who wrote an update) comes for free from the
//! node's Noise-verified `AppMessage.from`; confidentiality is entirely this module's job. The two
//! are orthogonal and both required.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroize;

/// A 32-byte symmetric space content key (XChaCha20-Poly1305).
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (192 bits — safe to pick at random per message).
pub const NONCE_LEN: usize = 24;

/// Domain-separation label mixed into the wrap-key KDF so a wrap secret can never collide with any
/// other use of an X25519 shared secret.
const WRAP_KDF_LABEL: &[u8] = b"ce-notes-wrap-v1";
/// Associated data bound into every space-content-key seal, pinning ciphertext to its key epoch.
const SEAL_AAD_PREFIX: &[u8] = b"ce-notes-seal-v1";

/// A space content key. Zeroized on drop so it does not linger in freed memory.
#[derive(Clone)]
pub struct SpaceKey(pub [u8; KEY_LEN]);

impl SpaceKey {
    /// Generate a fresh random space key from the OS CSPRNG.
    pub fn generate() -> SpaceKey {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        SpaceKey(k)
    }

    /// Construct from raw bytes (e.g. after unwrapping).
    pub fn from_bytes(b: [u8; KEY_LEN]) -> SpaceKey {
        SpaceKey(b)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.0).into())
    }
}

impl Drop for SpaceKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Seal `plaintext` under `key` for `epoch`, returning `(nonce, ciphertext)`. The epoch is bound in
/// as associated data, so ciphertext sealed under one key epoch cannot be silently reinterpreted
/// under another.
pub fn seal(key: &SpaceKey, epoch: u32, plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = seal_aad(epoch);
    let ct = key
        .cipher()
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| anyhow!("seal failed"))?;
    Ok((nonce, ct))
}

/// Open a ciphertext sealed with [`seal`] under the same `key` and `epoch`. Fails (rather than
/// returning garbage) if the key, epoch, nonce, or ciphertext do not match — AEAD authentication.
pub fn open(key: &SpaceKey, epoch: u32, nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Result<Vec<u8>> {
    let aad = seal_aad(epoch);
    key.cipher()
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| anyhow!("open failed: wrong key/epoch or tampered ciphertext"))
}

fn seal_aad(epoch: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD_PREFIX.len() + 4);
    aad.extend_from_slice(SEAL_AAD_PREFIX);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// A space key sealed to one device via an X25519 sealed box. Stored in plaintext in `SpaceMeta`
/// (it reveals nothing without the recipient's X25519 secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The key epoch this wraps (matches `SpaceMeta.key_epoch` at wrap time).
    pub epoch: u32,
    /// Ephemeral X25519 public key used for the ECDH (one-shot, never reused).
    pub ephemeral_pub: [u8; 32],
    /// XChaCha20-Poly1305 nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The sealed space key (32 bytes plaintext + 16-byte AEAD tag).
    pub ct: Vec<u8>,
}

/// Wrap `space_key` (at `epoch`) so only the holder of the X25519 secret matching `recipient_pub`
/// can recover it. Uses an ephemeral X25519 keypair (sealed-box construction).
pub fn wrap_key(recipient_pub: &[u8; 32], epoch: u32, space_key: &SpaceKey) -> Result<WrappedKey> {
    let mut eph_secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_secret_bytes);
    let eph_secret = XStaticSecret::from(eph_secret_bytes);
    eph_secret_bytes.zeroize();
    let eph_pub = XPublicKey::from(&eph_secret);

    let recipient = XPublicKey::from(*recipient_pub);
    let mut shared = eph_secret.diffie_hellman(&recipient).to_bytes();
    let wrap_key = kdf(&shared, eph_pub.as_bytes(), recipient_pub);
    shared.zeroize();

    let cipher = XChaCha20Poly1305::new((&wrap_key).into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &space_key.0, aad: WRAP_KDF_LABEL })
        .map_err(|_| anyhow!("wrap failed"))?;

    Ok(WrappedKey { epoch, ephemeral_pub: *eph_pub.as_bytes(), nonce, ct })
}

/// Unwrap a [`WrappedKey`] using this device's X25519 secret. Fails if the wrap was not addressed to
/// this device or has been tampered with.
pub fn unwrap_key(secret: &XStaticSecret, wrapped: &WrappedKey) -> Result<SpaceKey> {
    let our_pub = XPublicKey::from(secret);
    let eph_pub = XPublicKey::from(wrapped.ephemeral_pub);
    let mut shared = secret.diffie_hellman(&eph_pub).to_bytes();
    let wrap_key = kdf(&shared, &wrapped.ephemeral_pub, our_pub.as_bytes());
    shared.zeroize();

    let cipher = XChaCha20Poly1305::new((&wrap_key).into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload { msg: &wrapped.ct, aad: WRAP_KDF_LABEL },
        )
        .map_err(|_| anyhow!("unwrap failed: not addressed to this device or tampered"))?;
    let arr: [u8; KEY_LEN] =
        pt.as_slice().try_into().map_err(|_| anyhow!("unwrapped key has wrong length"))?;
    Ok(SpaceKey(arr))
}

/// Derive the AEAD wrap key from the ECDH shared secret, binding both public keys so a wrap is
/// pinned to its exact ephemeral/recipient pair.
fn kdf(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(WRAP_KDF_LABEL);
    h.update(shared);
    h.update(eph_pub);
    h.update(recipient_pub);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// This device's X25519 keypair, derived deterministically from its Ed25519 node secret.
///
/// The X25519 secret is the Ed25519 secret scalar (clamped); the X25519 public is the Montgomery
/// form of the Ed25519 public point. Two devices with the same node key always derive the same
/// X25519 keypair, and the published [`DeviceKeys::public`] is what others wrap to.
pub struct DeviceKeys {
    secret: XStaticSecret,
    public: [u8; 32],
}

impl DeviceKeys {
    /// Derive from a raw 32-byte Ed25519 secret seed (as returned by `Identity::secret_bytes`).
    pub fn from_ed25519_secret(ed_secret: &[u8; 32]) -> DeviceKeys {
        // Ed25519 secret scalar = first 32 bytes of SHA-512(seed), clamped. This is exactly how the
        // Ed25519 signing scalar is formed, so the X25519 secret corresponds to the same identity.
        let h = Sha512::digest(ed_secret);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h[..32]);
        // X25519 clamping (StaticSecret::from applies clamping on use, but clamp explicitly so the
        // public key we derive matches the Montgomery-converted Ed25519 public key).
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let secret = XStaticSecret::from(scalar);
        scalar.zeroize();
        let public = XPublicKey::from(&secret).to_bytes();
        DeviceKeys { secret, public }
    }

    /// Derive the X25519 *public* key that corresponds to an Ed25519 public NodeId, via the
    /// birational Edwards→Montgomery map. Lets a sender wrap to a peer knowing only its NodeId.
    pub fn x25519_public_from_node_id(node_id: &[u8; 32]) -> Result<[u8; 32]> {
        let compressed = CompressedEdwardsY(*node_id);
        let point = compressed
            .decompress()
            .ok_or_else(|| anyhow!("node id is not a valid Ed25519 public key"))?;
        Ok(point.to_montgomery().to_bytes())
    }

    /// This device's published X25519 public key.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Borrow the X25519 static secret (for unwrapping). Not exposed as bytes.
    pub fn secret(&self) -> &XStaticSecret {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SpaceKey::generate();
        let (nonce, ct) = seal(&key, 0, b"hello notes").unwrap();
        let pt = open(&key, 0, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hello notes");
    }

    #[test]
    fn open_fails_with_wrong_key() {
        let key = SpaceKey::generate();
        let other = SpaceKey::generate();
        let (nonce, ct) = seal(&key, 0, b"secret").unwrap();
        assert!(open(&other, 0, &nonce, &ct).is_err());
    }

    #[test]
    fn open_fails_with_wrong_epoch() {
        let key = SpaceKey::generate();
        let (nonce, ct) = seal(&key, 1, b"secret").unwrap();
        assert!(open(&key, 2, &nonce, &ct).is_err());
    }

    #[test]
    fn open_fails_on_tamper() {
        let key = SpaceKey::generate();
        let (nonce, mut ct) = seal(&key, 0, b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(open(&key, 0, &nonce, &ct).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let seed = [7u8; 32];
        let dev = DeviceKeys::from_ed25519_secret(&seed);
        let space_key = SpaceKey::generate();
        let wrapped = wrap_key(&dev.public(), 0, &space_key).unwrap();
        let recovered = unwrap_key(dev.secret(), &wrapped).unwrap();
        assert_eq!(recovered.0, space_key.0);
    }

    #[test]
    fn wrap_to_one_device_cannot_be_unwrapped_by_another() {
        let dev_a = DeviceKeys::from_ed25519_secret(&[1u8; 32]);
        let dev_b = DeviceKeys::from_ed25519_secret(&[2u8; 32]);
        let space_key = SpaceKey::generate();
        let wrapped = wrap_key(&dev_a.public(), 0, &space_key).unwrap();
        assert!(unwrap_key(dev_b.secret(), &wrapped).is_err());
    }

    #[test]
    fn ed25519_secret_derivation_is_deterministic() {
        let seed = [42u8; 32];
        let a = DeviceKeys::from_ed25519_secret(&seed);
        let b = DeviceKeys::from_ed25519_secret(&seed);
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn x25519_public_from_node_id_matches_derived_secret() {
        // Derive the keypair from a known Ed25519 seed, compute the matching node id (Ed25519
        // public), then check the Montgomery conversion of the node id equals the device's X25519
        // public key. This proves a sender can wrap to a peer knowing only its NodeId.
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk: VerifyingKey = sk.verifying_key();
        let node_id = vk.to_bytes();

        let dev = DeviceKeys::from_ed25519_secret(&seed);
        let from_node = DeviceKeys::x25519_public_from_node_id(&node_id).unwrap();
        assert_eq!(from_node, dev.public());
    }

    #[test]
    fn wrap_to_node_id_unwraps_with_device_secret() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        let seed = [11u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk: VerifyingKey = sk.verifying_key();
        let node_id = vk.to_bytes();

        let recipient_x = DeviceKeys::x25519_public_from_node_id(&node_id).unwrap();
        let space_key = SpaceKey::generate();
        let wrapped = wrap_key(&recipient_x, 3, &space_key).unwrap();

        let dev = DeviceKeys::from_ed25519_secret(&seed);
        let recovered = unwrap_key(dev.secret(), &wrapped).unwrap();
        assert_eq!(recovered.0, space_key.0);
        assert_eq!(wrapped.epoch, 3);
    }
}
