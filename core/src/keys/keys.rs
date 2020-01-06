use rand::rngs::OsRng;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

pub fn generate_server_key_share() {}

pub fn generate_document_key() {}

pub fn encrypt_document_key() {}

pub fn decrypt_document_key() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elliptic_key_encryption_example() {
        let mut alice_csprng = OsRng::new().unwrap();
        let alice_secret = EphemeralSecret::new(&mut alice_csprng);
        let alice_public = PublicKey::from(&alice_secret);
        let mut bob_csprng = OsRng::new().unwrap();
        let bob_secret = EphemeralSecret::new(&mut bob_csprng);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }
}
