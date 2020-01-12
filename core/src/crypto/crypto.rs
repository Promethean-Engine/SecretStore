use parity_crypto::publickey::{Public, Secret, Signature, Random, Generator, ec_math_utils, KeyPair, recover, verify_public};

use crate::types::{EncryptedDocumentKey, Error};

#[derive(Clone)]
struct KeyGenerationArtifacts{
    id_numbers: Vec<Secret>,
    polynoms1: Vec<Vec<Secret>>,
    secrets1: Vec<Vec<Secret>>,
    public_shares: Vec<Public>,
    secret_shares: Vec<Secret>,
    joint_public: Public,
}

struct ZeroGenerationArtifacts{
    polynoms1: Vec<Vec<Secret>>,
    secret_shares: Vec<Secret>,
}

pub trait Signable {
    fn sign(&self, public_key: Public) -> Signature {
        let mut sig: Signature;
        sig
    }

    fn verify(&self, public_key: Public) -> bool {
        let mut verified:bool;
        verified
    }
}

pub fn generate_server_key() -> (Public,Secret) {
    // data gathered during initialization: derived_point (generate_random_scalar()) and id_numbers:Vec<_>
    // data generated during key dist: polynoms1 (prepare_polynoms1()) and secrets1:Vec<_> (compute_polynom())
    // verification: polynoms2, secrets2, publics:Vec<_>(public_values_generation())
    // verification: keys_verification()
    
    // data gathered during key gen: public_shares:Vec<_> (compute_public_share) and secret_shares:Vec<_>(compute_secret_shares())

    // joint public key as result of dist key gen: compute_joint_public(public_shares.iter()).unwrap()
}

pub fn generate_server_key_shares() -> Vec<Secret> {
    let mut server_key_shares: Vec<Secret>;
    server_key_shares
}

pub fn generate_document_key() -> (Public,Secret) {
    let doc_key:(Public,Secret);
    doc_key
}

pub fn encrypt_document_key(document_secret_key: Public, joint_public: Public) -> EncryptedDocumentKey {
    key_adapter(super::math::encrypt_secret(&joint_public, &document_secret_key).unwrap())
}

pub fn decrypt_document_key(key: EncryptedDocumentKey) -> Secret {
    let secret:Secret;
    secret
}

fn key_adapter(key: super::math::EncryptedSecret) -> EncryptedDocumentKey {
    
}