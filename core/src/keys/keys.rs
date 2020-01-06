use crate::math::*;
use crate::types::Error;
use crate::types::{DocumentKey, EncryptedDocumentKey};

pub fn generate_server_key_share() {}

pub fn generate_document_key() -> DocumentKey {}

pub fn encrypt_document_key(
    secret: &Public,
    joint_public: &Public,
) -> Result<EncryptedDocumentKey, Error> {
}

pub fn decrypt_document_key(
    encrypted_point: &Public,
    common_point: &Public,
    joint_secret: &Secret,
) -> Result<DocumentKey, Error> {
}
