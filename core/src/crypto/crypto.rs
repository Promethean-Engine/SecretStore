use parity_crypto::publickey::{Public, Secret, Signature, Random, Generator, ec_math_utils, KeyPair, recover, verify_public};

use crate::types::{EncryptedDocumentKey, Error};
use bytes::Bytes;

use super::math::*;

pub fn generate_server_key(
    t:usize, n:usize,
    id_numbers: Option<Vec<Secret>>,
    secret_required: Option<Secret>)-> (Vec<Public>, Vec<Secret>) 
{ 
    // dummy data generated during initialization
    let derived_point = Random.generate().unwrap().public().clone();
	let id_numbers: Vec<_> = match id_numbers {
		Some(id_numbers) => id_numbers,
		None => (0..n).map(|_| generate_random_scalar().unwrap()).collect(),
    };
    
    // data from distribution
    let polynoms1 = prepare_polynoms1(t,n,secret_required);
    let secrets1: Vec<_> = (0..n)
    .map(|i| {
        (0..n)
            .map(|j| compute_polynom(&polynoms1[i], &id_numbers[j]).unwrap())
            .collect::<Vec<_>>()
    }).collect();

    //data for verification (dummy data?)
    let polynoms2: Vec<_> = (0..n)
		.map(|_| generate_random_polynom(t).unwrap())
		.collect();
	let secrets2: Vec<_> = (0..n)
		.map(|i| {
			(0..n)
				.map(|j| compute_polynom(&polynoms2[i], &id_numbers[j]).unwrap())
				.collect::<Vec<_>>()
		})
		.collect();
	let publics: Vec<_> = (0..n)
		.map(|i| {
			public_values_generation(t, &derived_point, &polynoms1[i], &polynoms2[i]).unwrap()
		})
        .collect();

    // data from key generation 
	let public_shares: Vec<_> = (0..n)
		.map(|i| compute_public_share(&polynoms1[i][0]).unwrap())
		.collect();
	let secret_shares: Vec<_> = (0..n)
		.map(|i| compute_secret_share(secrets1.iter().map(|s| &s[i])).unwrap())
		.collect();

	// joint public key, as a result of DKG
	let joint_public = compute_joint_public(public_shares.iter()).unwrap();

    // generate (Vec<Public>,Vec<Secret>)
    (public_shares,secret_shares)
}

pub fn generate_document_key() -> (Public,Secret) {
}

pub fn encrypt_document_key(document_secret_key: Public, joint_public: Public) -> EncryptedDocumentKey {
    key_adapter(super::math::encrypt_secret(&joint_public, &document_secret_key).unwrap())
}

pub fn decrypt_document_key(
    threshold: usize,
    access_key: &Secret,
    encrypted_point: &Public,
    joint_shadow_point: &Public) -> Public {
        super::math::decrypt_with_joint_shadow(
            threshold,
            &access_key,
            &encrypted_point,
            &joint_shadow_point
        ).unwrap()
}

fn key_adapter(key: super::math::EncryptedSecret) -> EncryptedDocumentKey {
    key.encrypted_point.as_bytes().to_vec()
}

pub fn sign() {}

pub fn verify() {}

#[cfg(test)]
pub mod tests {
    #[test]
    fn test_key_generation() {}

    #[test]
    fn test_encryption() {

    }

    #[test]
    fn test_decryption() {}

    #[test]
    fn test_sign() {}

    #[test]
    fn test_verify() {}
}