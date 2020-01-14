use parity_crypto::publickey::{
    ec_math_utils, recover, verify_public, Generator, KeyPair, Public, Random, Secret, Signature,
};

use crate::types::{EncryptedDocumentKey, Error};

use super::math::*;

pub fn generate_server_key(
    t: usize,
    n: usize,
    id_numbers: Option<Vec<Secret>>,
    secret_required: Option<Secret>,
) -> (Public, Vec<Secret>) {
    // dummy data generated during initialization
    let derived_point = Random.generate().unwrap().public().clone();
    let id_numbers: Vec<_> = match id_numbers {
        Some(id_numbers) => id_numbers,
        None => (0..n).map(|_| generate_random_scalar().unwrap()).collect(),
    };

    // data from distribution
    let polynoms1 = prepare_polynoms1(t, n, secret_required);
    let secrets1: Vec<_> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| compute_polynom(&polynoms1[i], &id_numbers[j]).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();

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
        .map(|i| public_values_generation(t, &derived_point, &polynoms1[i], &polynoms2[i]).unwrap())
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
    (joint_public, secret_shares)
}

pub fn generate_document_key(
    t: usize,
    n: usize,
    id_numbers: Option<Vec<Secret>>,
    secret_required: Option<Secret>,
) -> (Public, Vec<Secret>) {
    // dummy data generated during initialization
    let derived_point = Random.generate().unwrap().public().clone();
    let id_numbers: Vec<_> = match id_numbers {
        Some(id_numbers) => id_numbers,
        None => (0..n).map(|_| generate_random_scalar().unwrap()).collect(),
    };

    // data from distribution
    let polynoms1 = prepare_polynoms1(t, n, secret_required);
    let secrets1: Vec<_> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| compute_polynom(&polynoms1[i], &id_numbers[j]).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();

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
        .map(|i| public_values_generation(t, &derived_point, &polynoms1[i], &polynoms2[i]).unwrap())
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
    (joint_public, secret_shares)
}
use std::any::type_name;
fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

pub fn encrypt_document_key(
    document_secret_key: Public,
    joint_public: Public,
) -> EncryptedDocumentKey {
    key_adapter(super::math::encrypt_secret(&joint_public, &document_secret_key).unwrap())
}

pub fn decrypt_document_key(
    threshold: usize,
    access_key: &Secret,
    encrypted_point: &Public,
    joint_shadow_point: &Public,
) -> Public {
    super::math::decrypt_with_joint_shadow(
        threshold,
        &access_key,
        &encrypted_point,
        &joint_shadow_point,
    )
    .unwrap()
}

fn key_adapter(key: super::math::EncryptedSecret) -> EncryptedDocumentKey {
    key.encrypted_point.as_bytes().to_vec()
}


/* Other variable names
Curve is the curve

G = elliptic curve base point which generates subgroup of large prime order n 

n = int order of G; n * G = O, the identity element

dA = private key (random num) in [1, n-1]

QA = public key (calc'd by Curve); QA = dA * G

m = message to send

e = Hash(m)

z = leftmost (Ln) bits of e where where Ln is bit length of group order 
    //type hash

k = cryptographically secure rand int from [1,n-1]

(x,y) = curve point K*G = u1 * G + u2 * QA; cannot be O

r = x mod n (cannot be O); must get new k if = O

s = (inv(k))(z+r*dA)mod n ; if = O get new k 
    // compute shares for s portion of signature:
    // nonce_inv * (hash + secret * sig_r)

Signature: (r,s) or (r, -s mod n)

u1 = z*inv(s) mod n
u2 = r*inv(s) mod n 
*/


pub fn sign(
    t: usize,
    n: usize,
    joint_secret: Secret, 
    joint_nonce: Secret, 
    message_hash: primitive_types::H256
) -> Signature {
// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm    


// 1 hashed message to_scalar
let message_hash_scalar = to_scalar(message_hash.clone()).unwrap();
// 2 
// gen secret shares
// gen nonce artifacts which will be used for public vars

// 3 compute intermediary vars
//  - artifacts and nonce_artifacts (outputs of key_gen)
let artifacts = run_key_generation(t,n, None, Some(joint_secret));
let nonce_artifacts = run_key_generation(t,n, Some(artifacts.id_numbers.clone()), Some(joint_nonce));
    // // needs to output polynoms1, which is Vec<Vec<Secret> 

//  - nonce_public_shares which are joint into nonce_public (also output of key_gen)
let nonce_public_shares: Vec<_> = (0..n)
    .map(|i| compute_public_share(&nonce_artifacts.polynoms1[i][0]).unwrap())
    .collect();
// polynoms1 is Vec<Vec<Secrets>> 
// - nonce_public
let nonce_public = compute_joint_public(nonce_public_shares.iter()).unwrap();
//  -signature_r from (r,s) or (r, -s mod n) 
let signature_r = compute_ecdsa_r(&nonce_public).unwrap(); 

// 4 compute shares of inverted nonce so both nonce and inv(nonce) are unknown
let nonce_inv_shares = run_reciprocal_protocol(t, &nonce_artifacts);
// 5 multiply secret_shares * inv_nonce_shares
let mul_shares = run_multiplication_protocol(t, &artifacts.secret_shares, &nonce_inv_shares);

// 6 compute shares for s portion of signature such that 
//   nonce_inv * (hash + secret * sig_r)  i.e.: step 6 of signature 
//   s = (inv(k))(z+r*dA)mod n ; if = O get new k 
let double_t = 2 * t; 
let signature_s_shares: Vec<_> = (0..double_t + 1)
    .map(|i|{
        compute_ecdsa_s_share(
            &nonce_inv_shares[i],
            &mul_shares[i],
            &signature_r,
            &message_hash_scalar
        ).unwrap()
    }).collect(); 

// 7 compute sig_s from received shares 
let signature_s = compute_ecdsa_s(
    t, 
    &signature_s_shares, 
    &artifacts.id_numbers.iter().take(double_t + 1)
    .cloned().collect::<Vec<_>>()
).unwrap();

serialize_ecdsa_signature(&nonce_public, compute_ecdsa_r(&nonce_public).unwrap(), signature_s)
}

pub fn verify(public_key: Public, signature: Signature, message_hash: primitive_types::H256) -> bool {
    verify_public(&public_key, &signature, &message_hash).unwrap()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use primitive_types::H256;
    use std::any::type_name;

    #[test]
    fn test_key_generation() {
        let t: usize = 4;
        let n: usize = 5;

        let secret_hash = primitive_types::H256::random();
        let secret1 = Secret::from(secret_hash);
        let secret1_opt: Option<Secret> = Some(secret1);

        let mut secrets_vector_for_ids = vec![]; // <Option<Secret>>;
        let mut temp_hash;
        let mut temp_secret;
        // let mut temp_opt: Option<Secret>;
        for n in 0..5 {
            // create Vec of Secrets
            temp_hash = primitive_types::H256::random();
            temp_secret = Secret::from(temp_hash);
            // temp_opt = Some(temp_secret);
            secrets_vector_for_ids.push(temp_secret);
        }

        let keys = generate_document_key(t, n, Some(secrets_vector_for_ids), secret1_opt);
        // fn use these parameters: (usize,usize, Option<Vec<Secret>>, Option<Secret>)
    }

    fn to_array(bytes: &[u8]) -> [u8; 32] {
        let mut array = [0; 32];
        let bytes = &bytes[..array.len()];
        array.copy_from_slice(bytes);
        array
    }

    fn type_of<T>(_: T) -> &'static str {
        type_name::<T>()
    }

    #[test]
    fn test_encryption() {}

    #[test]
    fn test_decryption() {}

    #[test]
    fn test_sign() {
        let joint_secret: Secret = Random.generate().unwrap().secret().clone();
        let joint_nonce: Secret = Random.generate().unwrap().secret().clone();
        let message = H256::random();
        sign(3, 15, joint_secret, joint_nonce, message);
    }

    #[test]
    fn test_verify() {
        let joint_secret: Secret = Random.generate().unwrap().secret().clone();
        let joint_nonce: Secret = Random.generate().unwrap().secret().clone();
        let message = H256::random();
        let signature = sign(3, 15, joint_secret, joint_nonce, message);
        assert!(verify(recover(&signature, &message).unwrap(), signature, message))
    }
}
