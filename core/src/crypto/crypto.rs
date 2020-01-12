use parity_crypto::publickey::{Public, Secret, Signature, Random, Generator, ec_math_utils, KeyPair, recover, verify_public};

use crate::types::{EncryptedDocumentKey, Error};
use bytes::Bytes;

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

    }

    fn verify(&self, public_key: Public) -> bool {

    }
}


// run_key_gen, prepare_polynoms1
fn generate_random_scalar() -> Result<Secret, Error> {
    Ok(Random.generate()?.secret().clone())
}

/// Generate random polynom of threshold degree
fn generate_random_polynom(threshold: usize) -> Result<Vec<Secret>, Error> {
    (0..threshold + 1)
        .map(|_| generate_random_scalar())
        .collect()
}


// prepare_polynoms1 
fn prepare_polynoms1(t: usize, n: usize, secret_required: Option<Secret>) -> Vec<Vec<Secret>> {
	let mut polynoms1: Vec<_> = (0..n)
		.map(|_| generate_random_polynom(t).unwrap())
		.collect();
	// if we need specific secret to be shared, update polynoms so that sum of their free terms = required secret
	if let Some(mut secret_required) = secret_required {
		for polynom1 in polynoms1.iter_mut().take(n - 1) {
			let secret_coeff1 = generate_random_scalar().unwrap();
			secret_required.sub(&secret_coeff1).unwrap();
			polynom1[0] = secret_coeff1;
		}

		polynoms1[n - 1][0] = secret_required;
	}
	polynoms1
}

/// Compute value of polynom, using `node_number` as argument
fn compute_polynom(polynom: &[Secret], node_number: &Secret) -> Result<Secret, Error> {
    debug_assert!(!polynom.is_empty());

    let mut result = polynom[0].clone();
    for i in 1..polynom.len() {
        // calculate pow(node_number, i)
        let mut appendum = node_number.clone();
        appendum.pow(i)?;

        // calculate coeff * pow(point, i)
        appendum.mul(&polynom[i])?;

        // calculate result + coeff * pow(point, i)
        result.add(&appendum)?;
    }

    Ok(result)
}

/// Generate public keys for other participants.
fn public_values_generation(
    threshold: usize,
    derived_point: &Public,
    polynom1: &[Secret],
    polynom2: &[Secret],
) -> Result<Vec<Public>, Error> {
    debug_assert_eq!(polynom1.len(), threshold + 1);
    debug_assert_eq!(polynom2.len(), threshold + 1);

    // compute t+1 public values
    let mut publics = Vec::with_capacity(threshold + 1);
    for i in 0..threshold + 1 {
        let coeff1 = &polynom1[i];

        let mut multiplication1 = ec_math_utils::generation_point();
        ec_math_utils::public_mul_secret(&mut multiplication1, &coeff1)?;

        let coeff2 = &polynom2[i];
        let mut multiplication2 = derived_point.clone();
        ec_math_utils::public_mul_secret(&mut multiplication2, &coeff2)?;

        ec_math_utils::public_add(&mut multiplication1, &multiplication2)?;

        publics.push(multiplication1);
    }
    debug_assert_eq!(publics.len(), threshold + 1);

    Ok(publics)
}

fn compute_public_share(self_secret_value: &Secret) -> Result<Public, Error> {
    let mut public_share = ec_math_utils::generation_point();
    ec_math_utils::public_mul_secret(&mut public_share, self_secret_value)?;
    Ok(public_share)
}

/// Compute secret sum.
fn compute_secret_sum<'a, I>(mut secrets: I) -> Result<Secret, Error>
where
    I: Iterator<Item = &'a Secret>,
{
    let mut sum = secrets
        .next()
        .expect("compute_secret_sum is called when there's at least one secret; qed")
        .clone();
    while let Some(secret) = secrets.next() {
        sum.add(secret)?;
    }
    Ok(sum)
}


/// Compute public sum.
fn compute_public_sum<'a, I>(mut publics: I) -> Result<Public, Error>
where
    I: Iterator<Item = &'a Public>,
{
    let mut sum = publics
        .next()
        .expect("compute_public_sum is called when there's at least one public; qed")
        .clone();
    while let Some(public) = publics.next() {
        ec_math_utils::public_add(&mut sum, &public)?;
    }
    Ok(sum)
}

/// Compute secret share.
fn compute_secret_share<'a, I>(secret_values: I) -> Result<Secret, Error>
where
    I: Iterator<Item = &'a Secret>,
{
    compute_secret_sum(secret_values)
}

/// Compute joint public key.
fn compute_joint_public<'a, I>(public_shares: I) -> Result<Public, Error>
where
    I: Iterator<Item = &'a Public>,
{
    compute_public_sum(public_shares)
}



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

pub fn generate_server_key_shares() -> Vec<Secret> {

}

pub fn generate_document_key() -> (Public,Secret) {

}

pub fn encrypt_document_key(document_secret_key: Public, joint_public: Public) -> EncryptedDocumentKey {
    key_adapter(super::math::encrypt_secret(&joint_public, &document_secret_key).unwrap())
}

pub fn decrypt_document_key(key: EncryptedDocumentKey) -> Secret {
    let secret:Secret;
    secret
}

fn key_adapter(key: super::math::EncryptedSecret) -> EncryptedDocumentKey {
    key.encrypted_point.as_bytes().to_vec()
}

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
    fn test_signable_sign() {}

    #[test]
    fn test__signable_verify() {}
}