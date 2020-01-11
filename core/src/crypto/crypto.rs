// extern crate parity_crypto as crypto;

use parity_crypto::publickey::{Public, Secret, Signature, Random, Generator, ec_math_utils, KeyPair, recover, verify_public};

// for reference and testing

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

fn generate_server_key() {
// fns prepare_polynoms1 and run_key_gen (554 and 569) in math


// fn prepare_polynoms1 (554): 

// 1. generate 2d mut Vector of random polynomials, called polynoms1 :

//let mut polynoms1: Vec<_> = (0..n).map(|_|, generate_random_polynom(t).unwrap()).collect(); 

// 2. if secret_required, do 3 and 4: 
// 3. for all polynoms,

// - secret_coeff1 = generated and unwrapped random scalar :
            // gen_rand_scalar is in math line 46
// let secret_coeff1 = generate_random_scalar().unwrap();  

// - unwrap Secret's (which is struct type) inner:H256 then subtract secret_coeff1 : 
// secret_required.sub(&secret_coeff!).unwrap();

// 4. end of loop, put secret_required in polynoms1
// poynoms1[n-1][0] = secret_required;

// 5. return polynoms1, type Vec<Vec<Secret>> 

}

// 
fn generate_server_key_shares((t,n):(isize,isize)) {

}

fn generate_document_key() {}

fn encrypt_document_key() {}

fn decrypt_document_key() {}

fn generate_signature() {}

fn verify_signature() {}