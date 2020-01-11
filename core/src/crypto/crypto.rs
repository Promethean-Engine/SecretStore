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

pub trait Signable {
    fn sign(&self, public_key: Public) -> Signature {}

    fn verify(&self, public_key: Public) -> bool {}
}

fn generate_server_key() -> (Public,Secret) {
// fns prepare_polynoms1 and run_key_gen (554 and 569) in math


// fn prepare_polynoms1 (554): 

/*
1. generate 2d mut Vector of random polynomials, called polynoms1 :

let mut polynoms1: Vec<_> = (0..n).map(|_|, generate_random_polynom(t).unwrap()).collect(); 


2. if secret_required, do 3 and 4: 
3. for all polynoms,

a) secret_coeff1 = generated and unwrapped random scalar :
    (gen_rand_scalar is in math line 46)
let secret_coeff1 = generate_random_scalar().unwrap();  

b) unwrap Secret's (which is struct type) inner:H256 then subtract secret_coeff1 : 
secret_required.sub(&secret_coeff!).unwrap();


4. end of loop, put secret_required in polynoms1

poynoms1[n-1][0] = secret_required;

5. return polynoms1, type Vec<Vec<Secret>> 
*/

// fn run_key_gen, returns KeyGenerationArtifacts as defined at the top of this file:

/* 
fn run_key_generation(
    t:usize,n:usize, 
    id_numbers: Option<vec<Secret>>, 
    secret_required: Option<Secret>
) -> KeyGenerationArtifacts

    // data gathered during init 
let derived_point = Random.generate().unwrap().public().clone();
let id_numbers: Vec<_> = match id_numbers{
    Some(id_numbers) => id_numbers,
    None => (0..n).map(|_| generate_random_scalar().unwrap()).collect), 
};

    //data generated during key distribution
let polynoms1 = prepare_polynoms1(t,n,secret_required);
let secrets1: Vec<_> = (0..n).map(|i| (0..n).map(|j| compute_polynom(&polynoms1[i], &id_numbers[j]).unwrap()).collect::<Vec<_>>()).collect();

// following data is used only on verification step
let polynoms2: Vec<_> = (0..n).map(|_| generate_random_polynom(t).unwrap()).collect();
let secrets2: Vec<_> = (0..n).map(|i| (0..n).map(|j| compute_polynom(&polynoms2[i], &id_numbers[j]).unwrap()).collect::<Vec<_>>()).collect();
let publics: Vec<_> = (0..n).map(|i| public_values_generation(t, &derived_point, &polynoms1[i], &polynoms2[i]).unwrap()).collect();

// keys verification
(0..n).for_each(|i| {
    (0..n)
        .filter(|&j| i != j)
        .for_each(|j| {
            assert!(keys_verification(t, &derived_point, &id_numbers[i], &secrets1[j][i], &secrets2[j][i], &publics[j]).unwrap());
        })
});

// data, generated during keys generation
let public_shares: Vec<_> = (0..n).map(|i| compute_public_share(&polynoms1[i][0]).unwrap()).collect();
let secret_shares: Vec<_> = (0..n).map(|i| compute_secret_share(secrets1.iter().map(|s| &s[i])).unwrap()).collect();

// joint public key, as a result of DKG
let joint_public = compute_joint_public(public_shares.iter()).unwrap();

// return 
KeyGenerationArtifacts {
    id_numbers: id_numbers,
    polynoms1: polynoms1,
    secrets1: secrets1,
    public_shares: public_shares,
    secret_shares: secret_shares,
    joint_public: joint_public,
}
*/
}

fn generate_server_key_shares() -> Vec<Secret> {

}

fn generate_document_key() -> (Public,Secret) {

}

// TODO Return type should be the encrypted document key representation
fn encrypt_document_key(document_secret_key: Secret, server_secret_key: Secret) {

}

// TODO Argument should be the encrypted document key representation
fn decrypt_document_key() -> Secret {

}