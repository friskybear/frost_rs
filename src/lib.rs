use pyo3::{pymodule, types::PyModule, wrap_pyfunction, wrap_pymodule, PyResult, Python};

mod utility_module_secp256k1 {
    use base64::prelude::*;
    use frost_secp256k1 as frost_utility;
    use frost_utility::{
        keys::{
            dkg::{round1::Package as Round1Package, round2::Package as Round2Package},
            repairable::{repair_share_step_2, repair_share_step_3},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        serde::Serialize,
        Ciphersuite, Field, Group, Identifier, Secp256K1Sha256, Signature,
    };
    use pyo3::prelude::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub type CrateCiphersuite = Secp256K1Sha256;
    pub type Scalar = <<<Secp256K1Sha256 as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

    #[pyfunction]
    pub fn get_key(min: u16, max: u16) -> BTreeMap<String, String> {
        let rng = thread_rng();
        let (shares, _pubkey_package) = frost_utility::keys::generate_with_dealer(
            max,
            min,
            frost_utility::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        shares
            .into_iter()
            .map(|f| {
                (
                    BASE64_URL_SAFE.encode(f.0.serialize()),
                    BASE64_URL_SAFE.encode(f.1.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn get_dkg_get_coefficient_commitment(package: String) -> String {
        let coefficient_commitment = frost_utility::keys::dkg::round1::Package::deserialize(
            &BASE64_URL_SAFE.decode(package).unwrap(),
        )
        .unwrap()
        .commitment()
        .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn get_gen_with_dealer_coefficient_commitment(secret_share: String) -> String {
        let coefficient_commitment =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap())
                .unwrap()
                .commitment()
                .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn gen_key_package(secret_share: String) -> String {
        BASE64_URL_SAFE.encode(
            KeyPackage::try_from(
                SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap()).unwrap(),
            )
            .unwrap()
            .serialize()
            .unwrap(),
        )
    }
    #[pyfunction]
    pub fn print_key(key: String) {
        println!(
            "{:?}",
            KeyPackage::deserialize(&BASE64_URL_SAFE.decode(key).unwrap()).unwrap()
        );
    }
    #[pyfunction]
    pub fn construct(share: BTreeMap<String, String>) {
        let arr: [u8; 32] = BASE64_URL_SAFE
            .decode(share.keys().next().unwrap())
            .unwrap()[..]
            .try_into()
            .unwrap();
        println!(
            "\nback:\n{:?}\n",
            (
                Identifier::deserialize(&arr).unwrap(),
                SecretShare::deserialize(
                    &BASE64_URL_SAFE
                        .decode(share.values().next().unwrap())
                        .unwrap()
                )
            )
        );
    }

    #[derive(Serialize, Deserialize)]
    struct SecretShareCustom1 {
        commitment: Vec<Vec<u8>>,
        coefficent: Vec<String>,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn get_id() -> String {
        let mut bytes = [0u8; 64];
        thread_rng().fill_bytes(&mut bytes);
        let id = Identifier::derive(&bytes).unwrap().serialize();
        BASE64_URL_SAFE.encode(id)
    }
    #[pyfunction]
    pub fn round1(id: String, min: u16, max: u16) -> (String, String) {
        let rng = thread_rng();
        let id_deserialized =
            Identifier::deserialize(BASE64_URL_SAFE.decode(&id).unwrap()[..].try_into().unwrap())
                .unwrap();

        let (round1_secret_package, round1_package) =
            frost_utility::keys::dkg::part1(id_deserialized, max, min, rng).unwrap();
        let secret_share = SecretShareCustom1 {
            commitment: round1_secret_package
                .commitment()
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            coefficent: round1_secret_package
                .coefficients()
                .iter()
                .map(|f| serde_json::to_string(f).unwrap())
                .collect::<Vec<String>>(),
            id,
            min,
            max,
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&secret_share).unwrap()),
            BASE64_URL_SAFE.encode(round1_package.serialize().unwrap()),
        )
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct SecretShareCustom2 {
        commitment: Vec<Vec<u8>>,
        secret_share: String,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn round2(
        secret_package: String,
        round1_packages: BTreeMap<String, String>,
    ) -> (String, BTreeMap<String, String>) {
        let secret_custom: SecretShareCustom1 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(secret_package).unwrap()).unwrap();
        let id = secret_custom.id.clone();
        let secret_package_deserialized = frost_utility::keys::dkg::round1::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            coefficients: secret_custom
                .coefficent
                .iter()
                .map(|f| serde_json::from_str(f).unwrap())
                .collect(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 33]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let (round2_secret_package, round2_packages) = frost_utility::keys::dkg::part2(
            secret_package_deserialized,
            &round1_packages_deserialized,
        )
        .unwrap();
        let round2_public_package_serialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(package.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>();
        let round2_secert_package_serialized = SecretShareCustom2 {
            id,
            max: secret_custom.max,
            min: secret_custom.min,
            commitment: round2_secret_package
                .commitment
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            secret_share: serde_json::to_string(&round2_secret_package.secret_share).unwrap(),
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&round2_secert_package_serialized).unwrap()),
            round2_public_package_serialized,
        )
    }

    #[pyfunction]
    pub fn round3(
        round2_secret_package: String,
        round1_packages: BTreeMap<String, String>,
        round2_packages: BTreeMap<String, String>,
    ) -> (String, String) {
        let secret_custom: SecretShareCustom2 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(round2_secret_package).unwrap())
                .unwrap();

        let secret_package_deserialized = frost_utility::keys::dkg::round2::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            secret_share: serde_json::from_str(&secret_custom.secret_share).unwrap(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 33]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let round2_packages_deserialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round2::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round2Package>>();
        let (key_package, public_key) = frost_utility::keys::dkg::part3(
            &secret_package_deserialized,
            &round1_packages_deserialized,
            &round2_packages_deserialized,
        )
        .unwrap();
        let key_package_serialize = BASE64_URL_SAFE.encode(key_package.serialize().unwrap());
        let public_key_serialize = BASE64_URL_SAFE.encode(public_key.serialize().unwrap());
        (key_package_serialize, public_key_serialize)
    }

    #[pyfunction]
    pub fn preprocess(key_package: String) -> (String, String) {
        let mut rng = thread_rng();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let (nonces, commitment) =
            frost_utility::round1::commit(key_package_deserialized.signing_share(), &mut rng);
        let nonces_serialized = BASE64_URL_SAFE.encode(nonces.serialize().unwrap());
        let commitment_serialized = BASE64_URL_SAFE.encode(commitment.serialize().unwrap());
        (nonces_serialized, commitment_serialized)
    }
    #[pyfunction]
    pub fn sign(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        nonce: String,
        key_package: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let nonce_deserialized = frost_utility::round1::SigningNonces::deserialize(
            &BASE64_URL_SAFE.decode(nonce).unwrap(),
        )
        .unwrap();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_share = frost_utility::round2::sign(
            &signing_package,
            &nonce_deserialized,
            &key_package_deserialized,
        )
        .unwrap();
        BASE64_URL_SAFE.encode(signature_share.serialize())
    }
    #[pyfunction]
    pub fn aggregate(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        signature_shares: BTreeMap<String, String>,
        public_key: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_shares_deserialized = signature_shares
            .iter()
            .map(|(a, b)| {
                (
                    Identifier::deserialize(
                        &BASE64_URL_SAFE.decode(a).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SignatureShare::deserialize(
                        BASE64_URL_SAFE.decode(b).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SignatureShare>>();
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        BASE64_URL_SAFE.encode(
            frost_utility::aggregate(
                &signing_package,
                &signature_shares_deserialized,
                &public_key_deserialized,
            )
            .unwrap()
            .serialize(),
        )
    }

    #[pyfunction]
    pub fn verify(message: Vec<u8>, public_key: String, signature: String) -> bool {
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        let signature_deserialized = Signature::deserialize(
            BASE64_URL_SAFE.decode(signature).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_key_deserialized
            .verifying_key()
            .verify(&message, &signature_deserialized)
            .is_ok()
    }
    #[pyfunction]
    pub fn recover_step_1(
        helpers_identifiers: Vec<String>,
        helper_share: String,
        participant_identifier: String,
    ) -> BTreeMap<String, String> {
        let helpers_identifiers = helpers_identifiers
            .iter()
            .map(|f| {
                Identifier::deserialize(&BASE64_URL_SAFE.decode(f).unwrap()[..].try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<Identifier>>();
        let helper_share =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(helper_share).unwrap()).unwrap();
        let participant_identifier = Identifier::deserialize(
            &BASE64_URL_SAFE.decode(participant_identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let helper_deltas =
            frost_utility::keys::repairable::repair_share_step_1::<CrateCiphersuite, ThreadRng>(
                &helpers_identifiers,
                &helper_share,
                &mut rng,
                participant_identifier,
            )
            .unwrap();
        helper_deltas
            .iter()
            .map(|(id, scalar)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(serde_json::to_vec(&scalar).unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn recover_step_2(helpers_delta: Vec<String>) -> String {
        let helpers_delta: Vec<Scalar> = helpers_delta
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&repair_share_step_2(&helpers_delta)).unwrap())
    }
    #[pyfunction]
    pub fn recover_step_3(sigmas: Vec<String>, identifier: String, commitment: String) -> String {
        let sigmas: Vec<Scalar> = sigmas
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        let identifier = Identifier::deserialize(
            BASE64_URL_SAFE.decode(identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let commitment = VerifiableSecretSharingCommitment::deserialize(
            serde_json::from_slice::<Vec<Vec<u8>>>(&BASE64_URL_SAFE.decode(commitment).unwrap())
                .unwrap()
                .iter()
                .map(|f| f[..].try_into().unwrap())
                .collect::<Vec<[u8; 33]>>(),
        )
        .unwrap();
        BASE64_URL_SAFE.encode(
            repair_share_step_3(&sigmas, identifier, &commitment)
                .serialize()
                .unwrap(),
        )
    }
}

mod utility_module_ed448 {
    use base64::prelude::*;
    use frost_ed448 as frost_utility;
    use frost_utility::{
        keys::{
            dkg::{round1::Package as Round1Package, round2::Package as Round2Package},
            repairable::{repair_share_step_2, repair_share_step_3},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        serde::Serialize,
        Ciphersuite, Ed448Shake256, Field, Group, Identifier, Signature,
    };
    use pyo3::prelude::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub type CrateCiphersuite = Ed448Shake256;
    pub type Scalar = <<<Ed448Shake256 as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

    #[pyfunction]
    pub fn get_key(min: u16, max: u16) -> BTreeMap<String, String> {
        let rng = thread_rng();
        let (shares, _pubkey_package) = frost_utility::keys::generate_with_dealer(
            max,
            min,
            frost_utility::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        shares
            .into_iter()
            .map(|f| {
                (
                    BASE64_URL_SAFE.encode(f.0.serialize()),
                    BASE64_URL_SAFE.encode(f.1.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn get_dkg_get_coefficient_commitment(package: String) -> String {
        let coefficient_commitment = frost_utility::keys::dkg::round1::Package::deserialize(
            &BASE64_URL_SAFE.decode(package).unwrap(),
        )
        .unwrap()
        .commitment()
        .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn get_gen_with_dealer_coefficient_commitment(secret_share: String) -> String {
        let coefficient_commitment =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap())
                .unwrap()
                .commitment()
                .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn gen_key_package(secret_share: String) -> String {
        BASE64_URL_SAFE.encode(
            KeyPackage::try_from(
                SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap()).unwrap(),
            )
            .unwrap()
            .serialize()
            .unwrap(),
        )
    }
    #[pyfunction]
    pub fn print_key(key: String) {
        println!(
            "{:?}",
            KeyPackage::deserialize(&BASE64_URL_SAFE.decode(key).unwrap()).unwrap()
        );
    }
    #[pyfunction]
    pub fn construct(share: BTreeMap<String, String>) {
        let arr: [u8; 57] = BASE64_URL_SAFE
            .decode(share.keys().next().unwrap())
            .unwrap()[..]
            .try_into()
            .unwrap();
        println!(
            "\nback:\n{:?}\n",
            (
                Identifier::deserialize(&arr).unwrap(),
                SecretShare::deserialize(
                    &BASE64_URL_SAFE
                        .decode(share.values().next().unwrap())
                        .unwrap()
                )
            )
        );
    }

    #[derive(Serialize, Deserialize)]
    struct SecretShareCustom1 {
        commitment: Vec<Vec<u8>>,
        coefficent: Vec<String>,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn get_id() -> String {
        let mut bytes = [0u8; 64];
        thread_rng().fill_bytes(&mut bytes);
        let id = Identifier::derive(&bytes).unwrap().serialize();
        BASE64_URL_SAFE.encode(id)
    }
    #[pyfunction]
    pub fn round1(id: String, min: u16, max: u16) -> (String, String) {
        let rng = thread_rng();
        let id_deserialized =
            Identifier::deserialize(BASE64_URL_SAFE.decode(&id).unwrap()[..].try_into().unwrap())
                .unwrap();

        let (round1_secret_package, round1_package) =
            frost_utility::keys::dkg::part1(id_deserialized, max, min, rng).unwrap();
        let secret_share = SecretShareCustom1 {
            commitment: round1_secret_package
                .commitment()
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            coefficent: round1_secret_package
                .coefficients()
                .iter()
                .map(|f| serde_json::to_string(f).unwrap())
                .collect::<Vec<String>>(),
            id,
            min,
            max,
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&secret_share).unwrap()),
            BASE64_URL_SAFE.encode(round1_package.serialize().unwrap()),
        )
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct SecretShareCustom2 {
        commitment: Vec<Vec<u8>>,
        secret_share: String,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn round2(
        secret_package: String,
        round1_packages: BTreeMap<String, String>,
    ) -> (String, BTreeMap<String, String>) {
        let secret_custom: SecretShareCustom1 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(secret_package).unwrap()).unwrap();
        let id = secret_custom.id.clone();
        let secret_package_deserialized = frost_utility::keys::dkg::round1::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            coefficients: secret_custom
                .coefficent
                .iter()
                .map(|f| serde_json::from_str(f).unwrap())
                .collect(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 57]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let (round2_secret_package, round2_packages) = frost_utility::keys::dkg::part2(
            secret_package_deserialized,
            &round1_packages_deserialized,
        )
        .unwrap();
        let round2_public_package_serialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(package.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>();
        let round2_secert_package_serialized = SecretShareCustom2 {
            id,
            max: secret_custom.max,
            min: secret_custom.min,
            commitment: round2_secret_package
                .commitment
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            secret_share: serde_json::to_string(&round2_secret_package.secret_share).unwrap(),
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&round2_secert_package_serialized).unwrap()),
            round2_public_package_serialized,
        )
    }

    #[pyfunction]
    pub fn round3(
        round2_secret_package: String,
        round1_packages: BTreeMap<String, String>,
        round2_packages: BTreeMap<String, String>,
    ) -> (String, String) {
        let secret_custom: SecretShareCustom2 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(round2_secret_package).unwrap())
                .unwrap();

        let secret_package_deserialized = frost_utility::keys::dkg::round2::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            secret_share: serde_json::from_str(&secret_custom.secret_share).unwrap(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 57]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let round2_packages_deserialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round2::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round2Package>>();
        let (key_package, public_key) = frost_utility::keys::dkg::part3(
            &secret_package_deserialized,
            &round1_packages_deserialized,
            &round2_packages_deserialized,
        )
        .unwrap();
        let key_package_serialize = BASE64_URL_SAFE.encode(key_package.serialize().unwrap());
        let public_key_serialize = BASE64_URL_SAFE.encode(public_key.serialize().unwrap());
        (key_package_serialize, public_key_serialize)
    }

    #[pyfunction]
    pub fn preprocess(key_package: String) -> (String, String) {
        let mut rng = thread_rng();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let (nonces, commitment) =
            frost_utility::round1::commit(key_package_deserialized.signing_share(), &mut rng);
        let nonces_serialized = BASE64_URL_SAFE.encode(nonces.serialize().unwrap());
        let commitment_serialized = BASE64_URL_SAFE.encode(commitment.serialize().unwrap());
        (nonces_serialized, commitment_serialized)
    }
    #[pyfunction]
    pub fn sign(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        nonce: String,
        key_package: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let nonce_deserialized = frost_utility::round1::SigningNonces::deserialize(
            &BASE64_URL_SAFE.decode(nonce).unwrap(),
        )
        .unwrap();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_share = frost_utility::round2::sign(
            &signing_package,
            &nonce_deserialized,
            &key_package_deserialized,
        )
        .unwrap();
        BASE64_URL_SAFE.encode(signature_share.serialize())
    }
    #[pyfunction]
    pub fn aggregate(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        signature_shares: BTreeMap<String, String>,
        public_key: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_shares_deserialized = signature_shares
            .iter()
            .map(|(a, b)| {
                (
                    Identifier::deserialize(
                        &BASE64_URL_SAFE.decode(a).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SignatureShare::deserialize(
                        BASE64_URL_SAFE.decode(b).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SignatureShare>>();
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        BASE64_URL_SAFE.encode(
            frost_utility::aggregate(
                &signing_package,
                &signature_shares_deserialized,
                &public_key_deserialized,
            )
            .unwrap()
            .serialize(),
        )
    }

    #[pyfunction]
    pub fn verify(message: Vec<u8>, public_key: String, signature: String) -> bool {
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        let signature_deserialized = Signature::deserialize(
            BASE64_URL_SAFE.decode(signature).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_key_deserialized
            .verifying_key()
            .verify(&message, &signature_deserialized)
            .is_ok()
    }
    #[pyfunction]
    pub fn recover_step_1(
        helpers_identifiers: Vec<String>,
        helper_share: String,
        participant_identifier: String,
    ) -> BTreeMap<String, String> {
        let helpers_identifiers = helpers_identifiers
            .iter()
            .map(|f| {
                Identifier::deserialize(&BASE64_URL_SAFE.decode(f).unwrap()[..].try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<Identifier>>();
        let helper_share =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(helper_share).unwrap()).unwrap();
        let participant_identifier = Identifier::deserialize(
            &BASE64_URL_SAFE.decode(participant_identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let helper_deltas =
            frost_utility::keys::repairable::repair_share_step_1::<CrateCiphersuite, ThreadRng>(
                &helpers_identifiers,
                &helper_share,
                &mut rng,
                participant_identifier,
            )
            .unwrap();
        helper_deltas
            .iter()
            .map(|(id, scalar)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(serde_json::to_vec(&scalar).unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn recover_step_2(helpers_delta: Vec<String>) -> String {
        let helpers_delta: Vec<Scalar> = helpers_delta
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&repair_share_step_2(&helpers_delta)).unwrap())
    }
    #[pyfunction]
    pub fn recover_step_3(sigmas: Vec<String>, identifier: String, commitment: String) -> String {
        let sigmas: Vec<Scalar> = sigmas
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        let identifier = Identifier::deserialize(
            BASE64_URL_SAFE.decode(identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let commitment = VerifiableSecretSharingCommitment::deserialize(
            serde_json::from_slice::<Vec<Vec<u8>>>(&BASE64_URL_SAFE.decode(commitment).unwrap())
                .unwrap()
                .iter()
                .map(|f| f[..].try_into().unwrap())
                .collect::<Vec<[u8; 57]>>(),
        )
        .unwrap();
        BASE64_URL_SAFE.encode(
            repair_share_step_3(&sigmas, identifier, &commitment)
                .serialize()
                .unwrap(),
        )
    }
}

mod utility_module_ed25519 {
    use base64::prelude::*;
    use frost_ed25519 as frost_utility;
    use frost_utility::{
        keys::{
            dkg::{round1::Package as Round1Package, round2::Package as Round2Package},
            repairable::{repair_share_step_2, repair_share_step_3},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        serde::Serialize,
        Ciphersuite, Ed25519Sha512, Field, Group, Identifier, Signature,
    };
    use pyo3::prelude::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub type CrateCiphersuite = Ed25519Sha512;
    pub type Scalar = <<<Ed25519Sha512 as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

    #[pyfunction]
    pub fn get_key(min: u16, max: u16) -> BTreeMap<String, String> {
        let rng = thread_rng();
        let (shares, _pubkey_package) = frost_utility::keys::generate_with_dealer(
            max,
            min,
            frost_utility::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        shares
            .into_iter()
            .map(|f| {
                (
                    BASE64_URL_SAFE.encode(f.0.serialize()),
                    BASE64_URL_SAFE.encode(f.1.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn get_dkg_get_coefficient_commitment(package: String) -> String {
        let coefficient_commitment = frost_utility::keys::dkg::round1::Package::deserialize(
            &BASE64_URL_SAFE.decode(package).unwrap(),
        )
        .unwrap()
        .commitment()
        .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn get_gen_with_dealer_coefficient_commitment(secret_share: String) -> String {
        let coefficient_commitment =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap())
                .unwrap()
                .commitment()
                .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn gen_key_package(secret_share: String) -> String {
        BASE64_URL_SAFE.encode(
            KeyPackage::try_from(
                SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap()).unwrap(),
            )
            .unwrap()
            .serialize()
            .unwrap(),
        )
    }
    #[pyfunction]
    pub fn print_key(key: String) {
        println!(
            "{:?}",
            KeyPackage::deserialize(&BASE64_URL_SAFE.decode(key).unwrap()).unwrap()
        );
    }
    #[pyfunction]
    pub fn construct(share: BTreeMap<String, String>) {
        let arr: [u8; 32] = BASE64_URL_SAFE
            .decode(share.keys().next().unwrap())
            .unwrap()[..]
            .try_into()
            .unwrap();
        println!(
            "\nback:\n{:?}\n",
            (
                Identifier::deserialize(&arr).unwrap(),
                SecretShare::deserialize(
                    &BASE64_URL_SAFE
                        .decode(share.values().next().unwrap())
                        .unwrap()
                )
            )
        );
    }

    #[derive(Serialize, Deserialize)]
    struct SecretShareCustom1 {
        commitment: Vec<Vec<u8>>,
        coefficent: Vec<String>,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn get_id() -> String {
        let mut bytes = [0u8; 64];
        thread_rng().fill_bytes(&mut bytes);
        let id = Identifier::derive(&bytes).unwrap().serialize();
        BASE64_URL_SAFE.encode(id)
    }
    #[pyfunction]
    pub fn round1(id: String, min: u16, max: u16) -> (String, String) {
        let rng = thread_rng();
        let id_deserialized =
            Identifier::deserialize(BASE64_URL_SAFE.decode(&id).unwrap()[..].try_into().unwrap())
                .unwrap();

        let (round1_secret_package, round1_package) =
            frost_utility::keys::dkg::part1(id_deserialized, max, min, rng).unwrap();
        let secret_share = SecretShareCustom1 {
            commitment: round1_secret_package
                .commitment()
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            coefficent: round1_secret_package
                .coefficients()
                .iter()
                .map(|f| serde_json::to_string(f).unwrap())
                .collect::<Vec<String>>(),
            id,
            min,
            max,
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&secret_share).unwrap()),
            BASE64_URL_SAFE.encode(round1_package.serialize().unwrap()),
        )
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct SecretShareCustom2 {
        commitment: Vec<Vec<u8>>,
        secret_share: String,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn round2(
        secret_package: String,
        round1_packages: BTreeMap<String, String>,
    ) -> (String, BTreeMap<String, String>) {
        let secret_custom: SecretShareCustom1 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(secret_package).unwrap()).unwrap();
        let id = secret_custom.id.clone();
        let secret_package_deserialized = frost_utility::keys::dkg::round1::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            coefficients: secret_custom
                .coefficent
                .iter()
                .map(|f| serde_json::from_str(f).unwrap())
                .collect(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 32]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let (round2_secret_package, round2_packages) = frost_utility::keys::dkg::part2(
            secret_package_deserialized,
            &round1_packages_deserialized,
        )
        .unwrap();
        let round2_public_package_serialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(package.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>();
        let round2_secert_package_serialized = SecretShareCustom2 {
            id,
            max: secret_custom.max,
            min: secret_custom.min,
            commitment: round2_secret_package
                .commitment
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            secret_share: serde_json::to_string(&round2_secret_package.secret_share).unwrap(),
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&round2_secert_package_serialized).unwrap()),
            round2_public_package_serialized,
        )
    }

    #[pyfunction]
    pub fn round3(
        round2_secret_package: String,
        round1_packages: BTreeMap<String, String>,
        round2_packages: BTreeMap<String, String>,
    ) -> (String, String) {
        let secret_custom: SecretShareCustom2 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(round2_secret_package).unwrap())
                .unwrap();

        let secret_package_deserialized = frost_utility::keys::dkg::round2::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            secret_share: serde_json::from_str(&secret_custom.secret_share).unwrap(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 32]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let round2_packages_deserialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round2::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round2Package>>();
        let (key_package, public_key) = frost_utility::keys::dkg::part3(
            &secret_package_deserialized,
            &round1_packages_deserialized,
            &round2_packages_deserialized,
        )
        .unwrap();
        let key_package_serialize = BASE64_URL_SAFE.encode(key_package.serialize().unwrap());
        let public_key_serialize = BASE64_URL_SAFE.encode(public_key.serialize().unwrap());
        (key_package_serialize, public_key_serialize)
    }

    #[pyfunction]
    pub fn preprocess(key_package: String) -> (String, String) {
        let mut rng = thread_rng();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let (nonces, commitment) =
            frost_utility::round1::commit(key_package_deserialized.signing_share(), &mut rng);
        let nonces_serialized = BASE64_URL_SAFE.encode(nonces.serialize().unwrap());
        let commitment_serialized = BASE64_URL_SAFE.encode(commitment.serialize().unwrap());
        (nonces_serialized, commitment_serialized)
    }
    #[pyfunction]
    pub fn sign(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        nonce: String,
        key_package: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let nonce_deserialized = frost_utility::round1::SigningNonces::deserialize(
            &BASE64_URL_SAFE.decode(nonce).unwrap(),
        )
        .unwrap();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_share = frost_utility::round2::sign(
            &signing_package,
            &nonce_deserialized,
            &key_package_deserialized,
        )
        .unwrap();
        BASE64_URL_SAFE.encode(signature_share.serialize())
    }
    #[pyfunction]
    pub fn aggregate(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        signature_shares: BTreeMap<String, String>,
        public_key: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_shares_deserialized = signature_shares
            .iter()
            .map(|(a, b)| {
                (
                    Identifier::deserialize(
                        &BASE64_URL_SAFE.decode(a).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SignatureShare::deserialize(
                        BASE64_URL_SAFE.decode(b).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SignatureShare>>();
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        BASE64_URL_SAFE.encode(
            frost_utility::aggregate(
                &signing_package,
                &signature_shares_deserialized,
                &public_key_deserialized,
            )
            .unwrap()
            .serialize(),
        )
    }

    #[pyfunction]
    pub fn verify(message: Vec<u8>, public_key: String, signature: String) -> bool {
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        let signature_deserialized = Signature::deserialize(
            BASE64_URL_SAFE.decode(signature).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_key_deserialized
            .verifying_key()
            .verify(&message, &signature_deserialized)
            .is_ok()
    }
    #[pyfunction]
    pub fn recover_step_1(
        helpers_identifiers: Vec<String>,
        helper_share: String,
        participant_identifier: String,
    ) -> BTreeMap<String, String> {
        let helpers_identifiers = helpers_identifiers
            .iter()
            .map(|f| {
                Identifier::deserialize(&BASE64_URL_SAFE.decode(f).unwrap()[..].try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<Identifier>>();
        let helper_share =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(helper_share).unwrap()).unwrap();
        let participant_identifier = Identifier::deserialize(
            &BASE64_URL_SAFE.decode(participant_identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let helper_deltas =
            frost_utility::keys::repairable::repair_share_step_1::<CrateCiphersuite, ThreadRng>(
                &helpers_identifiers,
                &helper_share,
                &mut rng,
                participant_identifier,
            )
            .unwrap();
        helper_deltas
            .iter()
            .map(|(id, scalar)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(serde_json::to_vec(&scalar).unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn recover_step_2(helpers_delta: Vec<String>) -> String {
        let helpers_delta: Vec<Scalar> = helpers_delta
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&repair_share_step_2(&helpers_delta)).unwrap())
    }
    #[pyfunction]
    pub fn recover_step_3(sigmas: Vec<String>, identifier: String, commitment: String) -> String {
        let sigmas: Vec<Scalar> = sigmas
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        let identifier = Identifier::deserialize(
            BASE64_URL_SAFE.decode(identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let commitment = VerifiableSecretSharingCommitment::deserialize(
            serde_json::from_slice::<Vec<Vec<u8>>>(&BASE64_URL_SAFE.decode(commitment).unwrap())
                .unwrap()
                .iter()
                .map(|f| f[..].try_into().unwrap())
                .collect::<Vec<[u8; 32]>>(),
        )
        .unwrap();
        BASE64_URL_SAFE.encode(
            repair_share_step_3(&sigmas, identifier, &commitment)
                .serialize()
                .unwrap(),
        )
    }
}

mod utility_module_p256 {
    use base64::prelude::*;
    use frost_p256 as frost_utility;
    use frost_utility::{
        keys::{
            dkg::{round1::Package as Round1Package, round2::Package as Round2Package},
            repairable::{repair_share_step_2, repair_share_step_3},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        serde::Serialize,
        Ciphersuite, Field, Group, Identifier, P256Sha256, Signature,
    };
    use pyo3::prelude::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub type CrateCiphersuite = P256Sha256;
    pub type Scalar = <<<P256Sha256 as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

    #[pyfunction]
    pub fn get_key(min: u16, max: u16) -> BTreeMap<String, String> {
        let rng = thread_rng();
        let (shares, _pubkey_package) = frost_utility::keys::generate_with_dealer(
            max,
            min,
            frost_utility::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        shares
            .into_iter()
            .map(|f| {
                (
                    BASE64_URL_SAFE.encode(f.0.serialize()),
                    BASE64_URL_SAFE.encode(f.1.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn get_dkg_get_coefficient_commitment(package: String) -> String {
        let coefficient_commitment = frost_utility::keys::dkg::round1::Package::deserialize(
            &BASE64_URL_SAFE.decode(package).unwrap(),
        )
        .unwrap()
        .commitment()
        .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn get_gen_with_dealer_coefficient_commitment(secret_share: String) -> String {
        let coefficient_commitment =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap())
                .unwrap()
                .commitment()
                .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn gen_key_package(secret_share: String) -> String {
        BASE64_URL_SAFE.encode(
            KeyPackage::try_from(
                SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap()).unwrap(),
            )
            .unwrap()
            .serialize()
            .unwrap(),
        )
    }
    #[pyfunction]
    pub fn print_key(key: String) {
        println!(
            "{:?}",
            KeyPackage::deserialize(&BASE64_URL_SAFE.decode(key).unwrap()).unwrap()
        );
    }
    #[pyfunction]
    pub fn construct(share: BTreeMap<String, String>) {
        let arr: [u8; 32] = BASE64_URL_SAFE
            .decode(share.keys().next().unwrap())
            .unwrap()[..]
            .try_into()
            .unwrap();
        println!(
            "\nback:\n{:?}\n",
            (
                Identifier::deserialize(&arr).unwrap(),
                SecretShare::deserialize(
                    &BASE64_URL_SAFE
                        .decode(share.values().next().unwrap())
                        .unwrap()
                )
            )
        );
    }

    #[derive(Serialize, Deserialize)]
    struct SecretShareCustom1 {
        commitment: Vec<Vec<u8>>,
        coefficent: Vec<String>,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn get_id() -> String {
        let mut bytes = [0u8; 64];
        thread_rng().fill_bytes(&mut bytes);
        let id = Identifier::derive(&bytes).unwrap().serialize();
        BASE64_URL_SAFE.encode(id)
    }
    #[pyfunction]
    pub fn round1(id: String, min: u16, max: u16) -> (String, String) {
        let rng = thread_rng();
        let id_deserialized =
            Identifier::deserialize(BASE64_URL_SAFE.decode(&id).unwrap()[..].try_into().unwrap())
                .unwrap();

        let (round1_secret_package, round1_package) =
            frost_utility::keys::dkg::part1(id_deserialized, max, min, rng).unwrap();
        let secret_share = SecretShareCustom1 {
            commitment: round1_secret_package
                .commitment()
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            coefficent: round1_secret_package
                .coefficients()
                .iter()
                .map(|f| serde_json::to_string(f).unwrap())
                .collect::<Vec<String>>(),
            id,
            min,
            max,
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&secret_share).unwrap()),
            BASE64_URL_SAFE.encode(round1_package.serialize().unwrap()),
        )
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct SecretShareCustom2 {
        commitment: Vec<Vec<u8>>,
        secret_share: String,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn round2(
        secret_package: String,
        round1_packages: BTreeMap<String, String>,
    ) -> (String, BTreeMap<String, String>) {
        let secret_custom: SecretShareCustom1 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(secret_package).unwrap()).unwrap();
        let id = secret_custom.id.clone();
        let secret_package_deserialized = frost_utility::keys::dkg::round1::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            coefficients: secret_custom
                .coefficent
                .iter()
                .map(|f| serde_json::from_str(f).unwrap())
                .collect(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 33]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let (round2_secret_package, round2_packages) = frost_utility::keys::dkg::part2(
            secret_package_deserialized,
            &round1_packages_deserialized,
        )
        .unwrap();
        let round2_public_package_serialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(package.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>();
        let round2_secert_package_serialized = SecretShareCustom2 {
            id,
            max: secret_custom.max,
            min: secret_custom.min,
            commitment: round2_secret_package
                .commitment
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            secret_share: serde_json::to_string(&round2_secret_package.secret_share).unwrap(),
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&round2_secert_package_serialized).unwrap()),
            round2_public_package_serialized,
        )
    }

    #[pyfunction]
    pub fn round3(
        round2_secret_package: String,
        round1_packages: BTreeMap<String, String>,
        round2_packages: BTreeMap<String, String>,
    ) -> (String, String) {
        let secret_custom: SecretShareCustom2 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(round2_secret_package).unwrap())
                .unwrap();

        let secret_package_deserialized = frost_utility::keys::dkg::round2::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            secret_share: serde_json::from_str(&secret_custom.secret_share).unwrap(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 33]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let round2_packages_deserialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round2::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round2Package>>();
        let (key_package, public_key) = frost_utility::keys::dkg::part3(
            &secret_package_deserialized,
            &round1_packages_deserialized,
            &round2_packages_deserialized,
        )
        .unwrap();
        let key_package_serialize = BASE64_URL_SAFE.encode(key_package.serialize().unwrap());
        let public_key_serialize = BASE64_URL_SAFE.encode(public_key.serialize().unwrap());
        (key_package_serialize, public_key_serialize)
    }

    #[pyfunction]
    pub fn preprocess(key_package: String) -> (String, String) {
        let mut rng = thread_rng();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let (nonces, commitment) =
            frost_utility::round1::commit(key_package_deserialized.signing_share(), &mut rng);
        let nonces_serialized = BASE64_URL_SAFE.encode(nonces.serialize().unwrap());
        let commitment_serialized = BASE64_URL_SAFE.encode(commitment.serialize().unwrap());
        (nonces_serialized, commitment_serialized)
    }
    #[pyfunction]
    pub fn sign(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        nonce: String,
        key_package: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let nonce_deserialized = frost_utility::round1::SigningNonces::deserialize(
            &BASE64_URL_SAFE.decode(nonce).unwrap(),
        )
        .unwrap();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_share = frost_utility::round2::sign(
            &signing_package,
            &nonce_deserialized,
            &key_package_deserialized,
        )
        .unwrap();
        BASE64_URL_SAFE.encode(signature_share.serialize())
    }
    #[pyfunction]
    pub fn aggregate(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        signature_shares: BTreeMap<String, String>,
        public_key: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_shares_deserialized = signature_shares
            .iter()
            .map(|(a, b)| {
                (
                    Identifier::deserialize(
                        &BASE64_URL_SAFE.decode(a).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SignatureShare::deserialize(
                        BASE64_URL_SAFE.decode(b).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SignatureShare>>();
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        BASE64_URL_SAFE.encode(
            frost_utility::aggregate(
                &signing_package,
                &signature_shares_deserialized,
                &public_key_deserialized,
            )
            .unwrap()
            .serialize(),
        )
    }

    #[pyfunction]
    pub fn verify(message: Vec<u8>, public_key: String, signature: String) -> bool {
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        let signature_deserialized = Signature::deserialize(
            BASE64_URL_SAFE.decode(signature).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_key_deserialized
            .verifying_key()
            .verify(&message, &signature_deserialized)
            .is_ok()
    }
    #[pyfunction]
    pub fn recover_step_1(
        helpers_identifiers: Vec<String>,
        helper_share: String,
        participant_identifier: String,
    ) -> BTreeMap<String, String> {
        let helpers_identifiers = helpers_identifiers
            .iter()
            .map(|f| {
                Identifier::deserialize(&BASE64_URL_SAFE.decode(f).unwrap()[..].try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<Identifier>>();
        let helper_share =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(helper_share).unwrap()).unwrap();
        let participant_identifier = Identifier::deserialize(
            &BASE64_URL_SAFE.decode(participant_identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let helper_deltas =
            frost_utility::keys::repairable::repair_share_step_1::<CrateCiphersuite, ThreadRng>(
                &helpers_identifiers,
                &helper_share,
                &mut rng,
                participant_identifier,
            )
            .unwrap();
        helper_deltas
            .iter()
            .map(|(id, scalar)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(serde_json::to_vec(&scalar).unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn recover_step_2(helpers_delta: Vec<String>) -> String {
        let helpers_delta: Vec<Scalar> = helpers_delta
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&repair_share_step_2(&helpers_delta)).unwrap())
    }
    #[pyfunction]
    pub fn recover_step_3(sigmas: Vec<String>, identifier: String, commitment: String) -> String {
        let sigmas: Vec<Scalar> = sigmas
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        let identifier = Identifier::deserialize(
            BASE64_URL_SAFE.decode(identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let commitment = VerifiableSecretSharingCommitment::deserialize(
            serde_json::from_slice::<Vec<Vec<u8>>>(&BASE64_URL_SAFE.decode(commitment).unwrap())
                .unwrap()
                .iter()
                .map(|f| f[..].try_into().unwrap())
                .collect::<Vec<[u8; 33]>>(),
        )
        .unwrap();
        BASE64_URL_SAFE.encode(
            repair_share_step_3(&sigmas, identifier, &commitment)
                .serialize()
                .unwrap(),
        )
    }
}

mod utility_module_ristretto255 {
    use base64::prelude::*;
    use frost_ristretto255 as frost_utility;
    use frost_utility::{
        keys::{
            dkg::{round1::Package as Round1Package, round2::Package as Round2Package},
            repairable::{repair_share_step_2, repair_share_step_3},
            KeyPackage, PublicKeyPackage, SecretShare, VerifiableSecretSharingCommitment,
        },
        round1::SigningCommitments,
        round2::SignatureShare,
        serde::Serialize,
        Ciphersuite, Field, Group, Identifier, Ristretto255Sha512, Signature,
    };
    use pyo3::prelude::*;
    use rand::{rngs::ThreadRng, thread_rng, RngCore};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    pub type CrateCiphersuite = Ristretto255Sha512;
    pub type Scalar =
        <<<Ristretto255Sha512 as Ciphersuite>::Group as Group>::Field as Field>::Scalar;

    #[pyfunction]
    pub fn get_key(min: u16, max: u16) -> BTreeMap<String, String> {
        let rng = thread_rng();
        let (shares, _pubkey_package) = frost_utility::keys::generate_with_dealer(
            max,
            min,
            frost_utility::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();

        shares
            .into_iter()
            .map(|f| {
                (
                    BASE64_URL_SAFE.encode(f.0.serialize()),
                    BASE64_URL_SAFE.encode(f.1.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn get_dkg_get_coefficient_commitment(package: String) -> String {
        let coefficient_commitment = frost_utility::keys::dkg::round1::Package::deserialize(
            &BASE64_URL_SAFE.decode(package).unwrap(),
        )
        .unwrap()
        .commitment()
        .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn get_gen_with_dealer_coefficient_commitment(secret_share: String) -> String {
        let coefficient_commitment =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap())
                .unwrap()
                .commitment()
                .serialize();
        let coefficient_commitment = coefficient_commitment
            .iter()
            .map(|f| f.to_vec())
            .collect::<Vec<Vec<u8>>>();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&coefficient_commitment).unwrap())
    }
    #[pyfunction]
    pub fn gen_key_package(secret_share: String) -> String {
        BASE64_URL_SAFE.encode(
            KeyPackage::try_from(
                SecretShare::deserialize(&BASE64_URL_SAFE.decode(secret_share).unwrap()).unwrap(),
            )
            .unwrap()
            .serialize()
            .unwrap(),
        )
    }
    #[pyfunction]
    pub fn print_key(key: String) {
        println!(
            "{:?}",
            KeyPackage::deserialize(&BASE64_URL_SAFE.decode(key).unwrap()).unwrap()
        );
    }
    #[pyfunction]
    pub fn construct(share: BTreeMap<String, String>) {
        let arr: [u8; 32] = BASE64_URL_SAFE
            .decode(share.keys().next().unwrap())
            .unwrap()[..]
            .try_into()
            .unwrap();
        println!(
            "\nback:\n{:?}\n",
            (
                Identifier::deserialize(&arr).unwrap(),
                SecretShare::deserialize(
                    &BASE64_URL_SAFE
                        .decode(share.values().next().unwrap())
                        .unwrap()
                )
            )
        );
    }

    #[derive(Serialize, Deserialize)]
    struct SecretShareCustom1 {
        commitment: Vec<Vec<u8>>,
        coefficent: Vec<String>,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn get_id() -> String {
        let mut bytes = [0u8; 64];
        thread_rng().fill_bytes(&mut bytes);
        let id = Identifier::derive(&bytes).unwrap().serialize();
        BASE64_URL_SAFE.encode(id)
    }
    #[pyfunction]
    pub fn round1(id: String, min: u16, max: u16) -> (String, String) {
        let rng = thread_rng();
        let id_deserialized =
            Identifier::deserialize(BASE64_URL_SAFE.decode(&id).unwrap()[..].try_into().unwrap())
                .unwrap();

        let (round1_secret_package, round1_package) =
            frost_utility::keys::dkg::part1(id_deserialized, max, min, rng).unwrap();
        let secret_share = SecretShareCustom1 {
            commitment: round1_secret_package
                .commitment()
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            coefficent: round1_secret_package
                .coefficients()
                .iter()
                .map(|f| serde_json::to_string(f).unwrap())
                .collect::<Vec<String>>(),
            id,
            min,
            max,
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&secret_share).unwrap()),
            BASE64_URL_SAFE.encode(round1_package.serialize().unwrap()),
        )
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct SecretShareCustom2 {
        commitment: Vec<Vec<u8>>,
        secret_share: String,
        id: String,
        min: u16,
        max: u16,
    }
    #[pyfunction]
    pub fn round2(
        secret_package: String,
        round1_packages: BTreeMap<String, String>,
    ) -> (String, BTreeMap<String, String>) {
        let secret_custom: SecretShareCustom1 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(secret_package).unwrap()).unwrap();
        let id = secret_custom.id.clone();
        let secret_package_deserialized = frost_utility::keys::dkg::round1::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            coefficients: secret_custom
                .coefficent
                .iter()
                .map(|f| serde_json::from_str(f).unwrap())
                .collect(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 32]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let (round2_secret_package, round2_packages) = frost_utility::keys::dkg::part2(
            secret_package_deserialized,
            &round1_packages_deserialized,
        )
        .unwrap();
        let round2_public_package_serialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(package.serialize().unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>();
        let round2_secert_package_serialized = SecretShareCustom2 {
            id,
            max: secret_custom.max,
            min: secret_custom.min,
            commitment: round2_secret_package
                .commitment
                .serialize()
                .iter()
                .map(|f| f.to_vec())
                .collect::<Vec<Vec<u8>>>(),
            secret_share: serde_json::to_string(&round2_secret_package.secret_share).unwrap(),
        };
        (
            BASE64_URL_SAFE.encode(serde_json::to_vec(&round2_secert_package_serialized).unwrap()),
            round2_public_package_serialized,
        )
    }

    #[pyfunction]
    pub fn round3(
        round2_secret_package: String,
        round1_packages: BTreeMap<String, String>,
        round2_packages: BTreeMap<String, String>,
    ) -> (String, String) {
        let secret_custom: SecretShareCustom2 =
            serde_json::from_slice(&BASE64_URL_SAFE.decode(round2_secret_package).unwrap())
                .unwrap();

        let secret_package_deserialized = frost_utility::keys::dkg::round2::SecretPackage {
            identifier: Identifier::deserialize(
                BASE64_URL_SAFE.decode(secret_custom.id).unwrap()[..]
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            secret_share: serde_json::from_str(&secret_custom.secret_share).unwrap(),
            commitment: frost_utility::keys::VerifiableSecretSharingCommitment::deserialize(
                secret_custom
                    .commitment
                    .iter()
                    .map(|f| f[..].try_into().unwrap())
                    .collect::<Vec<[u8; 32]>>(),
            )
            .unwrap(),
            min_signers: secret_custom.min,
            max_signers: secret_custom.max,
        };

        let round1_packages_deserialized = round1_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round1::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round1Package>>();
        let round2_packages_deserialized = round2_packages
            .iter()
            .map(|(id, package)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    frost_utility::keys::dkg::round2::Package::deserialize(
                        &BASE64_URL_SAFE.decode(package).unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, Round2Package>>();
        let (key_package, public_key) = frost_utility::keys::dkg::part3(
            &secret_package_deserialized,
            &round1_packages_deserialized,
            &round2_packages_deserialized,
        )
        .unwrap();
        let key_package_serialize = BASE64_URL_SAFE.encode(key_package.serialize().unwrap());
        let public_key_serialize = BASE64_URL_SAFE.encode(public_key.serialize().unwrap());
        (key_package_serialize, public_key_serialize)
    }

    #[pyfunction]
    pub fn preprocess(key_package: String) -> (String, String) {
        let mut rng = thread_rng();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let (nonces, commitment) =
            frost_utility::round1::commit(key_package_deserialized.signing_share(), &mut rng);
        let nonces_serialized = BASE64_URL_SAFE.encode(nonces.serialize().unwrap());
        let commitment_serialized = BASE64_URL_SAFE.encode(commitment.serialize().unwrap());
        (nonces_serialized, commitment_serialized)
    }
    #[pyfunction]
    pub fn sign(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        nonce: String,
        key_package: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let nonce_deserialized = frost_utility::round1::SigningNonces::deserialize(
            &BASE64_URL_SAFE.decode(nonce).unwrap(),
        )
        .unwrap();
        let key_package_deserialized = frost_utility::keys::KeyPackage::deserialize(
            &BASE64_URL_SAFE.decode(key_package).unwrap(),
        )
        .unwrap();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_share = frost_utility::round2::sign(
            &signing_package,
            &nonce_deserialized,
            &key_package_deserialized,
        )
        .unwrap();
        BASE64_URL_SAFE.encode(signature_share.serialize())
    }
    #[pyfunction]
    pub fn aggregate(
        message: Vec<u8>,
        nonce_commitments: BTreeMap<String, String>,
        signature_shares: BTreeMap<String, String>,
        public_key: String,
    ) -> String {
        let nonce_commitment_deserialized = nonce_commitments
            .iter()
            .map(|(id, commitment)| {
                (
                    Identifier::deserialize(
                        BASE64_URL_SAFE.decode(id).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SigningCommitments::deserialize(&BASE64_URL_SAFE.decode(commitment).unwrap())
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SigningCommitments>>();
        let signing_package =
            frost_utility::SigningPackage::new(nonce_commitment_deserialized, &message);
        let signature_shares_deserialized = signature_shares
            .iter()
            .map(|(a, b)| {
                (
                    Identifier::deserialize(
                        &BASE64_URL_SAFE.decode(a).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                    SignatureShare::deserialize(
                        BASE64_URL_SAFE.decode(b).unwrap()[..].try_into().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<Identifier, SignatureShare>>();
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        BASE64_URL_SAFE.encode(
            frost_utility::aggregate(
                &signing_package,
                &signature_shares_deserialized,
                &public_key_deserialized,
            )
            .unwrap()
            .serialize(),
        )
    }

    #[pyfunction]
    pub fn verify(message: Vec<u8>, public_key: String, signature: String) -> bool {
        let public_key_deserialized =
            PublicKeyPackage::deserialize(&BASE64_URL_SAFE.decode(public_key).unwrap()).unwrap();
        let signature_deserialized = Signature::deserialize(
            BASE64_URL_SAFE.decode(signature).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        public_key_deserialized
            .verifying_key()
            .verify(&message, &signature_deserialized)
            .is_ok()
    }
    #[pyfunction]
    pub fn recover_step_1(
        helpers_identifiers: Vec<String>,
        helper_share: String,
        participant_identifier: String,
    ) -> BTreeMap<String, String> {
        let helpers_identifiers = helpers_identifiers
            .iter()
            .map(|f| {
                Identifier::deserialize(&BASE64_URL_SAFE.decode(f).unwrap()[..].try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<Identifier>>();
        let helper_share =
            SecretShare::deserialize(&BASE64_URL_SAFE.decode(helper_share).unwrap()).unwrap();
        let participant_identifier = Identifier::deserialize(
            &BASE64_URL_SAFE.decode(participant_identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let mut rng = rand::thread_rng();
        let helper_deltas =
            frost_utility::keys::repairable::repair_share_step_1::<CrateCiphersuite, ThreadRng>(
                &helpers_identifiers,
                &helper_share,
                &mut rng,
                participant_identifier,
            )
            .unwrap();
        helper_deltas
            .iter()
            .map(|(id, scalar)| {
                (
                    BASE64_URL_SAFE.encode(id.serialize()),
                    BASE64_URL_SAFE.encode(serde_json::to_vec(&scalar).unwrap()),
                )
            })
            .collect::<BTreeMap<String, String>>()
    }
    #[pyfunction]
    pub fn recover_step_2(helpers_delta: Vec<String>) -> String {
        let helpers_delta: Vec<Scalar> = helpers_delta
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        BASE64_URL_SAFE.encode(serde_json::to_vec(&repair_share_step_2(&helpers_delta)).unwrap())
    }
    #[pyfunction]
    pub fn recover_step_3(sigmas: Vec<String>, identifier: String, commitment: String) -> String {
        let sigmas: Vec<Scalar> = sigmas
            .iter()
            .map(|f| serde_json::from_slice(&BASE64_URL_SAFE.decode(f).unwrap()).unwrap())
            .collect();
        let identifier = Identifier::deserialize(
            BASE64_URL_SAFE.decode(identifier).unwrap()[..]
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let commitment = VerifiableSecretSharingCommitment::deserialize(
            serde_json::from_slice::<Vec<Vec<u8>>>(&BASE64_URL_SAFE.decode(commitment).unwrap())
                .unwrap()
                .iter()
                .map(|f| f[..].try_into().unwrap())
                .collect::<Vec<[u8; 32]>>(),
        )
        .unwrap();
        BASE64_URL_SAFE.encode(
            repair_share_step_3(&sigmas, identifier, &commitment)
                .serialize()
                .unwrap(),
        )
    }
}

// mod network_module{
// use std::time::Duration;

// use anyhow::{Context, Result};
// use libp2p::{Multiaddr, StreamProtocol};
// use libp2p_stream as stream;
// use pyo3::{pyfunction, PyResult};
// use tracing::level_filters::LevelFilter;
// use tracing_subscriber::EnvFilter;

// const INIT:StreamProtocol = StreamProtocol::new("/init");
// const ROUND1:StreamProtocol = StreamProtocol::new("/round1");
// const ROUND2:StreamProtocol = StreamProtocol::new("/round2");
// const COMMIT:StreamProtocol = StreamProtocol::new("/Commit");
// const SIGN  :StreamProtocol = StreamProtocol::new("/sign");

// }

#[pymodule]
fn network(_py: Python, _m: &PyModule) -> PyResult<()> {
    Ok(())
}
#[pymodule]
fn utility_secp256k1(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::round1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::round2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::print_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::round3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::get_id, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::construct, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::get_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_secp256k1::verify, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::recover_step_1,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::recover_step_2,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::recover_step_3,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::gen_key_package,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::get_gen_with_dealer_coefficient_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_secp256k1::get_dkg_get_coefficient_commitment,
        m
    )?)?;
    Ok(())
}

#[pymodule]
fn utility_ed448(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(utility_module_ed448::round1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::round2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::print_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::round3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::get_id, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::construct, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::get_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::verify, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::recover_step_1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::recover_step_2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::recover_step_3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed448::gen_key_package, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ed448::get_gen_with_dealer_coefficient_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ed448::get_dkg_get_coefficient_commitment,
        m
    )?)?;
    Ok(())
}
#[pymodule]
fn utility_ed25519(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(utility_module_ed25519::round1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::round2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::print_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::round3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::get_id, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::construct, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::get_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::verify, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::recover_step_1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::recover_step_2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ed25519::recover_step_3, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ed25519::gen_key_package,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ed25519::get_gen_with_dealer_coefficient_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ed25519::get_dkg_get_coefficient_commitment,
        m
    )?)?;
    Ok(())
}
#[pymodule]
fn utility_p256(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(utility_module_p256::round1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::round2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::print_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::round3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::get_id, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::construct, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::get_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::preprocess, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::verify, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::recover_step_1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::recover_step_2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::recover_step_3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_p256::gen_key_package, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_p256::get_gen_with_dealer_coefficient_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_p256::get_dkg_get_coefficient_commitment,
        m
    )?)?;
    Ok(())
}
#[pymodule]
fn utility_ristretto255(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::round1, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::round2, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::print_key, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::round3, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::get_id, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::construct, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::get_key, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::preprocess,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::sign, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(utility_module_ristretto255::verify, m)?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::recover_step_1,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::recover_step_2,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::recover_step_3,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::gen_key_package,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::get_gen_with_dealer_coefficient_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        utility_module_ristretto255::get_dkg_get_coefficient_commitment,
        m
    )?)?;
    Ok(())
}

#[pymodule]
fn frost(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(network))?;
    m.add_wrapped(wrap_pymodule!(utility_secp256k1))?;
    m.add_wrapped(wrap_pymodule!(utility_ed448))?;
    m.add_wrapped(wrap_pymodule!(utility_ed25519))?;
    m.add_wrapped(wrap_pymodule!(utility_p256))?;
    m.add_wrapped(wrap_pymodule!(utility_ristretto255))?;

    Ok(())
}
