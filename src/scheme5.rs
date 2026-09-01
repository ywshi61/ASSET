use ark_crypto_primitives::signature::schnorr::{Schnorr, SecretKey};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::UniformRand;

use digest::Digest;


// =====================================================
// Enhanced pre-signature
//
// sigma_tilde' = ((R_hat, s_tilde), (R_prime, s_prime))
//
// where
// R_hat = rG + Y
// =====================================================

#[derive(Clone, Debug)]
pub struct AdaptorPreSignature<C: CurveGroup> {
    // Standard Schnorr adaptor pre-signature
    pub commitment: C::Affine,
    pub prover_response: C::ScalarField,

    // Schnorr-style PoK of r
    pub proof_commitment: C::Affine,
    pub proof_response: C::ScalarField,
}


// =====================================================
// Full signature
//
// sigma = (R_hat, s)
// =====================================================

#[derive(Clone, Debug)]
pub struct AdaptorFullSignature<C: CurveGroup> {
    pub commitment: C::Affine,
    pub prover_response: C::ScalarField,
}


// =====================================================
// Trait
// =====================================================

pub trait AdaptorSignatureScheme: SignatureScheme {
    type PreSignature;
    type AdaptedSignature;

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error>;

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error>;

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error>;
}


// =====================================================
// Enhanced Schnorr Adaptor Signature
// =====================================================

impl<C: CurveGroup, D: Digest + Send + Sync> AdaptorSignatureScheme
    for Schnorr<C, D>
{
    type PreSignature = AdaptorPreSignature<C>;
    type AdaptedSignature = AdaptorFullSignature<C>;

    // -------------------------------------------------
    // pSign'
    // -------------------------------------------------
    //
    // Standard AS:
    //
    // r <- Z_q
    // R_hat = rG + Y
    // c = HSign(R_hat, X, m)
    // s_tilde = r + c*x
    //
    // PoK of r:
    //
    // r' <- Z_q
    // R' = r'G
    // c' = HProve(X, m, sigma_tilde, Y, R')
    // s' = r' + c'r
    //
    // Output:
    //
    // ((R_hat, s_tilde), (R', s'))
    //
    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error> {

        // -------------------------------------------------
        // Standard Schnorr adaptor pre-signature
        // -------------------------------------------------

        let random_nonce = C::ScalarField::rand(rng);

        // R_hat = rG + Y
        let commitment =
            (<C::Affine as AffineRepr>::generator() * random_nonce
                + *adaptor_pk)
                .into_affine();

        // c = HSign(R_hat || X || m)
        let verifier_challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;

        // s_tilde = r + c*x
        let prover_response =
            verifier_challenge * signer_sk.0
                + random_nonce;


        // -------------------------------------------------
        // Schnorr-style proof of knowledge of r
        // -------------------------------------------------

        let proof_nonce = C::ScalarField::rand(rng);

        // R' = r'G
        let proof_commitment =
            (<C::Affine as AffineRepr>::generator()
                * proof_nonce)
                .into_affine();

        // c' = HProve(pk, m, sigma_tilde, Y, R')
        let proof_challenge =
            hash_proof_challenge::<C, D>(
                signer_pk,
                message,
                &commitment,
                &prover_response,
                adaptor_pk,
                &proof_commitment,
            )?;

        // s' = r' + c' * r
        let proof_response =
            proof_nonce
                + proof_challenge * random_nonce;


        Ok(AdaptorPreSignature {
            commitment,
            prover_response,
            proof_commitment,
            proof_response,
        })
    }


    // -------------------------------------------------
    // pVrfy'
    // -------------------------------------------------
    //
    // b1:
    //
    // s_tilde G + Y ?= R_hat + cX
    //
    // b2:
    //
    // s'G ?= R' + c'(R_hat - Y)
    //
    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        // =================================================
        // 1. Standard adaptor pre-signature verification
        // =================================================

        let commitment = signature.commitment;
        let prover_response = signature.prover_response;

        // c = HSign(R_hat || X || m)
        let challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;

        // left = s_tilde G + Y
        let left =
            <C::Affine as AffineRepr>::generator()
                * prover_response
                + *adaptor_pk;

        // right = R_hat + cX
        let right =
            commitment.into_group()
                + *signer_pk * challenge;

        if left.into_affine() != right.into_affine() {
            return Err("pre-signature verification failure".into());
        }


        // =================================================
        // 2. Schnorr-style PoK verification
        // =================================================

        let proof_challenge =
            hash_proof_challenge::<C, D>(
                signer_pk,
                message,
                &signature.commitment,
                &signature.prover_response,
                adaptor_pk,
                &signature.proof_commitment,
            )?;

        // R = R_hat - Y = rG
        let nonce_commitment =
            signature.commitment.into_group()
                - adaptor_pk.into_group();

        // left = s'G
        let proof_left =
            <C::Affine as AffineRepr>::generator()
                * signature.proof_response;

        // right = R' + c'R
        let proof_right =
            signature.proof_commitment.into_group()
                + nonce_commitment * proof_challenge;

        if proof_left.into_affine()
            != proof_right.into_affine()
        {
            return Err("proof verification failure".into());
        }

        Ok(())
    }


    // -------------------------------------------------
    // Adapt'
    // -------------------------------------------------
    //
    // Ignore the proof:
    //
    // s = s_tilde + y
    //
    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {

        Ok(AdaptorFullSignature {
            commitment: signature.commitment,
            prover_response:
                signature.prover_response
                    + adaptor_sk.0,
        })
    }


    // -------------------------------------------------
    // Extract'
    // -------------------------------------------------
    //
    // Ignore the proof:
    //
    // y = s - s_tilde
    //
    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error> {

        let sk =
            signature.prover_response
                - pre_signature.prover_response;

        Ok(SecretKey(sk))
    }
}


// =====================================================
// HSign
//
// Same hash construction as Scheme 1
// =====================================================

fn hash_challenge<C: CurveGroup, D: Digest>(
    commitment: &C::Affine,
    signer_pk: &C::Affine,
    message: &[u8],
) -> Result<C::ScalarField, Error> {

    let mut hasher = D::new();
    let mut buf = Vec::new();

    commitment.serialize_compressed(&mut buf)?;
    hasher.update(&buf);

    buf.clear();

    signer_pk.serialize_compressed(&mut buf)?;
    hasher.update(&buf);

    hasher.update(message);

    let digest = hasher.finalize();

    Ok(
        C::ScalarField::from_be_bytes_mod_order(
            &digest,
        ),
    )
}


// =====================================================
// HProve
//
// c' = HProve(pk, m, sigma_tilde, Y, R')
//
// sigma_tilde = (R_hat, s_tilde)
//
// We use domain separation "HProve" because HProve is a
// separate random oracle from HSign in the construction.
// =====================================================

fn hash_proof_challenge<C: CurveGroup, D: Digest>(
    signer_pk: &C::Affine,
    message: &[u8],
    commitment: &C::Affine,
    prover_response: &C::ScalarField,
    adaptor_pk: &C::Affine,
    proof_commitment: &C::Affine,
) -> Result<C::ScalarField, Error> {

    let mut hasher = D::new();

    // Domain separation for HProve
    hasher.update(b"HProve");

    let mut buf = Vec::new();

    // pk
    signer_pk.serialize_compressed(&mut buf)?;
    hasher.update(&buf);
    buf.clear();

    // message
    hasher.update(message);

    // sigma_tilde.commitment
    commitment.serialize_compressed(&mut buf)?;
    hasher.update(&buf);
    buf.clear();

    // sigma_tilde.response
    prover_response.serialize_compressed(&mut buf)?;
    hasher.update(&buf);
    buf.clear();

    // Y
    adaptor_pk.serialize_compressed(&mut buf)?;
    hasher.update(&buf);
    buf.clear();

    // R'
    proof_commitment.serialize_compressed(&mut buf)?;
    hasher.update(&buf);

    let digest = hasher.finalize();

    Ok(
        C::ScalarField::from_be_bytes_mod_order(
            &digest,
        ),
    )
}


// =====================================================
// Tests
// =====================================================

#[cfg(test)]
mod test {

    use super::*;

    use ark_ec::Group;
    use ark_secp256k1::Projective as Secp256k1;
    use ark_std::test_rng;
    use sha3::Keccak256;

    type Scheme =
        Schnorr<Secp256k1, Keccak256>;


    // Exactly the same key generation as Scheme 1
    fn keygen<R: Rng>(
        rng: &mut R,
    ) -> (
        <Scheme as SignatureScheme>::PublicKey,
        <Scheme as SignatureScheme>::SecretKey,
    ) {

        let mut parameters =
            Scheme::setup(rng).unwrap();

        parameters.generator =
            Secp256k1::generator().into_affine();

        Scheme::keygen(
            &parameters,
            rng,
        )
        .unwrap()
    }


    #[test]
    fn completeness() {

        let rng = &mut test_rng();

        // Same key generation interface as Scheme 1
        let (signer_pk, signer_sk) =
            keygen(rng);

        let (adaptor_pk, adaptor_sk) =
            keygen(rng);

        let message =
            b"hello enhanced adaptor signature";


        // -------------------------------------------------
        // PreSign
        // -------------------------------------------------

        let pre_sig =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();


        // -------------------------------------------------
        // PreVrfy
        // -------------------------------------------------

        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &signer_pk,
                message,
            )
            .is_ok()
        );


        // -------------------------------------------------
        // Adapt
        // -------------------------------------------------

        let adapted_sig =
            <Scheme as AdaptorSignatureScheme>::adapt(
                &pre_sig,
                &adaptor_sk,
            )
            .unwrap();


        // -------------------------------------------------
        // Verify resulting Schnorr signature
        // -------------------------------------------------

        let challenge =
            hash_challenge::<
                Secp256k1,
                Keccak256,
            >(
                &adapted_sig.commitment,
                &signer_pk,
                message,
            )
            .unwrap();

        let left =
            Secp256k1::generator()
                * adapted_sig.prover_response;

        let right =
            adapted_sig.commitment.into_group()
                + signer_pk * challenge;

        assert_eq!(
            left.into_affine(),
            right.into_affine()
        );


        // -------------------------------------------------
        // Extract
        // -------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &pre_sig,
                &adapted_sig,
            )
            .unwrap();

        assert_eq!(
            extracted_sk.0,
            adaptor_sk.0
        );
    }


    #[test]
    fn invalid_proof_is_rejected() {

        let rng = &mut test_rng();

        let (signer_pk, signer_sk) =
            keygen(rng);

        let (adaptor_pk, _) =
            keygen(rng);

        let message =
            b"hello enhanced adaptor signature";

        let mut pre_sig =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();

        // Valid before modification
        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &signer_pk,
                message,
            )
            .is_ok()
        );

        // Modify s'
        pre_sig.proof_response +=
            Secp256k1::ScalarField::from(1u64);

        // PoK must now fail
        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &signer_pk,
                message,
            )
            .is_err()
        );
    }


    #[test]
    fn soundness() {

        let rng = &mut test_rng();

        let (signer_pk, signer_sk) =
            keygen(rng);

        let (adaptor_pk, _) =
            keygen(rng);

        let message =
            b"hello enhanced adaptor signature";


        // Pre-sign under the wrong statement
        let pre_sig =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &signer_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();


        // Verify using the actual adaptor statement
        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &signer_pk,
                message,
            )
            .is_err()
        );
    }
}