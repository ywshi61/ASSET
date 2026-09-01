use ark_crypto_primitives::signature::schnorr::{
    Schnorr,
    SecretKey,
};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;

use ark_ec::{
    AffineRepr,
    CurveGroup,
};

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use ark_std::rand::Rng;
use ark_std::UniformRand;

use digest::Digest;


// ============================================================
// Encrypted adaptor pre-signature
//
// pre-signature = (R, U, s_hat)
//
// R     = rG + Y
// U     = rho G
// s_hat = s_tilde + H_E(rho Y)
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorPreSignature<C: CurveGroup> {
    pub commitment: C::Affine,
    pub encryption_commitment: C::Affine,
    pub encrypted_response: C::ScalarField,
}


// ============================================================
// Full signature
//
// sigma = (R, s)
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorFullSignature<C: CurveGroup> {
    pub commitment: C::Affine,
    pub prover_response: C::ScalarField,
}


// ============================================================
// Adaptor signature trait
// ============================================================

pub trait AdaptorSignatureScheme: SignatureScheme {
    type PreSignature;
    type AdaptedSignature;
    type ExtractionKey;


    // --------------------------------------------------------
    // pSign
    // --------------------------------------------------------

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<
        (
            Self::PreSignature,
            Self::ExtractionKey,
        ),
        Error,
    >;


    // --------------------------------------------------------
    // pVrfy
    // --------------------------------------------------------

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;


    // --------------------------------------------------------
    // Adapt
    // --------------------------------------------------------

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error>;


    // --------------------------------------------------------
    // Extract
    // --------------------------------------------------------

    fn extract(
        extraction_key: &Self::ExtractionKey,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error>;


    // --------------------------------------------------------
    // Vrfy
    //
    // Verify the final Schnorr signature.
    // --------------------------------------------------------

    fn verify_full_signature(
        signature: &Self::AdaptedSignature,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;
}


// ============================================================
// Trivial solution
// ============================================================

impl<C: CurveGroup, D: Digest + Send + Sync>
    AdaptorSignatureScheme for Schnorr<C, D>
{
    type PreSignature = AdaptorPreSignature<C>;
    type AdaptedSignature = AdaptorFullSignature<C>;
    type ExtractionKey = C::ScalarField;


    // ========================================================
    // pSign
    // ========================================================
    //
    // First generate the ordinary Schnorr adaptor
    // pre-response:
    //
    // r <- Z_q
    // R = rG + Y
    // c = H(R || X || m)
    // s_tilde = cx + r
    //
    // Then encrypt s_tilde:
    //
    // rho <- Z_q
    // U = rho G
    // K = rho Y
    // h = H_E(K)
    // s_hat = s_tilde + h
    //
    // output:
    //
    // pre-signature = (R, U, s_hat)
    // extraction key = s_tilde
    // ========================================================

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<
        (
            Self::PreSignature,
            Self::ExtractionKey,
        ),
        Error,
    > {

        // ----------------------------------------------------
        // Standard Schnorr adaptor pre-signature
        // ----------------------------------------------------

        // r <- Z_q
        let random_nonce =
            C::ScalarField::rand(rng);


        // R = rG + Y
        let commitment =
            (
                <C::Affine as AffineRepr>::generator()
                    * random_nonce
                    + *adaptor_pk
            )
            .into_affine();


        // c = H(R || X || m)
        let verifier_challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;


        // s_tilde = cx + r
        let prover_response =
            verifier_challenge * signer_sk.0
                + random_nonce;


        // ----------------------------------------------------
        // DHIES-style encryption of s_tilde
        // ----------------------------------------------------

        // rho <- Z_q
        let encryption_nonce =
            C::ScalarField::rand(rng);


        // U = rho G
        let encryption_commitment =
            (
                <C::Affine as AffineRepr>::generator()
                    * encryption_nonce
            )
            .into_affine();


        // K = rho Y
        let shared_secret =
            (
                *adaptor_pk
                    * encryption_nonce
            )
            .into_affine();


        // h = H_E(K)
        let mask =
            hash_shared_secret::<C, D>(
                &shared_secret,
            )?;


        // s_hat = s_tilde + h
        let encrypted_response =
            prover_response + mask;


        Ok((
            AdaptorPreSignature {
                commitment,
                encryption_commitment,
                encrypted_response,
            },

            // Local extraction key
            prover_response,
        ))
    }


    // ========================================================
    // pVrfy
    // ========================================================
    //
    // Decrypt:
    //
    // K' = yU
    // h' = H_E(K')
    // s_tilde = s_hat - h'
    //
    // Then verify:
    //
    // s_tilde G + Y = R + cX
    // ========================================================

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        // ----------------------------------------------------
        // Decryption
        // ----------------------------------------------------

        // K' = yU
        let shared_secret =
            (
                signature.encryption_commitment
                    * adaptor_sk.0
            )
            .into_affine();


        // h' = H_E(K')
        let mask =
            hash_shared_secret::<C, D>(
                &shared_secret,
            )?;


        // s_tilde = s_hat - h'
        let prover_response =
            signature.encrypted_response
                - mask;


        // ----------------------------------------------------
        // Standard adaptor pre-verification
        // ----------------------------------------------------

        // c = H(R || X || m)
        let challenge =
            hash_challenge::<C, D>(
                &signature.commitment,
                signer_pk,
                message,
            )?;


        // left = s_tilde G + Y
        let left =
            <C::Affine as AffineRepr>::generator()
                * prover_response
                + *adaptor_pk;


        // right = R + cX
        let right =
            signature.commitment.into_group()
                + *signer_pk * challenge;


        if left.into_affine()
            != right.into_affine()
        {
            Err(
                "pre-signature verification failure"
                    .into(),
            )
        } else {
            Ok(())
        }
    }


    // ========================================================
    // Adapt
    // ========================================================
    //
    // Decrypt:
    //
    // K' = yU
    // h' = H_E(K')
    // s_tilde = s_hat - h'
    //
    // Adapt:
    //
    // s = s_tilde + y
    // ========================================================

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {

        // ----------------------------------------------------
        // Decryption
        // ----------------------------------------------------

        // K' = yU
        let shared_secret =
            (
                signature.encryption_commitment
                    * adaptor_sk.0
            )
            .into_affine();


        // h' = H_E(K')
        let mask =
            hash_shared_secret::<C, D>(
                &shared_secret,
            )?;


        // s_tilde = s_hat - h'
        let prover_response =
            signature.encrypted_response
                - mask;


        // ----------------------------------------------------
        // Adapt
        // ----------------------------------------------------

        // s = s_tilde + y
        let adapted_response =
            prover_response
                + adaptor_sk.0;


        Ok(
            AdaptorFullSignature {
                commitment:
                    signature.commitment,

                prover_response:
                    adapted_response,
            },
        )
    }


    // ========================================================
    // Extract
    // ========================================================
    //
    // ek = s_tilde
    //
    // y = s - ek
    // ========================================================

    fn extract(
        extraction_key: &Self::ExtractionKey,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error> {

        let sk =
            signature.prover_response
                - *extraction_key;


        Ok(
            SecretKey(sk),
        )
    }


    // ========================================================
    // Vrfy
    // ========================================================
    //
    // The encrypted pre-signature is no longer relevant.
    //
    // The adapted signature is an ordinary Schnorr signature:
    //
    // sigma = (R, s)
    //
    // c = H(R || X || m)
    //
    // check:
    //
    // sG = R + cX
    // ========================================================

    fn verify_full_signature(
        signature: &Self::AdaptedSignature,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        let commitment =
            signature.commitment;

        let prover_response =
            signature.prover_response;


        // ----------------------------------------------------
        // c = H(R || X || m)
        // ----------------------------------------------------

        let challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;


        // ----------------------------------------------------
        // left = sG
        // ----------------------------------------------------

        let left =
            <C::Affine as AffineRepr>::generator()
                * prover_response;


        // ----------------------------------------------------
        // right = R + cX
        // ----------------------------------------------------

        let right =
            commitment.into_group()
                + *signer_pk * challenge;


        if left.into_affine()
            != right.into_affine()
        {
            Err(
                "full signature verification failure"
                    .into(),
            )
        } else {
            Ok(())
        }
    }
}


// ============================================================
// Schnorr challenge
//
// c = H(R || X || m)
// ============================================================

fn hash_challenge<C: CurveGroup, D: Digest>(
    commitment: &C::Affine,
    signer_pk: &C::Affine,
    message: &[u8],
) -> Result<C::ScalarField, Error> {

    let mut hasher =
        D::new();

    let mut buf =
        Vec::new();


    // R
    commitment
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);

    buf.clear();


    // X
    signer_pk
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);


    // m
    hasher.update(message);


    let digest =
        hasher.finalize();


    Ok(
        C::ScalarField::from_be_bytes_mod_order(
            &digest,
        ),
    )
}


// ============================================================
// DHIES mask
//
// h = H_E(K)
// ============================================================

fn hash_shared_secret<C: CurveGroup, D: Digest>(
    shared_secret: &C::Affine,
) -> Result<C::ScalarField, Error> {

    let mut hasher =
        D::new();

    let mut buf =
        Vec::new();


    shared_secret
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);


    let digest =
        hasher.finalize();


    Ok(
        C::ScalarField::from_be_bytes_mod_order(
            &digest,
        ),
    )
}


// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod test {

    use super::*;

    use ark_ec::Group;
    use ark_secp256k1::Projective as Secp256k1;
    use ark_std::test_rng;

    use sha3::Keccak256;


    type Scheme =
        Schnorr<
            Secp256k1,
            Keccak256,
        >;


    // ========================================================
    // Key generation
    // ========================================================

    fn keygen<R: Rng>(
        rng: &mut R,
    ) -> (
        <Scheme as SignatureScheme>::PublicKey,
        <Scheme as SignatureScheme>::SecretKey,
    ) {

        let mut parameters =
            Scheme::setup(rng)
                .unwrap();


        parameters.generator =
            Secp256k1::generator()
                .into_affine();


        Scheme::keygen(
            &parameters,
            rng,
        )
        .unwrap()
    }


    // ========================================================
    // Completeness
    // ========================================================

    #[test]
    fn completeness() {

        // ----------------------------------------------------
        // Setup and key generation
        // ----------------------------------------------------

        let rng =
            &mut test_rng();


        let (
            signer_pk,
            signer_sk,
        ) =
            keygen(rng);


        let (
            adaptor_pk,
            adaptor_sk,
        ) =
            keygen(rng);


        let message =
            b"hello adaptor signature";


        // ----------------------------------------------------
        // pSign
        // ----------------------------------------------------

        let (
            pre_sig,
            extraction_key,
        ) =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();


        // ----------------------------------------------------
        // pVrfy
        // ----------------------------------------------------

        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
                message,
            )
            .is_ok()
        );


        // ----------------------------------------------------
        // Adapt
        // ----------------------------------------------------

        let adapted_sig =
            <Scheme as AdaptorSignatureScheme>::adapt(
                &pre_sig,
                &adaptor_sk,
            )
            .unwrap();


        // ----------------------------------------------------
        // Vrfy
        // ----------------------------------------------------

        assert!(
            <Scheme as AdaptorSignatureScheme>
                ::verify_full_signature(
                    &adapted_sig,
                    &signer_pk,
                    message,
                )
                .is_ok()
        );


        // ----------------------------------------------------
        // Extract
        // ----------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &extraction_key,
                &adapted_sig,
            )
            .unwrap();


        assert_eq!(
            extracted_sk.0,
            adaptor_sk.0,
        );
    }


    // ========================================================
    // Soundness
    // ========================================================

    #[test]
    fn soundness() {

        // ----------------------------------------------------
        // Setup and key generation
        // ----------------------------------------------------

        let rng =
            &mut test_rng();


        let (
            signer_pk,
            signer_sk,
        ) =
            keygen(rng);


        let (
            adaptor_pk,
            adaptor_sk,
        ) =
            keygen(rng);


        let message =
            b"hello adaptor signature";


        // ----------------------------------------------------
        // Pre-signature with invalid adaptor public key
        // ----------------------------------------------------

        let (
            pre_sig,
            _extraction_key,
        ) =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &signer_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();


        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
                message,
            )
            .is_err()
        );


        // ----------------------------------------------------
        // Pre-signature generated for invalid message
        // ----------------------------------------------------

        let (
            pre_sig,
            _extraction_key,
        ) =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                b"invalid",
                rng,
            )
            .unwrap();


        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
                message,
            )
            .is_err()
        );


        // ----------------------------------------------------
        // Valid pre-signature
        // ----------------------------------------------------

        let (
            pre_sig,
            extraction_key,
        ) =
            <Scheme as AdaptorSignatureScheme>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();


        assert!(
            <Scheme as AdaptorSignatureScheme>::verify(
                &pre_sig,
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
                message,
            )
            .is_ok()
        );


        // ----------------------------------------------------
        // Adapt with invalid secret key
        // ----------------------------------------------------

        let adapted_sig =
            <Scheme as AdaptorSignatureScheme>::adapt(
                &pre_sig,
                &signer_sk,
            )
            .unwrap();


        // ----------------------------------------------------
        // Wrong adaptor key => invalid full signature
        // ----------------------------------------------------

        assert!(
            <Scheme as AdaptorSignatureScheme>
                ::verify_full_signature(
                    &adapted_sig,
                    &signer_pk,
                    message,
                )
                .is_err()
        );


        // ----------------------------------------------------
        // Extract secret actually used for adaptation
        // ----------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &extraction_key,
                &adapted_sig,
            )
            .unwrap();


        assert_ne!(
            extracted_sk.0,
            adaptor_sk.0,
        );
    }
}