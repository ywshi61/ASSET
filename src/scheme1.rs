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
// Pre-signature
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorPreSignature<C: CurveGroup> {
    pub commitment: C::Affine,
    pub prover_response: C::ScalarField,
}


// ============================================================
// Full signature
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

    // --------------------------------------------------------
    // pSign
    // --------------------------------------------------------

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error>;


    // --------------------------------------------------------
    // pVrfy
    // --------------------------------------------------------

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
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
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error>;


    // --------------------------------------------------------
    // Vrfy
    //
    // Verify the adapted full signature.
    // --------------------------------------------------------

    fn verify_full_signature(
        signature: &Self::AdaptedSignature,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;
}


// ============================================================
// Schnorr adaptor signature implementation
// ============================================================

impl<C: CurveGroup, D: Digest + Send + Sync>
    AdaptorSignatureScheme for Schnorr<C, D>
{
    type PreSignature = AdaptorPreSignature<C>;
    type AdaptedSignature = AdaptorFullSignature<C>;


    // ========================================================
    // pSign
    // ========================================================
    //
    // r <- Z_q
    //
    // R_hat = rG + Y
    //
    // c = H(R_hat || X || m)
    //
    // s_tilde = r + cx
    //
    // output:
    //
    // sigma_tilde = (R_hat, s_tilde)
    // ========================================================

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error> {

        // Random nonce r
        let random_nonce =
            C::ScalarField::rand(rng);


        // ----------------------------------------------------
        // R_hat = rG + Y
        // ----------------------------------------------------

        let commitment =
            (
                <C::Affine as AffineRepr>::generator()
                    * random_nonce
                    + *adaptor_pk
            )
            .into_affine();


        // ----------------------------------------------------
        // c = H(R_hat || X || m)
        // ----------------------------------------------------

        let verifier_challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;


        // ----------------------------------------------------
        // s_tilde = r + cx
        // ----------------------------------------------------

        let prover_response =
            verifier_challenge * signer_sk.0
                + random_nonce;


        Ok(
            AdaptorPreSignature {
                commitment,
                prover_response,
            },
        )
    }


    // ========================================================
    // pVrfy
    // ========================================================
    //
    // c = H(R_hat || X || m)
    //
    // check:
    //
    // s_tilde G + Y
    //
    //      =
    //
    // R_hat + cX
    // ========================================================

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        let commitment =
            signature.commitment;

        let prover_response =
            signature.prover_response;


        // ----------------------------------------------------
        // c = H(R_hat || X || m)
        // ----------------------------------------------------

        let challenge =
            hash_challenge::<C, D>(
                &commitment,
                signer_pk,
                message,
            )?;


        // ----------------------------------------------------
        // left = s_tilde G + Y
        // ----------------------------------------------------

        let left =
            <C::Affine as AffineRepr>::generator()
                * prover_response
                + *adaptor_pk;


        // ----------------------------------------------------
        // right = R_hat + cX
        // ----------------------------------------------------

        let right =
            commitment.into_group()
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
    // s = s_tilde + y
    //
    // output:
    //
    // sigma = (R_hat, s)
    // ========================================================

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {

        Ok(
            AdaptorFullSignature {

                commitment:
                    signature.commitment,

                prover_response:
                    signature.prover_response
                        + adaptor_sk.0,
            },
        )
    }


    // ========================================================
    // Extract
    // ========================================================
    //
    // y = s - s_tilde
    // ========================================================

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
    ) -> Result<Self::SecretKey, Error> {

        let sk =
            signature.prover_response
                - pre_signature.prover_response;

        Ok(
            SecretKey(sk),
        )
    }


    // ========================================================
    // Vrfy
    // ========================================================
    //
    // Full Schnorr signature verification:
    //
    // c = H(R_hat || X || m)
    //
    // check:
    //
    // sG = R_hat + cX
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
        // c = H(R_hat || X || m)
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
        // right = R_hat + cX
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
// Hash challenge
// ============================================================
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


    // --------------------------------------------------------
    // R
    // --------------------------------------------------------

    commitment
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);

    buf.clear();


    // --------------------------------------------------------
    // X
    // --------------------------------------------------------

    signer_pk
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);


    // --------------------------------------------------------
    // m
    // --------------------------------------------------------

    hasher.update(message);


    // --------------------------------------------------------
    // Convert hash output to Z_q
    // --------------------------------------------------------

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

        let pre_sig =
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
                &pre_sig,
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
            _adaptor_sk,
        ) =
            keygen(rng);


        let message =
            b"hello adaptor signature";


        // ----------------------------------------------------
        // Pre-signature generated with invalid adaptor public key
        // ----------------------------------------------------

        let pre_sig =
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
                &signer_pk,
                message,
            )
            .is_err()
        );


        // ----------------------------------------------------
        // Pre-signature generated for invalid message
        // ----------------------------------------------------

        let pre_sig =
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
                &signer_pk,
                message,
            )
            .is_err()
        );


        // ----------------------------------------------------
        // Valid pre-signature
        // ----------------------------------------------------

        let pre_sig =
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
        // Wrong adaptor secret key => invalid full signature
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
        // Extract the secret actually used in adaptation
        // ----------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &pre_sig,
                &adapted_sig,
            )
            .unwrap();


        assert_eq!(
            extracted_sk.0,
            signer_sk.0,
        );
    }
}