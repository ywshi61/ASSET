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
// ASSET pre-signature
//
// sigma_tilde = (R_tilde, s_tilde)
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorPreSignature<C: CurveGroup> {
    pub commitment: C::Affine,
    pub prover_response: C::ScalarField,
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
        adaptor_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
        signer_pk: &Self::PublicKey,
    ) -> Result<Self::AdaptedSignature, Error>;


    // --------------------------------------------------------
    // SecExt
    // --------------------------------------------------------

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        extraction_key: &Self::ExtractionKey,
    ) -> Result<Self::SecretKey, Error>;


    // --------------------------------------------------------
    // Vrfy
    // --------------------------------------------------------

    fn verify_full_signature(
        signature: &Self::AdaptedSignature,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;
}


// ============================================================
// ASSET implementation
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
    // r <- Z_q
    //
    // R_tilde = rG
    //
    // k = H1(Y || Y^r || Y^x)
    //
    // k0 = H3(k)
    //
    // K = kG
    //
    // R = R_tilde + Y + K
    //
    // c = H2(X || R || m)
    //
    // s_tilde = cx + r + k0
    //
    // ek = r
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
        // r <- Z_q
        // ----------------------------------------------------

        let random_nonce =
            C::ScalarField::rand(rng);


        // ----------------------------------------------------
        // R_tilde = rG
        // ----------------------------------------------------

        let commitment =
            (
                <C::Affine as AffineRepr>::generator()
                    * random_nonce
            )
            .into_affine();


        // ----------------------------------------------------
        // Y^r -> rY
        // ----------------------------------------------------

        let y_r =
            (
                *adaptor_pk
                    * random_nonce
            )
            .into_affine();


        // ----------------------------------------------------
        // Y^x -> xY
        // ----------------------------------------------------

        let y_x =
            (
                *adaptor_pk
                    * signer_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // k = H1(Y || Y^r || Y^x)
        // ----------------------------------------------------

        let k =
            hash_h1::<C, D>(
                adaptor_pk,
                &y_r,
                &y_x,
            )?;


        // ----------------------------------------------------
        // k0 = H3(k)
        // ----------------------------------------------------

        let k0 =
            hash_h3::<C, D>(
                &k,
            )?;


        // ----------------------------------------------------
        // K = kG
        // ----------------------------------------------------

        let k_point =
            (
                <C::Affine as AffineRepr>::generator()
                    * k
            )
            .into_affine();


        // ----------------------------------------------------
        // R = R_tilde + Y + K
        // ----------------------------------------------------

        let final_commitment =
            (
                commitment.into_group()
                    + *adaptor_pk
                    + k_point
            )
            .into_affine();


        // ----------------------------------------------------
        // c = H2(X || R || m)
        // ----------------------------------------------------

        let challenge =
            hash_h2::<C, D>(
                signer_pk,
                &final_commitment,
                message,
            )?;


        // ----------------------------------------------------
        // s_tilde = cx + r + k0
        // ----------------------------------------------------

        let prover_response =
            challenge * signer_sk.0
                + random_nonce
                + k0;


        let pre_signature =
            AdaptorPreSignature {
                commitment,
                prover_response,
            };


        // ----------------------------------------------------
        // ek = r
        // ----------------------------------------------------

        let extraction_key =
            random_nonce;


        Ok((
            pre_signature,
            extraction_key,
        ))
    }


    // ========================================================
    // pVrfy
    // ========================================================
    //
    // R_tilde^y -> y R_tilde
    //
    // X^y -> yX
    //
    // k' = H1(Y || R_tilde^y || X^y)
    //
    // k0' = H3(k')
    //
    // K' = k'G
    //
    // R = R_tilde + Y + K'
    //
    // c' = H2(X || R || m)
    //
    // check:
    //
    // (s_tilde - k0')G
    //
    //      =
    //
    // R_tilde + c'X
    // ========================================================

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        // ----------------------------------------------------
        // R_tilde^y -> y R_tilde
        // ----------------------------------------------------

        let r_y =
            (
                signature.commitment
                    * adaptor_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // X^y -> yX
        // ----------------------------------------------------

        let x_y =
            (
                *signer_pk
                    * adaptor_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // k' = H1(Y || R_tilde^y || X^y)
        // ----------------------------------------------------

        let k_prime =
            hash_h1::<C, D>(
                adaptor_pk,
                &r_y,
                &x_y,
            )?;


        // ----------------------------------------------------
        // k0' = H3(k')
        // ----------------------------------------------------

        let k0_prime =
            hash_h3::<C, D>(
                &k_prime,
            )?;


        // ----------------------------------------------------
        // K' = k'G
        // ----------------------------------------------------

        let k_point =
            (
                <C::Affine as AffineRepr>::generator()
                    * k_prime
            )
            .into_affine();


        // ----------------------------------------------------
        // R = R_tilde + Y + K'
        // ----------------------------------------------------

        let final_commitment =
            (
                signature.commitment.into_group()
                    + *adaptor_pk
                    + k_point
            )
            .into_affine();


        // ----------------------------------------------------
        // c' = H2(X || R || m)
        // ----------------------------------------------------

        let challenge =
            hash_h2::<C, D>(
                signer_pk,
                &final_commitment,
                message,
            )?;


        // ----------------------------------------------------
        // left = (s_tilde - k0')G
        // ----------------------------------------------------

        let left =
            <C::Affine as AffineRepr>::generator()
                * (
                    signature.prover_response
                        - k0_prime
                );


        // ----------------------------------------------------
        // right = R_tilde + c'X
        // ----------------------------------------------------

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
    // k' = H1(Y || R_tilde^y || X^y)
    //
    // k0' = H3(k')
    //
    // R = R_tilde + Y + K'
    //
    // s = s_tilde + y + k' - k0'
    // ========================================================

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
        signer_pk: &Self::PublicKey,
    ) -> Result<Self::AdaptedSignature, Error> {

        // ----------------------------------------------------
        // R_tilde^y -> y R_tilde
        // ----------------------------------------------------

        let r_y =
            (
                signature.commitment
                    * adaptor_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // X^y -> yX
        // ----------------------------------------------------

        let x_y =
            (
                *signer_pk
                    * adaptor_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // k' = H1(Y || R_tilde^y || X^y)
        // ----------------------------------------------------

        let k_prime =
            hash_h1::<C, D>(
                adaptor_pk,
                &r_y,
                &x_y,
            )?;


        // ----------------------------------------------------
        // k0' = H3(k')
        // ----------------------------------------------------

        let k0_prime =
            hash_h3::<C, D>(
                &k_prime,
            )?;


        // ----------------------------------------------------
        // K' = k'G
        // ----------------------------------------------------

        let k_point =
            (
                <C::Affine as AffineRepr>::generator()
                    * k_prime
            )
            .into_affine();


        // ----------------------------------------------------
        // R = R_tilde + Y + K'
        // ----------------------------------------------------

        let final_commitment =
            (
                signature.commitment.into_group()
                    + *adaptor_pk
                    + k_point
            )
            .into_affine();


        // ----------------------------------------------------
        // s = s_tilde + y + k' - k0'
        // ----------------------------------------------------

        let adapted_response =
            signature.prover_response
                + adaptor_sk.0
                + k_prime
                - k0_prime;


        Ok(
            AdaptorFullSignature {
                commitment:
                    final_commitment,

                prover_response:
                    adapted_response,
            },
        )
    }


    // ========================================================
    // SecExt
    // ========================================================
    //
    // ek = r
    //
    // k = H1(Y || Y^r || Y^x)
    //
    // k0 = H3(k)
    //
    // y' = s - s_tilde - k + k0
    // ========================================================

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        extraction_key: &Self::ExtractionKey,
    ) -> Result<Self::SecretKey, Error> {

        // ----------------------------------------------------
        // Y^r -> rY
        // ----------------------------------------------------

        let y_r =
            (
                *adaptor_pk
                    * *extraction_key
            )
            .into_affine();


        // ----------------------------------------------------
        // Y^x -> xY
        // ----------------------------------------------------

        let y_x =
            (
                *adaptor_pk
                    * signer_sk.0
            )
            .into_affine();


        // ----------------------------------------------------
        // k = H1(Y || Y^r || Y^x)
        // ----------------------------------------------------

        let k =
            hash_h1::<C, D>(
                adaptor_pk,
                &y_r,
                &y_x,
            )?;


        // ----------------------------------------------------
        // k0 = H3(k)
        // ----------------------------------------------------

        let k0 =
            hash_h3::<C, D>(
                &k,
            )?;


        // ----------------------------------------------------
        // y' = s - s_tilde - k + k0
        // ----------------------------------------------------

        let extracted_sk =
            signature.prover_response
                - pre_signature.prover_response
                - k
                + k0;


        Ok(
            SecretKey(
                extracted_sk,
            ),
        )
    }


    // ========================================================
    // Vrfy
    // ========================================================
    //
    // The final ASSET signature is a standard Schnorr-form
    // signature:
    //
    // sigma = (R, s)
    //
    // However, ASSET uses H2 for the challenge:
    //
    // c = H2(X || R || m)
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

        // ----------------------------------------------------
        // c = H2(X || R || m)
        // ----------------------------------------------------

        let challenge =
            hash_h2::<C, D>(
                signer_pk,
                &signature.commitment,
                message,
            )?;


        // ----------------------------------------------------
        // left = sG
        // ----------------------------------------------------

        let left =
            <C::Affine as AffineRepr>::generator()
                * signature.prover_response;


        // ----------------------------------------------------
        // right = R + cX
        // ----------------------------------------------------

        let right =
            signature.commitment.into_group()
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
// H1
//
// k = H1(Y || Y^r || Y^x)
// ============================================================

fn hash_h1<C: CurveGroup, D: Digest>(
    adaptor_pk: &C::Affine,
    y_r: &C::Affine,
    y_x: &C::Affine,
) -> Result<C::ScalarField, Error> {

    let mut hasher =
        D::new();

    let mut buf =
        Vec::new();


    // --------------------------------------------------------
    // Domain separation
    // --------------------------------------------------------

    hasher.update(b"H1");


    // --------------------------------------------------------
    // Y
    // --------------------------------------------------------

    adaptor_pk
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);

    buf.clear();


    // --------------------------------------------------------
    // Y^r -> rY
    // --------------------------------------------------------

    y_r
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);

    buf.clear();


    // --------------------------------------------------------
    // Y^x -> xY
    // --------------------------------------------------------

    y_x
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
// H2
//
// c = H2(X || R || m)
// ============================================================

fn hash_h2<C: CurveGroup, D: Digest>(
    signer_pk: &C::Affine,
    final_commitment: &C::Affine,
    message: &[u8],
) -> Result<C::ScalarField, Error> {

    let mut hasher =
        D::new();

    let mut buf =
        Vec::new();


    // --------------------------------------------------------
    // Domain separation
    // --------------------------------------------------------

    hasher.update(b"H2");


    // --------------------------------------------------------
    // X
    // --------------------------------------------------------

    signer_pk
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);

    buf.clear();


    // --------------------------------------------------------
    // R
    // --------------------------------------------------------

    final_commitment
        .serialize_compressed(&mut buf)?;

    hasher.update(&buf);


    // --------------------------------------------------------
    // m
    // --------------------------------------------------------

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
// H3
//
// k0 = H3(k)
// ============================================================

fn hash_h3<C: CurveGroup, D: Digest>(
    k: &C::ScalarField,
) -> Result<C::ScalarField, Error> {

    let mut hasher =
        D::new();

    let mut buf =
        Vec::new();


    // --------------------------------------------------------
    // Domain separation
    // --------------------------------------------------------

    hasher.update(b"H3");


    // --------------------------------------------------------
    // k
    // --------------------------------------------------------

    k.serialize_compressed(
        &mut buf,
    )?;

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
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
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
        // SecExt
        // ----------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &pre_sig,
                &adapted_sig,
                &adaptor_pk,
                &signer_sk,
                &extraction_key,
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
        // Valid pre-signature
        // ----------------------------------------------------

        let (
            pre_sig,
            _extraction_key,
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
        // Invalid message
        // ----------------------------------------------------

        let (
            invalid_pre_sig,
            _invalid_extraction_key,
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
                &invalid_pre_sig,
                &adaptor_pk,
                &adaptor_sk,
                &signer_pk,
                message,
            )
            .is_err()
        );


        // ----------------------------------------------------
        // Fresh valid pre-signature for invalid adaptation test
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
        // Adapt using an invalid secret key
        //
        // Here signer_sk is deliberately used instead of y.
        // ----------------------------------------------------

        let adapted_sig =
            <Scheme as AdaptorSignatureScheme>::adapt(
                &pre_sig,
                &adaptor_pk,
                &signer_sk,
                &signer_pk,
            )
            .unwrap();


        // ----------------------------------------------------
        // Wrong adaptor secret => invalid full signature
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
        // SecExt should not recover the correct adaptor witness
        // ----------------------------------------------------

        let extracted_sk =
            <Scheme as AdaptorSignatureScheme>::extract(
                &pre_sig,
                &adapted_sig,
                &adaptor_pk,
                &signer_sk,
                &extraction_key,
            )
            .unwrap();


        assert_ne!(
            extracted_sk.0,
            adaptor_sk.0,
        );
    }
}