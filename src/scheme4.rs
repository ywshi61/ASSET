use ark_bls12_381::{
    Bls12_381,
    Fr,
    G1Affine,
    G1Projective,
    G2Affine,
    G2Projective,
};

use ark_crypto_primitives::Error;

use ark_ec::{
    pairing::Pairing,
    AffineRepr,
    CurveGroup,
    Group,
};

use ark_ff::{
    Field,
    PrimeField,
    UniformRand,
    Zero,
};

use ark_std::rand::Rng;


// ============================================================
// Public parameters
// ============================================================
//
// For one message m:
//
// g0, g1, g2 in G1
// h0 in G2
//
// g1 is also used for the adaptor relation:
//
//     Y = y * g1
//
// corresponding to:
//
//     Y = g1^y
//
// in the multiplicative notation.
// ============================================================

#[derive(Clone, Debug)]
pub struct PublicParameters {
    pub g0: G1Affine,
    pub g1: G1Affine,
    pub g2: G1Affine,
    pub h0: G2Affine,
}


// ============================================================
// BBS+ signing keys
// ============================================================

#[derive(Clone, Debug)]
pub struct PublicKey(
    pub G2Affine,
);

#[derive(Clone, Debug)]
pub struct SecretKey(
    pub Fr,
);


// ============================================================
// Adaptor statement / witness
// ============================================================
//
// Y = y * g1
//
// Y: G1 element
// y: scalar
// ============================================================

pub type AdaptorPublicKey = G1Affine;
pub type AdaptorSecretKey = Fr;


// ============================================================
// BBS+ adaptor pre-signature
// ============================================================
//
// sigma_tilde = (A, e, r)
//
// A =
//   (g0 + r*g1 + Y + m*g2)
//   /
//   (e + sk)
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorPreSignature {
    pub a: G1Affine,
    pub e: Fr,
    pub r: Fr,
}


// ============================================================
// Adapted BBS+ signature
// ============================================================
//
// sigma = (A, e, r')
//
// r' = r + y
// ============================================================

#[derive(Clone, Debug)]
pub struct AdaptorFullSignature {
    pub a: G1Affine,
    pub e: Fr,
    pub r: Fr,
}


// ============================================================
// Scheme marker
// ============================================================

pub struct BbsPlusAdaptor;


// ============================================================
// Adaptor signature trait
// ============================================================
//
// Main algorithms:
//
// pSign
// pVrfy
// Adapt
// Extract
// Vrfy
//
// Setup and key-generation functions are also included because
// BBS+ uses pairing-specific public parameters and key types.
// ============================================================

pub trait AdaptorSignatureScheme {

    // --------------------------------------------------------
    // Setup
    // --------------------------------------------------------

    fn setup<R: Rng>(
        rng: &mut R,
    ) -> PublicParameters;


    // --------------------------------------------------------
    // Signing key generation
    // --------------------------------------------------------

    fn keygen<R: Rng>(
        params: &PublicParameters,
        rng: &mut R,
    ) -> (
        PublicKey,
        SecretKey,
    );


    // --------------------------------------------------------
    // Adaptor statement / witness generation
    // --------------------------------------------------------

    fn adaptor_keygen<R: Rng>(
        params: &PublicParameters,
        rng: &mut R,
    ) -> (
        AdaptorPublicKey,
        AdaptorSecretKey,
    );


    // --------------------------------------------------------
    // pSign
    // --------------------------------------------------------

    fn pre_sign<R: Rng>(
        params: &PublicParameters,
        adaptor_pk: &AdaptorPublicKey,
        signer_pk: &PublicKey,
        signer_sk: &SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<AdaptorPreSignature, Error>;


    // --------------------------------------------------------
    // pVrfy
    // --------------------------------------------------------

    fn verify(
        params: &PublicParameters,
        signature: &AdaptorPreSignature,
        adaptor_pk: &AdaptorPublicKey,
        signer_pk: &PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;


    // --------------------------------------------------------
    // Adapt
    // --------------------------------------------------------

    fn adapt(
        signature: &AdaptorPreSignature,
        adaptor_sk: &AdaptorSecretKey,
    ) -> Result<AdaptorFullSignature, Error>;


    // --------------------------------------------------------
    // Extract
    // --------------------------------------------------------

    fn extract(
        pre_signature: &AdaptorPreSignature,
        signature: &AdaptorFullSignature,
    ) -> Result<AdaptorSecretKey, Error>;


    // --------------------------------------------------------
    // Vrfy
    // --------------------------------------------------------

    fn verify_full_signature(
        params: &PublicParameters,
        signature: &AdaptorFullSignature,
        signer_pk: &PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;
}


// ============================================================
// Helper: sample a nonzero scalar
// ============================================================

fn random_nonzero_scalar<R: Rng>(
    rng: &mut R,
) -> Fr {

    loop {

        let value =
            Fr::rand(rng);

        if !value.is_zero() {
            return value;
        }
    }
}


// ============================================================
// Helper: convert message to Z_p
// ============================================================
//
// BBS+ signs field elements rather than arbitrary byte strings.
//
// To keep the benchmark interface consistent with Schemes 1--3,
// the byte string is deterministically mapped into Fr.
//
// If the resulting scalar is zero, use 1 because the BBS+
// definition considered here uses messages in Z_p^*.
// ============================================================

fn message_to_scalar(
    message: &[u8],
) -> Fr {

    let mut value =
        Fr::from_be_bytes_mod_order(
            message,
        );


    if value.is_zero() {
        value =
            Fr::from(1u64);
    }


    value
}


// ============================================================
// BBS+-based adaptor signature implementation
// ============================================================

impl AdaptorSignatureScheme for BbsPlusAdaptor {


    // ========================================================
    // Setup
    // ========================================================
    //
    // Choose:
    //
    // g0, g1, g2 in G1
    // h0 in G2
    //
    // Setup is excluded from the timed benchmark.
    // ========================================================

    fn setup<R: Rng>(
        rng: &mut R,
    ) -> PublicParameters {

        let base_g1 =
            G1Projective::generator();


        // ----------------------------------------------------
        // g0
        // ----------------------------------------------------

        let g0 =
            (
                base_g1
                    * random_nonzero_scalar(rng)
            )
            .into_affine();


        // ----------------------------------------------------
        // g1
        // ----------------------------------------------------

        let g1 =
            (
                base_g1
                    * random_nonzero_scalar(rng)
            )
            .into_affine();


        // ----------------------------------------------------
        // g2
        // ----------------------------------------------------

        let g2 =
            (
                base_g1
                    * random_nonzero_scalar(rng)
            )
            .into_affine();


        // ----------------------------------------------------
        // h0
        // ----------------------------------------------------

        let h0 =
            G2Projective::generator()
                .into_affine();


        PublicParameters {
            g0,
            g1,
            g2,
            h0,
        }
    }


    // ========================================================
    // KeyGen
    // ========================================================
    //
    // sk <- Z_p^*
    //
    // vk = sk * h0
    //
    // corresponding to:
    //
    // vk = h0^sk
    // ========================================================

    fn keygen<R: Rng>(
        params: &PublicParameters,
        rng: &mut R,
    ) -> (
        PublicKey,
        SecretKey,
    ) {

        // ----------------------------------------------------
        // sk <- Z_p^*
        // ----------------------------------------------------

        let sk =
            random_nonzero_scalar(rng);


        // ----------------------------------------------------
        // vk = sk * h0
        // ----------------------------------------------------

        let vk =
            (
                params.h0.into_group()
                    * sk
            )
            .into_affine();


        (
            PublicKey(vk),
            SecretKey(sk),
        )
    }


    // ========================================================
    // Adaptor key generation
    // ========================================================
    //
    // y <- Z_p^*
    //
    // Y = y * g1
    //
    // corresponding to:
    //
    // Y = g1^y
    // ========================================================

    fn adaptor_keygen<R: Rng>(
        params: &PublicParameters,
        rng: &mut R,
    ) -> (
        AdaptorPublicKey,
        AdaptorSecretKey,
    ) {

        // ----------------------------------------------------
        // y <- Z_p^*
        // ----------------------------------------------------

        let y =
            random_nonzero_scalar(rng);


        // ----------------------------------------------------
        // Y = y * g1
        // ----------------------------------------------------

        let statement =
            (
                params.g1.into_group()
                    * y
            )
            .into_affine();


        (
            statement,
            y,
        )
    }


    // ========================================================
    // pSign
    // ========================================================
    //
    // Ordinary BBS+:
    //
    // A =
    //
    //   (g0 + r*g1 + m*g2)
    //   -----------------
    //       e + sk
    //
    //
    // Adaptor version:
    //
    // A =
    //
    //   (g0 + r*g1 + Y + m*g2)
    //   ---------------------
    //          e + sk
    //
    //
    // Output:
    //
    // sigma_tilde = (A, e, r)
    // ========================================================

    fn pre_sign<R: Rng>(
        params: &PublicParameters,
        adaptor_pk: &AdaptorPublicKey,
        _signer_pk: &PublicKey,
        signer_sk: &SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<AdaptorPreSignature, Error> {

        // ----------------------------------------------------
        // Encode message as m in Z_p
        // ----------------------------------------------------

        let m =
            message_to_scalar(
                message,
            );


        // ----------------------------------------------------
        // r <- Z_p^*
        // ----------------------------------------------------

        let r =
            random_nonzero_scalar(
                rng,
            );


        // ----------------------------------------------------
        // e <- Z_p^*
        //
        // Need:
        //
        // e + sk != 0
        //
        // so that the inverse exists.
        // ----------------------------------------------------

        let e;
        let inverse;


        loop {

            let candidate =
                random_nonzero_scalar(
                    rng,
                );


            let denominator =
                candidate
                    + signer_sk.0;


            if let Some(inv) =
                denominator.inverse()
            {
                e =
                    candidate;

                inverse =
                    inv;

                break;
            }
        }


        // ----------------------------------------------------
        // B =
        //
        // g0 + r*g1 + Y + m*g2
        // ----------------------------------------------------

        let base =
            params.g0.into_group()
                + params.g1.into_group() * r
                + adaptor_pk.into_group()
                + params.g2.into_group() * m;


        // ----------------------------------------------------
        // A =
        //
        // B / (e + sk)
        // ----------------------------------------------------

        let a =
            (
                base * inverse
            )
            .into_affine();


        // ----------------------------------------------------
        // sigma_tilde = (A, e, r)
        // ----------------------------------------------------

        Ok(
            AdaptorPreSignature {
                a,
                e,
                r,
            },
        )
    }


    // ========================================================
    // pVrfy
    // ========================================================
    //
    // Check:
    //
    // e(A, vk + e*h0)
    //
    //          =
    //
    // e(g0 + r*g1 + Y + m*g2, h0)
    //
    // ========================================================

    fn verify(
        params: &PublicParameters,
        signature: &AdaptorPreSignature,
        adaptor_pk: &AdaptorPublicKey,
        signer_pk: &PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        // ----------------------------------------------------
        // m
        // ----------------------------------------------------

        let m =
            message_to_scalar(
                message,
            );


        // ----------------------------------------------------
        // vk + e*h0
        // ----------------------------------------------------

        let second_left =
            (
                signer_pk.0.into_group()
                    + params.h0.into_group()
                        * signature.e
            )
            .into_affine();


        // ----------------------------------------------------
        // g0 + r*g1 + Y + m*g2
        // ----------------------------------------------------

        let second_base =
            (
                params.g0.into_group()
                    + params.g1.into_group()
                        * signature.r
                    + adaptor_pk.into_group()
                    + params.g2.into_group()
                        * m
            )
            .into_affine();


        // ----------------------------------------------------
        // Left pairing
        //
        // e(A, vk + e*h0)
        // ----------------------------------------------------

        let left =
            Bls12_381::pairing(
                signature.a,
                second_left,
            );


        // ----------------------------------------------------
        // Right pairing
        //
        // e(g0 + r*g1 + Y + m*g2, h0)
        // ----------------------------------------------------

        let right =
            Bls12_381::pairing(
                second_base,
                params.h0,
            );


        // ----------------------------------------------------
        // Compare
        // ----------------------------------------------------

        if left != right {

            Err(
                "BBS+ adaptor pre-signature verification failure"
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
    // Given:
    //
    // sigma_tilde = (A, e, r)
    //
    // and witness:
    //
    // y
    //
    // compute:
    //
    // r' = r + y
    //
    // output:
    //
    // sigma = (A, e, r')
    // ========================================================

    fn adapt(
        signature: &AdaptorPreSignature,
        adaptor_sk: &AdaptorSecretKey,
    ) -> Result<AdaptorFullSignature, Error> {

        // ----------------------------------------------------
        // r' = r + y
        // ----------------------------------------------------

        let adapted_r =
            signature.r
                + *adaptor_sk;


        // ----------------------------------------------------
        // sigma = (A, e, r')
        // ----------------------------------------------------

        Ok(
            AdaptorFullSignature {
                a:
                    signature.a,

                e:
                    signature.e,

                r:
                    adapted_r,
            },
        )
    }


    // ========================================================
    // Extract
    // ========================================================
    //
    // Given:
    //
    // sigma_tilde = (A, e, r)
    //
    // sigma       = (A, e, r')
    //
    // extract:
    //
    // y = r' - r
    // ========================================================

    fn extract(
        pre_signature: &AdaptorPreSignature,
        signature: &AdaptorFullSignature,
    ) -> Result<AdaptorSecretKey, Error> {

        let extracted_sk =
            signature.r
                - pre_signature.r;


        Ok(
            extracted_sk,
        )
    }


    // ========================================================
    // Vrfy
    // ========================================================
    //
    // After adaptation:
    //
    // r' = r + y
    //
    // and because:
    //
    // r*g1 + Y
    // =
    // r*g1 + y*g1
    // =
    // (r+y)*g1
    // =
    // r'*g1,
    //
    // the adapted signature is an ordinary BBS+ signature:
    //
    // sigma = (A, e, r')
    //
    //
    // Verify:
    //
    // e(A, vk + e*h0)
    //
    //          =
    //
    // e(g0 + r'*g1 + m*g2, h0)
    // ========================================================

    fn verify_full_signature(
        params: &PublicParameters,
        signature: &AdaptorFullSignature,
        signer_pk: &PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {

        // ----------------------------------------------------
        // m
        // ----------------------------------------------------

        let m =
            message_to_scalar(
                message,
            );


        // ----------------------------------------------------
        // vk + e*h0
        // ----------------------------------------------------

        let second_left =
            (
                signer_pk.0.into_group()
                    + params.h0.into_group()
                        * signature.e
            )
            .into_affine();


        // ----------------------------------------------------
        // g0 + r'*g1 + m*g2
        //
        // Note:
        //
        // adaptor statement Y no longer appears here.
        // ----------------------------------------------------

        let base =
            (
                params.g0.into_group()
                    + params.g1.into_group()
                        * signature.r
                    + params.g2.into_group()
                        * m
            )
            .into_affine();


        // ----------------------------------------------------
        // Left pairing:
        //
        // e(A, vk + e*h0)
        // ----------------------------------------------------

        let left =
            Bls12_381::pairing(
                signature.a,
                second_left,
            );


        // ----------------------------------------------------
        // Right pairing:
        //
        // e(g0 + r'*g1 + m*g2, h0)
        // ----------------------------------------------------

        let right =
            Bls12_381::pairing(
                base,
                params.h0,
            );


        // ----------------------------------------------------
        // Compare
        // ----------------------------------------------------

        if left != right {

            Err(
                "BBS+ signature verification failure"
                    .into(),
            )

        } else {

            Ok(())
        }
    }
}


// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod test {

    use super::*;

    use ark_std::test_rng;


    // ========================================================
    // Completeness
    // ========================================================

    #[test]
    fn completeness() {

        let rng =
            &mut test_rng();


        // ----------------------------------------------------
        // Setup
        // ----------------------------------------------------

        let params =
            <BbsPlusAdaptor as AdaptorSignatureScheme>::setup(
                rng,
            );


        // ----------------------------------------------------
        // BBS+ signer key generation
        // ----------------------------------------------------

        let (
            signer_pk,
            signer_sk,
        ) =
            <BbsPlusAdaptor as AdaptorSignatureScheme>::keygen(
                &params,
                rng,
            );


        // ----------------------------------------------------
        // Adaptor statement:
        //
        // Y = y*g1
        // ----------------------------------------------------

        let (
            adaptor_pk,
            adaptor_sk,
        ) =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adaptor_keygen(
                    &params,
                    rng,
                );


        // ----------------------------------------------------
        // Message
        // ----------------------------------------------------

        let message =
            b"hello BBS+ adaptor signature";


        // ----------------------------------------------------
        // pSign
        // ----------------------------------------------------

        let pre_sig =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::pre_sign(
                    &params,
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
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify(
                    &params,
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
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adapt(
                    &pre_sig,
                    &adaptor_sk,
                )
                .unwrap();


        // ----------------------------------------------------
        // Vrfy
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify_full_signature(
                    &params,
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
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::extract(
                    &pre_sig,
                    &adapted_sig,
                )
                .unwrap();


        // ----------------------------------------------------
        // Extracted witness must equal y
        // ----------------------------------------------------

        assert_eq!(
            extracted_sk,
            adaptor_sk,
        );
    }


    // ========================================================
    // Soundness
    // ========================================================

    #[test]
    fn soundness() {

        let rng =
            &mut test_rng();


        // ----------------------------------------------------
        // Setup
        // ----------------------------------------------------

        let params =
            <BbsPlusAdaptor as AdaptorSignatureScheme>::setup(
                rng,
            );


        // ----------------------------------------------------
        // Signer key
        // ----------------------------------------------------

        let (
            signer_pk,
            signer_sk,
        ) =
            <BbsPlusAdaptor as AdaptorSignatureScheme>::keygen(
                &params,
                rng,
            );


        // ----------------------------------------------------
        // Correct adaptor statement / witness
        // ----------------------------------------------------

        let (
            adaptor_pk,
            adaptor_sk,
        ) =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adaptor_keygen(
                    &params,
                    rng,
                );


        // ----------------------------------------------------
        // Different adaptor statement / witness
        // ----------------------------------------------------

        let (
            wrong_adaptor_pk,
            wrong_adaptor_sk,
        ) =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adaptor_keygen(
                    &params,
                    rng,
                );


        // ----------------------------------------------------
        // Message
        // ----------------------------------------------------

        let message =
            b"hello BBS+ adaptor signature";


        // ----------------------------------------------------
        // Generate valid pre-signature
        // ----------------------------------------------------

        let pre_sig =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::pre_sign(
                    &params,
                    &adaptor_pk,
                    &signer_pk,
                    &signer_sk,
                    message,
                    rng,
                )
                .unwrap();


        // ----------------------------------------------------
        // Correct statement => pVrfy succeeds
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify(
                    &params,
                    &pre_sig,
                    &adaptor_pk,
                    &signer_pk,
                    message,
                )
                .is_ok()
        );


        // ----------------------------------------------------
        // Wrong statement => pVrfy fails
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify(
                    &params,
                    &pre_sig,
                    &wrong_adaptor_pk,
                    &signer_pk,
                    message,
                )
                .is_err()
        );


        // ----------------------------------------------------
        // Wrong message => pVrfy fails
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify(
                    &params,
                    &pre_sig,
                    &adaptor_pk,
                    &signer_pk,
                    b"wrong message",
                )
                .is_err()
        );


        // ----------------------------------------------------
        // Correct adaptation
        // ----------------------------------------------------

        let correct_adapted_sig =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adapt(
                    &pre_sig,
                    &adaptor_sk,
                )
                .unwrap();


        // ----------------------------------------------------
        // Correctly adapted full signature => Vrfy succeeds
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify_full_signature(
                    &params,
                    &correct_adapted_sig,
                    &signer_pk,
                    message,
                )
                .is_ok()
        );


        // ----------------------------------------------------
        // Adapt using wrong adaptor secret key
        // ----------------------------------------------------

        let wrong_adapted_sig =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::adapt(
                    &pre_sig,
                    &wrong_adaptor_sk,
                )
                .unwrap();


        // ----------------------------------------------------
        // Wrong adaptor secret key => invalid full signature
        // ----------------------------------------------------

        assert!(
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::verify_full_signature(
                    &params,
                    &wrong_adapted_sig,
                    &signer_pk,
                    message,
                )
                .is_err()
        );


        // ----------------------------------------------------
        // Extract from incorrectly adapted signature
        //
        // Since:
        //
        // r' = r + wrong_y,
        //
        // extraction obtains exactly wrong_y.
        // ----------------------------------------------------

        let extracted_wrong_sk =
            <BbsPlusAdaptor as AdaptorSignatureScheme>
                ::extract(
                    &pre_sig,
                    &wrong_adapted_sig,
                )
                .unwrap();


        assert_eq!(
            extracted_wrong_sk,
            wrong_adaptor_sk,
        );


        assert_ne!(
            extracted_wrong_sk,
            adaptor_sk,
        );
    }
}