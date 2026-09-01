use criterion::{
    criterion_group,
    criterion_main,
    Criterion,
};

use std::hint::black_box;
use std::time::Duration;

use ark_crypto_primitives::signature::schnorr::Schnorr;
use ark_crypto_primitives::signature::SignatureScheme;

use ark_ec::{
    CurveGroup,
    Group,
};

use ark_secp256k1::Projective as Secp256k1;
use ark_serialize::CanonicalSerialize;

use ark_std::rand::Rng;
use ark_std::test_rng;

use asset::scheme1::AdaptorSignatureScheme as Scheme1Adaptor;
use asset::scheme2::AdaptorSignatureScheme as Scheme2Adaptor;
use asset::scheme3::AdaptorSignatureScheme as Scheme3Adaptor;

use asset::scheme4::{
    AdaptorSignatureScheme as Scheme4Adaptor,
    BbsPlusAdaptor,
};

use sha3::Keccak256;


// ============================================================
// Schnorr scheme used by Schemes 1--3
// ============================================================

type Scheme =
    Schnorr<
        Secp256k1,
        Keccak256,
    >;


// ============================================================
// Schnorr key generation
//
// Used only by Schemes 1--3.
// Setup and key generation are excluded from benchmarking.
// ============================================================

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








// ============================================================
// Compressed serialized size helper
//
// This helper measures the concrete byte length under Arkworks'
// compressed canonical serialization. These sizes correspond to
// the cryptographic object sizes used in Table III.
// ============================================================

fn compressed_size<T: CanonicalSerialize>(
    value: &T,
) -> usize {

    let mut bytes =
        Vec::new();

    value
        .serialize_compressed(
            &mut bytes,
        )
        .unwrap();

    bytes.len()
}


// ============================================================
// Scheme 1
//
// Schnorr-based adaptor signature
// ============================================================

fn benchmark_scheme1(
    c: &mut Criterion,
) {

    let rng =
        &mut test_rng();


    // --------------------------------------------------------
    // Setup: excluded from benchmark
    // --------------------------------------------------------

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
        [0u8; 32];


    // --------------------------------------------------------
    // Generate inputs for subsequent algorithms.
    //
    // These operations are not included in the timing of
    // pVrfy, Adapt, Extract, or Vrfy.
    // --------------------------------------------------------

    let pre_sig =
        <Scheme as Scheme1Adaptor>::pre_sign(
            &adaptor_pk,
            &signer_pk,
            &signer_sk,
            &message,
            rng,
        )
        .unwrap();


    let adapted_sig =
        <Scheme as Scheme1Adaptor>::adapt(
            &pre_sig,
            &adaptor_sk,
        )
        .unwrap();


    // ========================================================
    // PreSign
    // ========================================================

    c.bench_function(
        "Scheme1/PreSign",
        |b| {

            b.iter(|| {

                let sig =
                    <Scheme as Scheme1Adaptor>::pre_sign(
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&signer_sk),
                        black_box(&message),
                        rng,
                    )
                    .unwrap();


                black_box(sig);
            });
        },
    );


    // ========================================================
    // PreVrfy
    // ========================================================

    c.bench_function(
        "Scheme1/PreVrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme1Adaptor>::verify(
                        black_box(&pre_sig),
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&message),
                    );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Adapt
    // ========================================================

    c.bench_function(
        "Scheme1/Adapt",
        |b| {

            b.iter(|| {

                let sig =
                    <Scheme as Scheme1Adaptor>::adapt(
                        black_box(&pre_sig),
                        black_box(&adaptor_sk),
                    )
                    .unwrap();


                black_box(sig);
            });
        },
    );


    // ========================================================
    // Extract
    // ========================================================

    c.bench_function(
        "Scheme1/Extract",
        |b| {

            b.iter(|| {

                let sk =
                    <Scheme as Scheme1Adaptor>::extract(
                        black_box(&pre_sig),
                        black_box(&adapted_sig),
                    )
                    .unwrap();


                black_box(sk);
            });
        },
    );


    // ========================================================
    // Vrfy
    //
    // Full Schnorr signature verification
    // ========================================================

    c.bench_function(
        "Scheme1/Vrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme1Adaptor>
                        ::verify_full_signature(
                            black_box(&adapted_sig),
                            black_box(&signer_pk),
                            black_box(&message),
                        );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Storage
    // ========================================================

    // --------------------------------------------------------
    // Pre-signature = (R, s_tilde)
    // --------------------------------------------------------

    let mut pre_sig_bytes =
        Vec::new();


    pre_sig
        .commitment
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .prover_response
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Full signature = (R, s)
    // --------------------------------------------------------

    let mut full_sig_bytes =
        Vec::new();


    adapted_sig
        .commitment
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    adapted_sig
        .prover_response
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Concrete storage cost corresponding to Table III
    //
    // Signer:
    //   signing public key + signing secret key + pre-signature
    //
    // Adaptor:
    //   statement + witness + pre-signature
    //
    // Blockchain:
    //   full signature
    // --------------------------------------------------------

    let signer_pk_size =
        compressed_size(
            &signer_pk,
        );

    let signer_sk_size =
        compressed_size(
            &signer_sk,
        );

    let adaptor_pk_size =
        compressed_size(
            &adaptor_pk,
        );

    let adaptor_sk_size =
        compressed_size(
            &adaptor_sk,
        );


    let signer_storage_bytes =
        signer_pk_size
        + signer_sk_size
        + pre_sig_bytes.len();


    let adaptor_storage_bytes =
        adaptor_pk_size
        + adaptor_sk_size
        + pre_sig_bytes.len();


    let blockchain_storage_bytes =
        full_sig_bytes.len();


    println!(
        "Scheme 1 pre-signature size: {} bytes",
        pre_sig_bytes.len(),
    );


    println!(
        "Scheme 1 full signature size: {} bytes",
        full_sig_bytes.len(),
    );


    println!(
        "Scheme 1 extraction key size: 0 bytes",
    );


    println!(
        "Scheme 1 signer storage size: {} bytes",
        signer_storage_bytes,
    );


    println!(
        "Scheme 1 adaptor storage size: {} bytes",
        adaptor_storage_bytes,
    );


    println!(
        "Scheme 1 blockchain storage size: {} bytes",
        blockchain_storage_bytes,
    );
}


// ============================================================
// Scheme 2
//
// Trivial solution
// ============================================================

fn benchmark_scheme2(
    c: &mut Criterion,
) {

    let rng =
        &mut test_rng();


    // --------------------------------------------------------
    // Setup: excluded from benchmark
    // --------------------------------------------------------

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
        [0u8; 32];


    // --------------------------------------------------------
    // Generate inputs for subsequent algorithms
    // --------------------------------------------------------

    let (
        pre_sig,
        extraction_key,
    ) =
        <Scheme as Scheme2Adaptor>::pre_sign(
            &adaptor_pk,
            &signer_pk,
            &signer_sk,
            &message,
            rng,
        )
        .unwrap();


    let adapted_sig =
        <Scheme as Scheme2Adaptor>::adapt(
            &pre_sig,
            &adaptor_sk,
        )
        .unwrap();


    // ========================================================
    // PreSign
    // ========================================================

    c.bench_function(
        "Scheme2/PreSign",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme2Adaptor>::pre_sign(
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&signer_sk),
                        black_box(&message),
                        rng,
                    )
                    .unwrap();


                black_box(result);
            });
        },
    );


    // ========================================================
    // PreVrfy
    // ========================================================

    c.bench_function(
        "Scheme2/PreVrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme2Adaptor>::verify(
                        black_box(&pre_sig),
                        black_box(&adaptor_pk),
                        black_box(&adaptor_sk),
                        black_box(&signer_pk),
                        black_box(&message),
                    );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Adapt
    // ========================================================

    c.bench_function(
        "Scheme2/Adapt",
        |b| {

            b.iter(|| {

                let sig =
                    <Scheme as Scheme2Adaptor>::adapt(
                        black_box(&pre_sig),
                        black_box(&adaptor_sk),
                    )
                    .unwrap();


                black_box(sig);
            });
        },
    );


    // ========================================================
    // Extract
    // ========================================================

    c.bench_function(
        "Scheme2/Extract",
        |b| {

            b.iter(|| {

                let sk =
                    <Scheme as Scheme2Adaptor>::extract(
                        black_box(&extraction_key),
                        black_box(&adapted_sig),
                    )
                    .unwrap();


                black_box(sk);
            });
        },
    );


    // ========================================================
    // Vrfy
    //
    // The final signature is an ordinary Schnorr signature.
    // No decryption is needed here.
    // ========================================================

    c.bench_function(
        "Scheme2/Vrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme2Adaptor>
                        ::verify_full_signature(
                            black_box(&adapted_sig),
                            black_box(&signer_pk),
                            black_box(&message),
                        );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Storage
    // ========================================================

    // --------------------------------------------------------
    // Pre-signature = (R, U, s_hat)
    // --------------------------------------------------------

    let mut pre_sig_bytes =
        Vec::new();


    pre_sig
        .commitment
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .encryption_commitment
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .encrypted_response
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Full signature = (R, s)
    // --------------------------------------------------------

    let mut full_sig_bytes =
        Vec::new();


    adapted_sig
        .commitment
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    adapted_sig
        .prover_response
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Extraction key = s_tilde
    // --------------------------------------------------------

    let mut extraction_key_bytes =
        Vec::new();


    extraction_key
        .serialize_compressed(
            &mut extraction_key_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Concrete storage cost corresponding to Table III
    //
    // Signer:
    //   signing public key + signing secret key
    //   + encrypted pre-signature + extraction key
    //
    // Adaptor:
    //   statement + witness + encrypted pre-signature
    //
    // Blockchain:
    //   full signature
    // --------------------------------------------------------

    let signer_pk_size =
        compressed_size(
            &signer_pk,
        );

    let signer_sk_size =
        compressed_size(
            &signer_sk,
        );

    let adaptor_pk_size =
        compressed_size(
            &adaptor_pk,
        );

    let adaptor_sk_size =
        compressed_size(
            &adaptor_sk,
        );


    let signer_storage_bytes =
        signer_pk_size
        + signer_sk_size
        + pre_sig_bytes.len()
        + extraction_key_bytes.len();


    let adaptor_storage_bytes =
        adaptor_pk_size
        + adaptor_sk_size
        + pre_sig_bytes.len();


    let blockchain_storage_bytes =
        full_sig_bytes.len();


    println!(
        "Scheme 2 pre-signature size: {} bytes",
        pre_sig_bytes.len(),
    );


    println!(
        "Scheme 2 full signature size: {} bytes",
        full_sig_bytes.len(),
    );


    println!(
        "Scheme 2 extraction key size: {} bytes",
        extraction_key_bytes.len(),
    );


    println!(
        "Scheme 2 signer storage size: {} bytes",
        signer_storage_bytes,
    );


    println!(
        "Scheme 2 adaptor storage size: {} bytes",
        adaptor_storage_bytes,
    );


    println!(
        "Scheme 2 blockchain storage size: {} bytes",
        blockchain_storage_bytes,
    );
}


// ============================================================
// Scheme 3
//
// ASSET
// ============================================================

fn benchmark_scheme3(
    c: &mut Criterion,
) {

    let rng =
        &mut test_rng();


    // --------------------------------------------------------
    // Setup: excluded from benchmark
    // --------------------------------------------------------

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
        [0u8; 32];


    // --------------------------------------------------------
    // Generate inputs for subsequent algorithms
    // --------------------------------------------------------

    let (
        pre_sig,
        extraction_key,
    ) =
        <Scheme as Scheme3Adaptor>::pre_sign(
            &adaptor_pk,
            &signer_pk,
            &signer_sk,
            &message,
            rng,
        )
        .unwrap();


    let adapted_sig =
        <Scheme as Scheme3Adaptor>::adapt(
            &pre_sig,
            &adaptor_pk,
            &adaptor_sk,
            &signer_pk,
        )
        .unwrap();


    // ========================================================
    // PreSign
    // ========================================================

    c.bench_function(
        "Scheme3/PreSign",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme3Adaptor>::pre_sign(
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&signer_sk),
                        black_box(&message),
                        rng,
                    )
                    .unwrap();


                black_box(result);
            });
        },
    );


    // ========================================================
    // PreVrfy
    // ========================================================

    c.bench_function(
        "Scheme3/PreVrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme3Adaptor>::verify(
                        black_box(&pre_sig),
                        black_box(&adaptor_pk),
                        black_box(&adaptor_sk),
                        black_box(&signer_pk),
                        black_box(&message),
                    );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Adapt
    // ========================================================

    c.bench_function(
        "Scheme3/Adapt",
        |b| {

            b.iter(|| {

                let sig =
                    <Scheme as Scheme3Adaptor>::adapt(
                        black_box(&pre_sig),
                        black_box(&adaptor_pk),
                        black_box(&adaptor_sk),
                        black_box(&signer_pk),
                    )
                    .unwrap();


                black_box(sig);
            });
        },
    );


    // ========================================================
    // SecExt
    // ========================================================

    c.bench_function(
        "Scheme3/Extract",
        |b| {

            b.iter(|| {

                let sk =
                    <Scheme as Scheme3Adaptor>::extract(
                        black_box(&pre_sig),
                        black_box(&adapted_sig),
                        black_box(&adaptor_pk),
                        black_box(&signer_sk),
                        black_box(&extraction_key),
                    )
                    .unwrap();


                black_box(sk);
            });
        },
    );


    // ========================================================
    // Vrfy
    //
    // ASSET full-signature verification:
    //
    // c = H2(X || R || m)
    // sG = R + cX
    // ========================================================

    c.bench_function(
        "Scheme3/Vrfy",
        |b| {

            b.iter(|| {

                let result =
                    <Scheme as Scheme3Adaptor>
                        ::verify_full_signature(
                            black_box(&adapted_sig),
                            black_box(&signer_pk),
                            black_box(&message),
                        );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Storage
    // ========================================================

    // --------------------------------------------------------
    // Pre-signature = (R_tilde, s_tilde)
    // --------------------------------------------------------

    let mut pre_sig_bytes =
        Vec::new();


    pre_sig
        .commitment
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .prover_response
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Full signature = (R, s)
    // --------------------------------------------------------

    let mut full_sig_bytes =
        Vec::new();


    adapted_sig
        .commitment
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    adapted_sig
        .prover_response
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Extraction key = r
    // --------------------------------------------------------

    let mut extraction_key_bytes =
        Vec::new();


    extraction_key
        .serialize_compressed(
            &mut extraction_key_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Concrete storage cost corresponding to Table III
    //
    // Signer:
    //   signing public key + signing secret key
    //   + pre-signature + extraction key ek
    //
    // Adaptor:
    //   statement + witness + pre-signature
    //
    // Blockchain:
    //   full signature
    // --------------------------------------------------------

    let signer_pk_size =
        compressed_size(
            &signer_pk,
        );

    let signer_sk_size =
        compressed_size(
            &signer_sk,
        );

    let adaptor_pk_size =
        compressed_size(
            &adaptor_pk,
        );

    let adaptor_sk_size =
        compressed_size(
            &adaptor_sk,
        );


    let signer_storage_bytes =
        signer_pk_size
        + signer_sk_size
        + pre_sig_bytes.len()
        + extraction_key_bytes.len();


    let adaptor_storage_bytes =
        adaptor_pk_size
        + adaptor_sk_size
        + pre_sig_bytes.len();


    let blockchain_storage_bytes =
        full_sig_bytes.len();


    println!(
        "Scheme 3 pre-signature size: {} bytes",
        pre_sig_bytes.len(),
    );


    println!(
        "Scheme 3 full signature size: {} bytes",
        full_sig_bytes.len(),
    );


    println!(
        "Scheme 3 extraction key size: {} bytes",
        extraction_key_bytes.len(),
    );


    println!(
        "Scheme 3 signer storage size: {} bytes",
        signer_storage_bytes,
    );


    println!(
        "Scheme 3 adaptor storage size: {} bytes",
        adaptor_storage_bytes,
    );


    println!(
        "Scheme 3 blockchain storage size: {} bytes",
        blockchain_storage_bytes,
    );
}


// ============================================================
// Scheme 4
//
// BBS+-based adaptor signature
// ============================================================

fn benchmark_scheme4(
    c: &mut Criterion,
) {

    let rng =
        &mut test_rng();


    // ========================================================
    // Setup: excluded from benchmark
    // ========================================================

    let params =
        <BbsPlusAdaptor as Scheme4Adaptor>::setup(
            rng,
        );


    let (
        signer_pk,
        signer_sk,
    ) =
        <BbsPlusAdaptor as Scheme4Adaptor>::keygen(
            &params,
            rng,
        );


    let (
        adaptor_pk,
        adaptor_sk,
    ) =
        <BbsPlusAdaptor as Scheme4Adaptor>::adaptor_keygen(
            &params,
            rng,
        );


    let message =
        [0u8; 32];


    // --------------------------------------------------------
    // Generate inputs for subsequent algorithms
    // --------------------------------------------------------

    let pre_sig =
        <BbsPlusAdaptor as Scheme4Adaptor>::pre_sign(
            &params,
            &adaptor_pk,
            &signer_pk,
            &signer_sk,
            &message,
            rng,
        )
        .unwrap();


    let adapted_sig =
        <BbsPlusAdaptor as Scheme4Adaptor>::adapt(
            &pre_sig,
            &adaptor_sk,
        )
        .unwrap();


    // ========================================================
    // PreSign
    // ========================================================

    c.bench_function(
        "Scheme4/PreSign",
        |b| {

            b.iter(|| {

                let result =
                    <BbsPlusAdaptor as Scheme4Adaptor>::pre_sign(
                        black_box(&params),
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&signer_sk),
                        black_box(&message),
                        rng,
                    )
                    .unwrap();


                black_box(result);
            });
        },
    );


    // ========================================================
    // PreVrfy
    // ========================================================

    c.bench_function(
        "Scheme4/PreVrfy",
        |b| {

            b.iter(|| {

                let result =
                    <BbsPlusAdaptor as Scheme4Adaptor>::verify(
                        black_box(&params),
                        black_box(&pre_sig),
                        black_box(&adaptor_pk),
                        black_box(&signer_pk),
                        black_box(&message),
                    );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Adapt
    // ========================================================

    c.bench_function(
        "Scheme4/Adapt",
        |b| {

            b.iter(|| {

                let sig =
                    <BbsPlusAdaptor as Scheme4Adaptor>::adapt(
                        black_box(&pre_sig),
                        black_box(&adaptor_sk),
                    )
                    .unwrap();


                black_box(sig);
            });
        },
    );


    // ========================================================
    // Extract
    // ========================================================

    c.bench_function(
        "Scheme4/Extract",
        |b| {

            b.iter(|| {

                let sk =
                    <BbsPlusAdaptor as Scheme4Adaptor>::extract(
                        black_box(&pre_sig),
                        black_box(&adapted_sig),
                    )
                    .unwrap();


                black_box(sk);
            });
        },
    );


    // ========================================================
    // Vrfy
    //
    // Full BBS+ signature verification:
    //
    // e(A, vk + e*h0)
    //
    //      =
    //
    // e(g0 + r*g1 + m*g2, h0)
    // ========================================================

    c.bench_function(
        "Scheme4/Vrfy",
        |b| {

            b.iter(|| {

                let result =
                    <BbsPlusAdaptor as Scheme4Adaptor>
                        ::verify_full_signature(
                            black_box(&params),
                            black_box(&adapted_sig),
                            black_box(&signer_pk),
                            black_box(&message),
                        );


                black_box(result)
                    .unwrap();
            });
        },
    );


    // ========================================================
    // Storage
    // ========================================================

    // --------------------------------------------------------
    // Pre-signature = (A, e, r)
    // --------------------------------------------------------

    let mut pre_sig_bytes =
        Vec::new();


    pre_sig
        .a
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .e
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    pre_sig
        .r
        .serialize_compressed(
            &mut pre_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Full signature = (A, e, r')
    // --------------------------------------------------------

    let mut full_sig_bytes =
        Vec::new();


    adapted_sig
        .a
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    adapted_sig
        .e
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    adapted_sig
        .r
        .serialize_compressed(
            &mut full_sig_bytes,
        )
        .unwrap();


    // --------------------------------------------------------
    // Concrete storage cost corresponding to Table III
    //
    // Signer:
    //   signing public key + signing secret key + pre-signature
    //
    // Adaptor:
    //   statement + witness + pre-signature
    //
    // Blockchain:
    //   full signature
    // --------------------------------------------------------

    let signer_pk_size =
        compressed_size(
            &signer_pk.0,
        );

    let signer_sk_size =
        compressed_size(
            &signer_sk.0,
        );

    let adaptor_pk_size =
        compressed_size(
            &adaptor_pk,
        );

    let adaptor_sk_size =
        compressed_size(
            &adaptor_sk,
        );


    let signer_storage_bytes =
        signer_pk_size
        + signer_sk_size
        + pre_sig_bytes.len();


    let adaptor_storage_bytes =
        adaptor_pk_size
        + adaptor_sk_size
        + pre_sig_bytes.len();


    let blockchain_storage_bytes =
        full_sig_bytes.len();


    println!(
        "Scheme 4 pre-signature size: {} bytes",
        pre_sig_bytes.len(),
    );


    println!(
        "Scheme 4 full signature size: {} bytes",
        full_sig_bytes.len(),
    );


    println!(
        "Scheme 4 extraction key size: 0 bytes",
    );


    println!(
        "Scheme 4 signer storage size: {} bytes",
        signer_storage_bytes,
    );


    println!(
        "Scheme 4 adaptor storage size: {} bytes",
        adaptor_storage_bytes,
    );


    println!(
        "Scheme 4 blockchain storage size: {} bytes",
        blockchain_storage_bytes,
    );
}


// ============================================================
// Criterion configuration
// ============================================================

criterion_group! {

    name = benches;

    config =
        Criterion::default()
            .sample_size(100)
            .warm_up_time(
                Duration::from_secs(3),
            )
            .measurement_time(
                Duration::from_secs(20),
            );

    targets =
        benchmark_scheme1,
        benchmark_scheme2,
        benchmark_scheme3,
        benchmark_scheme4
}


criterion_main!(
    benches
);