use criterion::{
    criterion_group,
    criterion_main,
    BenchmarkId,
    Criterion,
    SamplingMode,
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
// Configuration
// ============================================================

// Each Criterion sample measures one batch consisting of N distinct
// protocol instances.  Setup/key generation and preparation of the
// pre-signatures/full signatures used by deterministic algorithms are
// performed outside the timed region.
//
// The five batch sizes are used for the scaling experiment.
const BATCH_SIZES: &[u64] = &[1, 10, 100, 500, 1000];


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
// Independent batch messages
// ============================================================

// We keep the long-term keys fixed for each scheme, as in a realistic
// signer/adaptor deployment, while each batch element uses a distinct
// message and independently generated pre-signature randomness.
//
// For deterministic algorithms (pVrfy, Adapt, (Sec)Ext, Vrfy), all
// per-instance inputs are prepared before timing.  Thus the benchmark
// measures only the target algorithm, not instance construction.
fn make_messages() -> Vec<[u8; 32]> {
    let max_batch_size =
        *BATCH_SIZES
            .iter()
            .max()
            .unwrap() as usize;

    (0..max_batch_size)
        .map(|index| {
            let mut message =
                [0u8; 32];

            message[..8]
                .copy_from_slice(
                    &(index as u64)
                        .to_le_bytes(),
                );

            message
        })
        .collect()
}


// ============================================================
// Shared helper for batch-size benchmarks
// ============================================================

fn benchmark_batches<F>(
    c: &mut Criterion,
    group_name: &str,
    mut operation: F,
)
where
    F: FnMut(usize),
{
    let mut group =
        c.benchmark_group(group_name);

    // 4 schemes x 5 algorithms x 5 batch sizes = 100 benchmark points.
    //
    // Large BBS+ batches can take seconds per Criterion iteration.
    // Flat sampling avoids Criterion increasing the iteration count
    // aggressively for these long-running benchmark points.
    group.sample_size(10);

    group.sampling_mode(
        SamplingMode::Flat,
    );

    group.warm_up_time(
        Duration::from_secs(1),
    );

    group.measurement_time(
        Duration::from_secs(5),
    );

    for &batch_size in BATCH_SIZES {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &n| {
                let n =
                    n as usize;

                b.iter(|| {
                    for index in 0..n {
                        operation(
                            black_box(index),
                        );
                    }
                });
            },
        );
    }

    group.finish();
}


// ============================================================
// Scheme 1: Schnorr-based adaptor signature
// ============================================================

fn benchmark_scheme1_scaling(
    c: &mut Criterion,
) {
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

    let messages =
        make_messages();

    // Prepare N independent instances outside timing.
    let mut pre_sigs =
        Vec::with_capacity(messages.len());

    let mut adapted_sigs =
        Vec::with_capacity(messages.len());

    for message in &messages {
        let pre_sig =
            <Scheme as Scheme1Adaptor>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();

        let adapted_sig =
            <Scheme as Scheme1Adaptor>::adapt(
                &pre_sig,
                &adaptor_sk,
            )
            .unwrap();

        pre_sigs.push(
            pre_sig,
        );

        adapted_sigs.push(
            adapted_sig,
        );
    }

    benchmark_batches(
        c,
        "Scaling/Scheme1/PreSign",
        |index| {
            let result =
                <Scheme as Scheme1Adaptor>::pre_sign(
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&signer_sk),
                    black_box(&messages[index]),
                    rng,
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme1/PreVrfy",
        |index| {
            let result =
                <Scheme as Scheme1Adaptor>::verify(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&messages[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme1/Adapt",
        |index| {
            let result =
                <Scheme as Scheme1Adaptor>::adapt(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_sk),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme1/Extract",
        |index| {
            let result =
                <Scheme as Scheme1Adaptor>::extract(
                    black_box(&pre_sigs[index]),
                    black_box(&adapted_sigs[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme1/Vrfy",
        |index| {
            let result =
                <Scheme as Scheme1Adaptor>
                    ::verify_full_signature(
                        black_box(&adapted_sigs[index]),
                        black_box(&signer_pk),
                        black_box(&messages[index]),
                    )
                    .unwrap();

            black_box(result);
        },
    );
}


// ============================================================
// Scheme 2: Trivial solution
// ============================================================

fn benchmark_scheme2_scaling(
    c: &mut Criterion,
) {
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

    let messages =
        make_messages();

    // Prepare N independent instances outside timing.
    let mut pre_sigs =
        Vec::with_capacity(messages.len());

    let mut extraction_keys =
        Vec::with_capacity(messages.len());

    let mut adapted_sigs =
        Vec::with_capacity(messages.len());

    for message in &messages {
        let (
            pre_sig,
            extraction_key,
        ) =
            <Scheme as Scheme2Adaptor>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();

        let adapted_sig =
            <Scheme as Scheme2Adaptor>::adapt(
                &pre_sig,
                &adaptor_sk,
            )
            .unwrap();

        pre_sigs.push(
            pre_sig,
        );

        extraction_keys.push(
            extraction_key,
        );

        adapted_sigs.push(
            adapted_sig,
        );
    }

    benchmark_batches(
        c,
        "Scaling/Scheme2/PreSign",
        |index| {
            let result =
                <Scheme as Scheme2Adaptor>::pre_sign(
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&signer_sk),
                    black_box(&messages[index]),
                    rng,
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme2/PreVrfy",
        |index| {
            let result =
                <Scheme as Scheme2Adaptor>::verify(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&adaptor_sk),
                    black_box(&signer_pk),
                    black_box(&messages[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme2/Adapt",
        |index| {
            let result =
                <Scheme as Scheme2Adaptor>::adapt(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_sk),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme2/Extract",
        |index| {
            let result =
                <Scheme as Scheme2Adaptor>::extract(
                    black_box(&extraction_keys[index]),
                    black_box(&adapted_sigs[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme2/Vrfy",
        |index| {
            let result =
                <Scheme as Scheme2Adaptor>
                    ::verify_full_signature(
                        black_box(&adapted_sigs[index]),
                        black_box(&signer_pk),
                        black_box(&messages[index]),
                    )
                    .unwrap();

            black_box(result);
        },
    );
}


// ============================================================
// Scheme 3: ASSET
// ============================================================

fn benchmark_scheme3_scaling(
    c: &mut Criterion,
) {
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

    let messages =
        make_messages();

    // Prepare N independent instances outside timing.
    let mut pre_sigs =
        Vec::with_capacity(messages.len());

    let mut extraction_keys =
        Vec::with_capacity(messages.len());

    let mut adapted_sigs =
        Vec::with_capacity(messages.len());

    for message in &messages {
        let (
            pre_sig,
            extraction_key,
        ) =
            <Scheme as Scheme3Adaptor>::pre_sign(
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
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

        pre_sigs.push(
            pre_sig,
        );

        extraction_keys.push(
            extraction_key,
        );

        adapted_sigs.push(
            adapted_sig,
        );
    }

    benchmark_batches(
        c,
        "Scaling/Scheme3/PreSign",
        |index| {
            let result =
                <Scheme as Scheme3Adaptor>::pre_sign(
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&signer_sk),
                    black_box(&messages[index]),
                    rng,
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme3/PreVrfy",
        |index| {
            let result =
                <Scheme as Scheme3Adaptor>::verify(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&adaptor_sk),
                    black_box(&signer_pk),
                    black_box(&messages[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme3/Adapt",
        |index| {
            let result =
                <Scheme as Scheme3Adaptor>::adapt(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&adaptor_sk),
                    black_box(&signer_pk),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme3/Extract",
        |index| {
            let result =
                <Scheme as Scheme3Adaptor>::extract(
                    black_box(&pre_sigs[index]),
                    black_box(&adapted_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&signer_sk),
                    black_box(&extraction_keys[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme3/Vrfy",
        |index| {
            let result =
                <Scheme as Scheme3Adaptor>
                    ::verify_full_signature(
                        black_box(&adapted_sigs[index]),
                        black_box(&signer_pk),
                        black_box(&messages[index]),
                    )
                    .unwrap();

            black_box(result);
        },
    );
}


// ============================================================
// Scheme 4: BBS+-based adaptor signature
// ============================================================

fn benchmark_scheme4_scaling(
    c: &mut Criterion,
) {
    let rng =
        &mut test_rng();

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

    let messages =
        make_messages();

    // Prepare N independent instances outside timing.
    let mut pre_sigs =
        Vec::with_capacity(messages.len());

    let mut adapted_sigs =
        Vec::with_capacity(messages.len());

    for message in &messages {
        let pre_sig =
            <BbsPlusAdaptor as Scheme4Adaptor>::pre_sign(
                &params,
                &adaptor_pk,
                &signer_pk,
                &signer_sk,
                message,
                rng,
            )
            .unwrap();

        let adapted_sig =
            <BbsPlusAdaptor as Scheme4Adaptor>::adapt(
                &pre_sig,
                &adaptor_sk,
            )
            .unwrap();

        pre_sigs.push(
            pre_sig,
        );

        adapted_sigs.push(
            adapted_sig,
        );
    }

    benchmark_batches(
        c,
        "Scaling/Scheme4/PreSign",
        |index| {
            let result =
                <BbsPlusAdaptor as Scheme4Adaptor>::pre_sign(
                    black_box(&params),
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&signer_sk),
                    black_box(&messages[index]),
                    rng,
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme4/PreVrfy",
        |index| {
            let result =
                <BbsPlusAdaptor as Scheme4Adaptor>::verify(
                    black_box(&params),
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_pk),
                    black_box(&signer_pk),
                    black_box(&messages[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme4/Adapt",
        |index| {
            let result =
                <BbsPlusAdaptor as Scheme4Adaptor>::adapt(
                    black_box(&pre_sigs[index]),
                    black_box(&adaptor_sk),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme4/Extract",
        |index| {
            let result =
                <BbsPlusAdaptor as Scheme4Adaptor>::extract(
                    black_box(&pre_sigs[index]),
                    black_box(&adapted_sigs[index]),
                )
                .unwrap();

            black_box(result);
        },
    );

    benchmark_batches(
        c,
        "Scaling/Scheme4/Vrfy",
        |index| {
            let result =
                <BbsPlusAdaptor as Scheme4Adaptor>
                    ::verify_full_signature(
                        black_box(&params),
                        black_box(&adapted_sigs[index]),
                        black_box(&signer_pk),
                        black_box(&messages[index]),
                    )
                    .unwrap();

            black_box(result);
        },
    );
}


// ============================================================
// Criterion configuration
// ============================================================

criterion_group! {
    name = scaling_benches;

    // Per-group settings are configured in benchmark_batches().
    config = Criterion::default();

    targets =
        benchmark_scheme1_scaling,
        benchmark_scheme2_scaling,
        benchmark_scheme3_scaling,
        benchmark_scheme4_scaling
}

criterion_main!(
    scaling_benches
);
