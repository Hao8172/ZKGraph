use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof_multi},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use std::{
    collections::HashMap, fs::File, io::Write, marker::PhantomData, path::PathBuf, time::Instant,
};

use rand_core::OsRng;
use zkgraph::{
    circuit::{
        is_3::MyCircuit,
        utils::{parse_datetime, read_csv, string_to_u64},
    },
    data::csr::CsrValue,
};

fn main() {
    let k = 16;

    let all_time = Instant::now();
    println!("start...");

    println!("start to load data...");
    let data_load_start = Instant::now();

    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
        '|',
    )
    .expect("Failed to read person data");

    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
        '|',
    )
    .expect("Failed to read relation data");

    let mut person: Vec<Vec<u64>> = Vec::new();
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            string_to_u64(&row[1]),
            string_to_u64(&row[2]),
        ];
        person.push(person_row);
    }
    println!("person.len:{:?}", person.len());

    let mut person_knows_person: Vec<Vec<u64>> = Vec::new();
    for row in &relation_data {
        if row.len() >= 2 {
            let relation_row = vec![
                row[0].parse::<u64>().unwrap(),
                row[1].parse::<u64>().unwrap(),
                parse_datetime(&row[2]),
            ];
            person_knows_person.push(relation_row);
        }
    }
    println!("person_knows_person.len:{:?}", person_knows_person.len());

    let person_id = 933u64;

    let circuit = MyCircuit::<Fr> {
        person,
        person_id,
        person_knows_person,
        _marker: PhantomData,
    };

    // let mut processed_pkp_data_fr: Vec<Vec<Fr>> = Vec::new();
    //     for row_fr in &pkp_data_fr {
    //         let p1 = row_fr[0];
    //         let p2 = row_fr[1];
    //         let date = row_fr[2];

    //         processed_pkp_data_fr.push(vec![p1, p2, date]);

    //         if p1 != p2 {
    //             processed_pkp_data_fr.push(vec![p2, p1, date]);
    //         }
    //     }
    //     println!("original_pkp_data_fr.len: {:?}", pkp_data_fr.len());
    //     println!("processed_pkp_data_fr.len: {:?}", processed_pkp_data_fr.len());

    println!("data loading time taken: {:?}", data_load_start.elapsed());
    println!("k = {}", k);

    let params_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
        .join(format!("kzg_param{}", k));

    let params_start = Instant::now();
    let params = if params_path.exists() {
        println!("The parameter file already exists and is being read...");
        let mut file =
            File::open(&params_path).expect(&format!("invalid parameter file path: {:?}", params_path));
        Params::read::<_>(&mut file).unwrap()
    } else {
        println!("Parameter file does not exist, generating...");
        let params = ParamsKZG::<Bn256>::new(k);
        let mut file =
            File::create(&params_path).expect(&format!("invalid parameter file path: {:?}", params_path));
        <ParamsKZG<_> as Params<_>>::write(&params, &mut file).unwrap();
        params
    };
    println!("Parameter processing completed. Time taken: {:?}", params_start.elapsed());

    let keys_start = Instant::now();
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");
    println!("keys generating completed. Time taken: {:?}", keys_start.elapsed());

    println!("start proof generating...");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let public_input = vec![Fr::from(1)];
    let proof_start = Instant::now();
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[vec![public_input.clone()]],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    let proof = transcript.finalize();
    println!("proof generation completed. Time taken: {:?}", proof_start.elapsed());

    let proof_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
        .join("is3_proof.bin");
    let mut proof_file: File = File::create(&proof_file_path).expect("failed to create proof file");
    proof_file.write_all(&proof).expect("failed to write proof to file");

    let proof_file_metadata = std::fs::metadata(&proof_file_path).expect("failed to get metadata");
    let proof_size_bytes = proof_file_metadata.len();
    let proof_size_kb = proof_size_bytes as f64 / 1024.0;
    println!("proof size: {} bytes ({:.2} KB)", proof_size_bytes, proof_size_kb);

    let verifier_params = params.verifier_params();
    
    println!("start proof verifying...");
    let mut verifier_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.as_slice());

    let verify_start = Instant::now();
    assert!(
        verify_proof_multi::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<Bn256>,
            _,
            _,
            SingleStrategy<_>,
        >(
            &verifier_params,
            &vk,
            &[vec![public_input]],
            &mut verifier_transcript,
        ),
        "failed to verify proof"
    );

    println!("verification success. Time taken: {:?}", verify_start.elapsed());
    println!("The entire process is completed. Time taken: {:?}", all_time.elapsed());
}
