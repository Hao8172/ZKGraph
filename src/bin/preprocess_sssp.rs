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
        preprocess_sssp_from_ic1::MyCircuit,
        utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64},
    },
    data::csr::CsrValue,
};

fn main() {
    let k = 17;

    let all_time = Instant::now();
    println!("start...");

    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
        '|',
    )
    .expect("Failed to read data");
    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
        '|',
    )
    .expect("Failed to read data");

    let mut person_table: Vec<Vec<Fr>> = Vec::new();
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            Fr::from(row[0].parse::<u64>().expect("invalid ID")),
            Fr::from(string_to_u64(&row[1])),
            Fr::from(string_to_u64(&row[2])),
            Fr::from(if row[3] == "male" { 1 } else { 0 }),
            Fr::from(parse_date(&row[4])),
            Fr::from(parse_datetime(&row[5])),
            Fr::from(ipv4_to_u64(&row[6])),
            Fr::from(string_to_u64(&row[7])),
        ];
        person_table.push(person_row);
    }

    let mut original_pkp: Vec<Vec<Fr>> = Vec::new();
    for (_, row) in relation_data.iter().enumerate() {
        let r_row = vec![
            Fr::from(row[0].parse::<u64>().expect("invalid ID")),
            Fr::from(row[1].parse::<u64>().expect("invalid ID")),
        ];
        original_pkp.push(r_row);
    }

    let mut person_knows_person: Vec<Vec<Fr>> = Vec::new();
    for row_fr in &original_pkp {
        let p1 = row_fr[0];
        let p2 = row_fr[1];

        person_knows_person.push(vec![p1, p2]);

        if p1 != p2 {
            person_knows_person.push(vec![p2, p1]);
        }
    }

    println!("person:{:?}", person_table.len());
    println!("person_knows_person.len:{:?}", person_knows_person.len());

    let test_person_id_val: u64 = 21990232556585;
    let person_id_fr = Fr::from(test_person_id_val);

    let circuit = MyCircuit::<Fr> {
        person: person_table,
        person_knows_person,
        person_id: person_id_fr,
        _marker: PhantomData,
    };

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
