use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof_multi, Circuit},
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
        ic_1::MyCircuit,
        utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64},
    },
    data::csr::CsrValue,
};

fn main() {
    let all_time = Instant::now();
    println!("start...");

    let k = 16;

    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let email_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_email_emailaddress_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let language_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_speaks_language_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let location_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_isLocatedIn_place_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let place_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/place_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let studyat_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_studyAt_organisation_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let workat_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_workAt_organisation_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let organisation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/organisation_0_0.csv",
        '|',
    )
    .expect("Failed to load data");
    let org_location_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/organisation_isLocatedIn_place_0_0.csv",
            '|',
        ).expect("Failed to load data");

    let mut person_table = Vec::new();
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            string_to_u64(&row[1]),
            string_to_u64(&row[2]),
            if row[3] == "male" { 1 } else { 0 },
            parse_date(&row[4]),
            parse_datetime(&row[5]),
            ipv4_to_u64(&row[6]),
            string_to_u64(&row[7]),
        ];
        person_table.push(person_row);
    }

    let mut person_knows_person = Vec::new();
    for (_, row) in relation_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            row[1].parse::<u64>().expect("invalid ID"),
        ];
        person_knows_person.push(r_row);
    }

    let mut person_speaks_language = Vec::new();
    for (_, row) in language_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            string_to_u64(&row[1]),
        ];
        person_speaks_language.push(r_row);
    }

    let mut person_email_emailaddress = Vec::new();
    for (_, row) in email_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            string_to_u64(&row[1]),
        ];
        person_email_emailaddress.push(r_row);
    }

    let mut person_isLocatedIn_place = Vec::new();
    for (_, row) in location_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            row[1].parse::<u64>().expect("invalid ID"),
        ];
        person_isLocatedIn_place.push(r_row);
    }

    let mut place = Vec::new();
    for (_, row) in place_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            string_to_u64(&row[1]),
        ];
        place.push(r_row);
    }

    let mut person_studyAt_organisation = Vec::new();
    for (_, row) in studyat_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            row[1].parse::<u64>().expect("invalid ID"),
            row[2].parse::<u64>().expect("invalid Year"),
        ];
        person_studyAt_organisation.push(r_row);
    }

    let mut person_workAt_organisation = Vec::new();
    for (_, row) in workat_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            row[1].parse::<u64>().expect("invalid ID"),
            row[2].parse::<u64>().expect("invalid Year"),
        ];
        person_workAt_organisation.push(r_row);
    }

    // id | type | name
    let mut organisation = Vec::new();
    for (_, row) in organisation_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            if row[1] == "company" { 1 } else { 0 },
            string_to_u64(&row[2]),
        ];
        organisation.push(r_row);
    }
    let mut organisation_isLocatedIn_place = Vec::new();
    for (_, row) in org_location_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("invalid ID"),
            row[1].parse::<u64>().expect("invalid ID"),
        ];
        organisation_isLocatedIn_place.push(r_row);
    }

    println!("person:{:?}", person_table.len());
    println!("person_knows_person.len:{:?}", person_knows_person.len());
    println!("person_speaks_language:{:?}", person_speaks_language.len());
    println!(
        "person_email_emailaddress:{:?}",
        person_email_emailaddress.len()
    );
    println!(
        "person_isLocatedIn_place:{:?}",
        person_isLocatedIn_place.len()
    );
    println!("places:{:?}", place.len());
    println!(
        "person_studyAt_organisation:{:?}",
        person_studyAt_organisation.len()
    );
    println!(
        "person_workAt_organisation:{:?}",
        person_workAt_organisation.len()
    );
    println!("organisation:{:?}", organisation.len());
    println!(
        "organisation_isLocatedIn_place:{:?}",
        organisation_isLocatedIn_place.len()
    );

    let test_person_id: u64 = 30786325583618;
    let test_person_firstname = string_to_u64("Chau");

    let circuit = MyCircuit::<Fr> {
        person: person_table,
        person_knows_person,
        person_id: test_person_id,
        person_firstname: test_person_firstname,
        _marker: PhantomData,
        person_speaks_language,
        person_email_emailaddress,
        person_isLocatedIn_place,
        place,
        person_studyAt_organisation,
        person_workAt_organisation,
        organisation,
        organisation_isLocatedIn_place,
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
    println!("Parameter processing completed. Time taken:{:?}", params_start.elapsed());

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
    println!("The entire process is completed. Time taken:{:?}", all_time.elapsed());
}
