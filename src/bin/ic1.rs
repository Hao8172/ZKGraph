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
    }, // 导入 MyCircuit 和 Config
    data::csr::CsrValue, // 导入 CsrValue
};

fn main() {
    let all_time = Instant::now();
    println!("开始执行...");

    // ---------------------------
    // 数据加载与预处理
    // ---------------------------
    println!("开始加载和处理数据...");
    let data_load_start = Instant::now();

    let k = 16;

    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
        '|',
    )
    .expect("无法加载 Person 数据");
    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
        '|',
    )
    .expect("无法加载 Relation 数据");
    let email_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_email_emailaddress_0_0.csv",
        '|',
    )
    .expect("无法加载 eamil 数据");
    let language_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_speaks_language_0_0.csv",
        '|',
    )
    .expect("无法加载 language 数据");
    let location_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_isLocatedIn_place_0_0.csv",
        '|',
    )
    .expect("无法加载 location 数据");
    let place_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/place_0_0.csv",
        '|',
    )
    .expect("无法加载 place 数据");
    let studyat_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_studyAt_organisation_0_0.csv",
        '|',
    )
    .expect("无法加载 study 数据");
    let workat_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_workAt_organisation_0_0.csv",
        '|',
    )
    .expect("无法加载 work 数据");
    let organisation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/organisation_0_0.csv",
        '|',
    )
    .expect("无法加载 organisation 数据");
    let org_location_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/organisation_isLocatedIn_place_0_0.csv",
            '|',
        ).expect("无法加载 organisation_isLocatedIn_place 数据");

    let mut person_table = Vec::new();
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
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
            row[0].parse::<u64>().expect("无效的 Person ID"),
            row[1].parse::<u64>().expect("无效的 Person ID"),
        ];
        person_knows_person.push(r_row);
    }

    let mut person_speaks_language = Vec::new();
    for (_, row) in language_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            string_to_u64(&row[1]),
        ];
        person_speaks_language.push(r_row);
    }

    let mut person_email_emailaddress = Vec::new();
    for (_, row) in email_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            string_to_u64(&row[1]),
        ];
        person_email_emailaddress.push(r_row);
    }

    let mut person_isLocatedIn_place = Vec::new();
    for (_, row) in location_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            row[1].parse::<u64>().expect("无效的 Place ID"),
        ];
        person_isLocatedIn_place.push(r_row);
    }

    let mut place = Vec::new();
    for (_, row) in place_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Place ID"),
            string_to_u64(&row[1]),
        ];
        place.push(r_row);
    }

    let mut person_studyAt_organisation = Vec::new();
    for (_, row) in studyat_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            row[1].parse::<u64>().expect("无效的 organisation ID"),
            row[2].parse::<u64>().expect("无效的 ClassYear"),
        ];
        person_studyAt_organisation.push(r_row);
    }

    let mut person_workAt_organisation = Vec::new();
    for (_, row) in workat_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            row[1].parse::<u64>().expect("无效的 organisation ID"),
            row[2].parse::<u64>().expect("无效的 workfrom"),
        ];
        person_workAt_organisation.push(r_row);
    }

    // id | type | name
    let mut organisation = Vec::new();
    for (_, row) in organisation_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            if row[1] == "company" { 1 } else { 0 },
            string_to_u64(&row[2]),
        ];
        organisation.push(r_row);
    }
    let mut organisation_isLocatedIn_place = Vec::new();
    for (_, row) in org_location_data.iter().enumerate() {
        let r_row = vec![
            row[0].parse::<u64>().expect("无效的 Organisation ID"),
            row[1].parse::<u64>().expect("无效的 Place ID"),
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

    println!("使用 k = {}", k);

    // 设置参数文件的路径 (推荐放在项目目录下)
    let params_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
        .join(format!("kzg_param{}", k));

    // 生成或加载参数
    let params_start = Instant::now();
    let params = if params_path.exists() {
        println!("参数文件已存在，正在读取...");
        let mut file =
            File::open(&params_path).expect(&format!("无法打开参数文件: {:?}", params_path));
        Params::read::<_>(&mut file).unwrap()
    } else {
        println!("参数文件不存在，正在生成...");
        let params = ParamsKZG::<Bn256>::new(k);
        let mut file =
            File::create(&params_path).expect(&format!("无法创建参数文件: {:?}", params_path));
        <ParamsKZG<_> as Params<_>>::write(&params, &mut file).unwrap();
        params
    };
    println!("参数处理完成。耗时: {:?}", params_start.elapsed());

    let keys_start = Instant::now();
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");
    println!("keys 生成完成。耗时: {:?}", keys_start.elapsed());

    // ---------------------------
    // 生成证明
    // ---------------------------
    println!("开始生成证明...");
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
    println!("证明生成完成。耗时: {:?}", proof_start.elapsed());

    // 将证明写入文件
    let proof_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
        .join("is3_proof.bin");
    let mut proof_file: File = File::create(&proof_file_path).expect("无法创建证明文件");
    proof_file.write_all(&proof).expect("写入证明失败");

    let proof_file_metadata = std::fs::metadata(&proof_file_path).expect("无法获取证明文件元数据");
    let proof_size_bytes = proof_file_metadata.len();
    let proof_size_kb = proof_size_bytes as f64 / 1024.0;
    println!("证明文件大小: {} bytes ({:.2} KB)", proof_size_bytes, proof_size_kb);

    let verifier_params = params.verifier_params();
    // ---------------------------
    // 验证证明
    // ---------------------------
    println!("开始验证证明...");
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

    println!("证明验证成功！耗时: {:?}", verify_start.elapsed());
    println!("整个过程完成,耗时：{:?}", all_time.elapsed());
}
