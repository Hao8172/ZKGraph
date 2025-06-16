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
        bi_sssp_from_ic1::MyCircuit,
        utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64},
    }, // 导入 MyCircuit 和 Config
    data::csr::CsrValue, // 导入 CsrValue
};

fn main() {
    let k = 16;

    let all_time = Instant::now();
    println!("开始执行...");

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

    let mut person_table: Vec<Vec<Fr>> = Vec::new();
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            Fr::from(row[0].parse::<u64>().expect("无效的 Person ID")),
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

    let mut person_knows_person: Vec<Vec<Fr>> = Vec::new();
    for (_, row) in relation_data.iter().enumerate() {
        let r_row = vec![
            Fr::from(row[0].parse::<u64>().expect("无效的 Person ID")),
            Fr::from(row[1].parse::<u64>().expect("无效的 Person ID")),
        ];
        person_knows_person.push(r_row);
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
