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
        is_1_csr::MyCircuit,
        utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64},
    }, // 导入 MyCircuit 和 Config
    data::csr::CsrValue, // 导入 CsrValue
};

fn main() {
    let k = 18;

    let all_time = Instant::now();
    println!("开始执行...");

    // ---------------------------
    // 数据加载与预处理
    // ---------------------------
    println!("开始加载和处理数据...");
    let data_load_start = Instant::now();

    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/sf10/social_network/dynamic/person_0_0.csv",
        '|',
    )
    .expect("无法加载 Person 数据");
    let place_data = read_csv(
        "/home/wh/zkgraph/src/data/sf10/social_network/static/place_0_0.csv",
        '|',
    )
    .expect("无法加载 Place 数据");
    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/sf10/social_network/dynamic/person_isLocatedIn_place_0_0.csv",
        '|',
    )
    .expect("无法加载 Relation 数据");

    let mut person_id_to_index = HashMap::new();
    let mut person_table: Vec<Vec<Fr>> = Vec::new();
    for (i, row) in person_data.iter().enumerate() {
        let id = row[0].parse::<u64>().expect("无效的 Person ID");
        person_id_to_index.insert(id, i);
        let person_row = vec![
            Fr::from(id),
            Fr::from(0),
            Fr::from(0),
            Fr::from(if row[3] == "male" { 1 } else { 0 }),
            Fr::from(parse_date(&row[4])),
            Fr::from(parse_datetime(&row[5])),
            Fr::from(0),
            Fr::from(0),
        ];
        person_table.push(person_row);
    }

    let mut place_id_to_index = HashMap::new();
    for (i, row) in place_data.iter().enumerate() {
        if row.is_empty() || row[0].is_empty() {
            continue;
        }
        let id = row[0].parse::<u64>().expect("无效的 Place ID");
        place_id_to_index.insert(id, i);
    }

    let mut edges: Vec<(u64, u64)> = Vec::new();
    let mut person_to_places_map = HashMap::<u64, Vec<u64>>::new();
    for row in &relation_data {
        let person_id = row[0].parse::<u64>().expect("无效的 Person ID");
        let place_id = row[1].parse::<u64>().expect("无效的 Place ID");
        if let (Some(&p_idx), Some(&pl_idx)) = (
            person_id_to_index.get(&person_id),
            place_id_to_index.get(&place_id),
        ) {
            let place_idx_fr = pl_idx as u64;
            edges.push((p_idx as u64, pl_idx as u64));
            person_to_places_map
                .entry(p_idx as u64)
                .or_default()
                .push(place_idx_fr);
        }
    }
    edges.sort_by_key(|&(p_idx, _)| p_idx);
    let person_to_place_csr = CsrValue::<Fr>::from_sorted_edges(&edges).expect("构建 CSR 失败");

    println!(
        "person_to_place_csr.len:{:?}",
        person_to_place_csr.row.len()
    );
    println!("person:{:?}", person_table.len());

    let test_person_id_val: u64 = 933;
    let person_id_fr = Fr::from(test_person_id_val);
    let test_person_idx = person_id_to_index
        .get(&test_person_id_val)
        .expect("测试 Person ID 未找到");

    println!("测试 Person ID: {}", test_person_id_val);
    println!("测试 Person Index: {}", test_person_idx);

    let circuit = MyCircuit::<Fr> {
        person: person_table,
        person_to_place: person_to_place_csr,
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

    // // 将证明写入文件
    let proof_file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
        .join("is1_proof.bin");
    println!("将证明写入文件: {:?}", proof_file_path);
    let mut proof_file = File::create(&proof_file_path).expect("无法创建证明文件");
    proof_file.write_all(&proof).expect("写入证明失败");

    let proof_file_metadata = std::fs::metadata(&proof_file_path).expect("无法获取证明文件元数据");
    let proof_size_bytes = proof_file_metadata.len();
    let proof_size_kb = proof_size_bytes as f64 / 1024.0;
    println!(
        "证明文件大小: {} bytes ({:.2} KB)",
        proof_size_bytes, proof_size_kb
    );

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
