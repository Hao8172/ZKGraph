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
    }, // 导入 MyCircuit 和 Config
    data::csr::CsrValue, // 导入 CsrValue
};

fn main() {
    let k = 16; // 电路规模参数

    let all_time = Instant::now();
    // ---------------------------
    // 数据加载与预处理
    // ---------------------------
    println!("开始加载和处理数据...");
    let data_load_start = Instant::now();

    // 读取 person 数据 (id, firstName, lastName)
    let person_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
        '|',
    )
    .expect("Failed to read person data");

    // 读取 person_knows_person 数据
    let relation_data = read_csv(
        "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
        '|',
    )
    .expect("Failed to read relation data");

    let mut person: Vec<Vec<u64>> = Vec::new(); // 修改为 u64
    for (_, row) in person_data.iter().enumerate() {
        let person_row = vec![
            row[0].parse::<u64>().expect("无效的 Person ID"),
            string_to_u64(&row[1]),
            string_to_u64(&row[2]),
        ];
        person.push(person_row);
    }
    println!("person.len:{:?}", person.len());

    let mut person_knows_person: Vec<Vec<u64>> = Vec::new(); // 修改为 u64
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

    // 测试用的person_id
    let person_id = 933u64; // 从示例数据中选取，修改为 u64

    // 创建电路实例
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

    //         // 添加原始方向 (p1, p2, date)
    //         processed_pkp_data_fr.push(vec![p1, p2, date]);

    //         // 添加反向 (p2, p1, date)，前提是 p1 和 p2 不同
    //         if p1 != p2 {
    //             processed_pkp_data_fr.push(vec![p2, p1, date]);
    //         }
    //     }
    //     println!("original_pkp_data_fr.len: {:?}", pkp_data_fr.len());
    //     println!("processed_pkp_data_fr.len: {:?}", processed_pkp_data_fr.len());

    println!("数据加载完成。耗时: {:?}", data_load_start.elapsed());
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
