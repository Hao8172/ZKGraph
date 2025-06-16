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
        set_expand::MyCircuit,
        utils::{parse_datetime, read_csv, string_to_u64},
    }, // 导入 MyCircuit 和 Config
    data::csr::CsrValue, // 导入 CsrValue
};

fn main() {
    let k = 16;
    let all_time = Instant::now();
    println!("开始执行...");

    // ---------------------------
    // 数据加载与预处理
    // ---------------------------
    println!("开始加载和处理数据...");
    let data_load_start = Instant::now();

    let post_relation = read_csv(
        "/home/wh/zkgraph/src/data/message_fact/60k/post_hasCreator_person.csv",
        '|',
    )
    .expect("Failed to read post data");

    // 读取comment数据
    let comment_relation = read_csv(
        "/home/wh/zkgraph/src/data/message_fact/60k/comment_hasCreator_person.csv",
        '|',
    )
    .expect("Failed to read comment data");


    let mut comment_hasCreator_person: Vec<Vec<u64>> = Vec::new();
    for (_, row) in comment_relation.iter().enumerate() {
        let comment_row = vec![
            row[0].parse::<u64>().expect("无效的 comment ID"),
            row[1].parse::<u64>().expect("无效的 Person ID"),
        ];
        comment_hasCreator_person.push(comment_row);
    }
    println!("comment relation.len:{:?}", comment_hasCreator_person.len());

    let mut post_hasCreator_person: Vec<Vec<u64>> = Vec::new();
    for (_, row) in post_relation.iter().enumerate() {
        let post_row = vec![
            row[0].parse::<u64>().expect("无效的 post ID"),
            row[1].parse::<u64>().expect("无效的 Person ID"),
        ];
        post_hasCreator_person.push(post_row);
    }
    println!("post relation.len:{:?}", post_hasCreator_person.len());


    let circuit = MyCircuit::<Fr> {
        comment_hasCreator_person,
        post_hasCreator_person,
        friends_ids_val: (1..=50).collect(),
        _marker: PhantomData,
    };

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
