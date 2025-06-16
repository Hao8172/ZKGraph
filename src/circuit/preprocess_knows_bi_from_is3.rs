use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation}; // 添加 ErrorFront
use std::marker::PhantomData;
// 确保 IsZeroChip 和 IsZeroConfig 被正确导入
use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};

/*
IS3. 一个人的朋友们
MATCH (n:Person {id: $personId })-[r:KNOWS]-(friend)
RETURN
    friend.id AS personId,
    friend.firstName AS firstName,
    friend.lastName AS lastName,
    r.creationDate AS friendshipCreationDate
*/

// 定义一个 Field 特质，要求实现 PrimeField
pub trait Field: PrimeField {}
// 为所有实现 PrimeField 的类型 F 实现 Field 特质
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct Is3CircuitConfig<F: Field> {
    // 移除 Ord，因为它在 F 上已经约束
    pub q_personid_ops: Selector, // 用于在 person_knows_person 表上操作的选择器

    // Person 表: id | firstname | lastname
    pub person_table_cols: Vec<Column<Advice>>,
    // Person_knows_Person 表: person1_id | person2_id | creation_date
    // 假设 person1_id 是我们要匹配 target_person_id 的列
    pub pkp_table_cols: Vec<Column<Advice>>,

    pub target_person_id: Column<Advice>, // 我们要查找其朋友的目标 $personId

    // 用于检查 person_knows_person[0] == target_person_id
    pub is_pkp0_eq_target_chip: IsZeroConfig<F>,
    pub is_pkp0_eq_target_output_col: Column<Advice>, // is_pkp0_eq_target_chip 的输出 (如果相等则为1, 否则为0)
    pub iz_pkp0_inv_col: Column<Advice>,              // is_pkp0_eq_target_chip 的逆元列

    // 用于检查 person_knows_person[1] == target_person_id (确保朋友不是目标自己)
    pub is_pkp1_eq_target_chip: IsZeroConfig<F>,
    pub is_pkp1_eq_target_output_col: Column<Advice>, // is_pkp1_eq_target_chip 的输出
    pub iz_pkp1_inv_col: Column<Advice>,              // is_pkp1_eq_target_chip 的逆元列

    // 如果 pkp 表的行代表 target_person_id 的一个实际友谊，则此位为1
    // (即, pkp_table_cols[0] == target_person_id AND pkp_table_cols[1] != target_person_id)
    pub actual_friendship_check_bit: Column<Advice>,

    // Result 表: friend_id | friend_firstName | friend_lastName | CreationDate | source_personid
    pub result_table_cols: Vec<Column<Advice>>,
    pub q_result_person_lookup: Vec<Selector>, // 用于查找: 从 person 表获取结果详情
    pub q_result_pkp_shuffle: Vec<Selector>,   // 用于 shuffle: 结果友谊 vs pkp 友谊
    pub q_verify_shuffle_participation: Selector, // 用于验证 shuffle 参与的选择器

    pub instance_col: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is3Chip<F: Field> {
    // 移除 Ord
    config: Is3CircuitConfig<F>,
}

impl<F: Field> Is3Chip<F> {
    // 移除 Ord
    pub fn construct(config: Is3CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Is3CircuitConfig<F> {
        let instance_col = meta.instance_column();
        meta.enable_equality(instance_col);

        let q_personid_ops = meta.selector();

        let mut person_table_cols = Vec::new();
        for _ in 0..3 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            person_table_cols.push(col);
        }

        let mut pkp_table_cols = Vec::new();
        for _ in 0..3 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            pkp_table_cols.push(col);
        }

        let target_person_id = meta.advice_column();
        meta.enable_equality(target_person_id);

        // --- IsZeroChip for pkp_table_cols[0] == target_person_id ---
        let iz_pkp0_inv_col = meta.advice_column();
        let is_pkp0_eq_target_output_col = meta.advice_column();
        meta.enable_equality(is_pkp0_eq_target_output_col);
        let is_pkp0_eq_target_chip = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_personid_ops),
            |meta| {
                meta.query_advice(pkp_table_cols[0], Rotation::cur())
                    - meta.query_advice(target_person_id, Rotation::cur())
            },
            iz_pkp0_inv_col,
            is_pkp0_eq_target_output_col,
        );

        // --- IsZeroChip for pkp_table_cols[1] == target_person_id ---
        let iz_pkp1_inv_col = meta.advice_column();
        let is_pkp1_eq_target_output_col = meta.advice_column();
        meta.enable_equality(is_pkp1_eq_target_output_col);
        let is_pkp1_eq_target_chip = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_personid_ops),
            |meta| {
                meta.query_advice(pkp_table_cols[1], Rotation::cur())
                    - meta.query_advice(target_person_id, Rotation::cur())
            },
            iz_pkp1_inv_col,
            is_pkp1_eq_target_output_col,
        );

        let actual_friendship_check_bit = meta.advice_column();
        meta.enable_equality(actual_friendship_check_bit);

        // 约束 actual_friendship_check_bit
        // 它为 1 当 pkp_table_cols[0] == target_id AND pkp_table_cols[1] != target_id
        meta.create_gate("constrain_actual_friendship_check_bit", |meta| {
            let q_enable = meta.query_selector(q_personid_ops);
            let assigned_bit = meta.query_advice(actual_friendship_check_bit, Rotation::cur());
            let is_pkp0_eq = meta.query_advice(is_pkp0_eq_target_output_col, Rotation::cur());
            let is_pkp1_eq = meta.query_advice(is_pkp1_eq_target_output_col, Rotation::cur()); // 1 if pkp[1] == target
            let one = Expression::Constant(F::ONE);

            // expected_bit = is_pkp0_eq * (1 - is_pkp1_eq)
            let expected_bit = is_pkp0_eq * (one - is_pkp1_eq);

            vec![q_enable * (assigned_bit - expected_bit)]
        });

        // --- Result 表和 Lookups/Shuffles ---
        let mut result_table_cols = Vec::new();
        for _ in 0..5 {
            let col = meta.advice_column();
            meta.enable_equality(col);
            result_table_cols.push(col);
        }

        let one = Expression::Constant(F::ONE);
        let mut q_result_person_lookup = Vec::new();
        for _ in 0..2 {
            q_result_person_lookup.push(meta.complex_selector());
        }
        meta.lookup_any("lookup_friend_details", |meta| {
            let q_lookup_active_result = meta.query_selector(q_result_person_lookup[0]);
            let q_lookup_active_person = meta.query_selector(q_result_person_lookup[1]);

            let r_friend_id = meta.query_advice(result_table_cols[0], Rotation::cur());
            let r_first_name = meta.query_advice(result_table_cols[1], Rotation::cur());
            let r_last_name = meta.query_advice(result_table_cols[2], Rotation::cur());

            let p_id = meta.query_advice(person_table_cols[0], Rotation::cur());
            let p_first_name = meta.query_advice(person_table_cols[1], Rotation::cur());
            let p_last_name = meta.query_advice(person_table_cols[2], Rotation::cur());

            vec![
                (
                    q_lookup_active_result.clone() * one.clone(),
                    q_lookup_active_person.clone() * one.clone(),
                ),
                (
                    q_lookup_active_result.clone() * r_friend_id,
                    q_lookup_active_person.clone() * p_id,
                ),
                (
                    q_lookup_active_result.clone() * r_first_name,
                    q_lookup_active_person.clone() * p_first_name,
                ),
                (
                    q_lookup_active_result * r_last_name,
                    q_lookup_active_person * p_last_name,
                ),
            ]
        });

        let mut q_result_pkp_shuffle = Vec::new();
        for _ in 0..2 {
            q_result_pkp_shuffle.push(meta.complex_selector());
        }
        // Shuffle 用于连接 result 行和 person_knows_person 行
        meta.shuffle("shuffle_result_pkp_connection", |meta| {
            let q_shuffle_lhs = meta.query_selector(q_result_pkp_shuffle[0]); // LHS: result 表
            let q_shuffle_rhs = meta.query_selector(q_result_pkp_shuffle[1]); // RHS: person_knows_person 表

            // LHS 从 result 表: (source_personid, friend_id, creationDate)
            let lhs_source_pid = meta.query_advice(result_table_cols[4], Rotation::cur());
            let lhs_friend_pid = meta.query_advice(result_table_cols[0], Rotation::cur());
            let lhs_date = meta.query_advice(result_table_cols[3], Rotation::cur());

            // RHS 从 person_knows_person 表 (直接使用其列)
            // pkp_table_cols[0] 应该是 $target_person_id (当 actual_friendship_check_bit=1)
            // pkp_table_cols[1] 应该是 friend_id (当 actual_friendship_check_bit=1)
            // pkp_table_cols[2] 是 creationDate
            let rhs_source_pid = meta.query_advice(pkp_table_cols[0], Rotation::cur());
            let rhs_friend_pid = meta.query_advice(pkp_table_cols[1], Rotation::cur());
            let rhs_date = meta.query_advice(pkp_table_cols[2], Rotation::cur());

            vec![
                (
                    q_shuffle_lhs.clone() * lhs_source_pid,
                    q_shuffle_rhs.clone() * rhs_source_pid,
                ),
                (
                    q_shuffle_lhs.clone() * lhs_friend_pid,
                    q_shuffle_rhs.clone() * rhs_friend_pid,
                ),
                (q_shuffle_lhs * lhs_date, q_shuffle_rhs * rhs_date),
            ]
        });

        let q_verify_shuffle_participation = meta.selector();
        meta.create_gate(
            "verify_q_result_shuffle_rhs_selector_matches_check_bit",
            |meta| {
                let q_enable_gate = meta.query_selector(q_verify_shuffle_participation);
                let q_shuffle_rhs_selector_actual_value =
                    meta.query_selector(q_result_pkp_shuffle[1]);
                let check_bit_value =
                    meta.query_advice(actual_friendship_check_bit, Rotation::cur());
                vec![q_enable_gate * (q_shuffle_rhs_selector_actual_value - check_bit_value)]
            },
        );

        Is3CircuitConfig {
            q_personid_ops,
            person_table_cols,
            target_person_id,
            is_pkp0_eq_target_chip,
            is_pkp0_eq_target_output_col,
            iz_pkp0_inv_col,
            is_pkp1_eq_target_chip,
            is_pkp1_eq_target_output_col,
            iz_pkp1_inv_col,
            actual_friendship_check_bit,
            instance_col,
            pkp_table_cols,
            result_table_cols,
            q_result_person_lookup,
            q_result_pkp_shuffle,
            q_verify_shuffle_participation,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_data: Vec<Vec<u64>>,
        person_knows_person_data: Vec<Vec<u64>>,
        target_person_id_val: u64,
    ) -> Result<(), ErrorFront> {
        // 使用 PlonkError
        // --- 阶段 1: 根据预处理数据填充 result 表 ---
        let mut result_witness_table: Vec<Vec<u64>> = Vec::new();
        for relation_row in &person_knows_person_data {
            let p1_in_relation = relation_row[0];
            let p2_in_relation = relation_row[1]; // 这是潜在的朋友
            let creationdate = relation_row[2];

            // 由于数据已预处理，我们只关心 p1 是目标且 p2 不是目标的情况
            if p1_in_relation == target_person_id_val && p2_in_relation != target_person_id_val {
                // p2_in_relation 是朋友的 ID
                // 在 person_data 中查找这位朋友的详细信息
                for friend_detail_row in &person_data {
                    if friend_detail_row[0] == p2_in_relation {
                        // 找到了朋友
                        let result_row = vec![
                            friend_detail_row[0], // result_table_cols[0] = friend.id
                            friend_detail_row[1], // result_table_cols[1] = friend.firstName
                            friend_detail_row[2], // result_table_cols[2] = friend.lastName
                            creationdate,         // result_table_cols[3] = friendshipCreationDate
                            target_person_id_val, // result_table_cols[4] = source_personid (用于 shuffle)
                        ];
                        result_witness_table.push(result_row);
                        break; // 找到了朋友信息，跳出内层循环
                    }
                }
            }
        }

        // --- 阶段 2: 为电路分配见证 ---
        let chip_is_pkp0_eq_target =
            IsZeroChip::construct(self.config.is_pkp0_eq_target_chip.clone());
        let chip_is_pkp1_eq_target =
            IsZeroChip::construct(self.config.is_pkp1_eq_target_chip.clone());

        layouter.assign_region(
            || "主见证分配区域",
            |mut region| {
                // 分配 person_knows_person 表及相关检查位
                for (row_idx, pkp_row_data) in person_knows_person_data.iter().enumerate() {
                    self.config.q_personid_ops.enable(&mut region, row_idx)?;
                    self.config
                        .q_verify_shuffle_participation
                        .enable(&mut region, row_idx)?;

                    region.assign_advice(
                        || format!("target_person_id_for_pkp_row_{}", row_idx),
                        self.config.target_person_id,
                        row_idx,
                        || Value::known(F::from(target_person_id_val)),
                    )?;

                    for col_idx in 0..pkp_row_data.len() {
                        region.assign_advice(
                            || format!("pkp_row_{}_col_{}", row_idx, col_idx),
                            self.config.pkp_table_cols[col_idx],
                            row_idx,
                            || Value::known(F::from(pkp_row_data[col_idx])),
                        )?;
                    }

                    // 分配给 IsZeroChip for pkp_table_cols[0]
                    let val_p1 = pkp_row_data[0];
                    let is_pkp0_eq_target_witness = if val_p1 == target_person_id_val {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("is_pkp0_eq_target_output_col_row_{}", row_idx),
                        self.config.is_pkp0_eq_target_output_col,
                        row_idx,
                        || Value::known(is_pkp0_eq_target_witness),
                    )?;
                    chip_is_pkp0_eq_target
                        .assign(&mut region, row_idx, Value::known(F::from(val_p1) - F::from(target_person_id_val)))
                        .unwrap();

                    // 分配给 IsZeroChip for pkp_table_cols[1]
                    let val_p2 = pkp_row_data[1];
                    let is_pkp1_eq_target_witness = if val_p2 == target_person_id_val {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("is_pkp1_eq_target_output_col_row_{}", row_idx),
                        self.config.is_pkp1_eq_target_output_col,
                        row_idx,
                        || Value::known(is_pkp1_eq_target_witness),
                    )?;
                    chip_is_pkp1_eq_target
                        .assign(&mut region, row_idx, Value::known(F::from(val_p2) - F::from(target_person_id_val)))
                        .unwrap();

                    // 计算并分配 actual_friendship_check_bit
                    // actual_friendship_bit = (pkp[0] == target) AND (pkp[1] != target)
                    let actual_friendship_bit_val_bool = (is_pkp0_eq_target_witness == F::ONE)
                        && (is_pkp1_eq_target_witness == F::ZERO);
                    let actual_friendship_bit_f_val = if actual_friendship_bit_val_bool {
                        F::ONE
                    } else {
                        F::ZERO
                    };

                    region.assign_advice(
                        || format!("actual_friendship_check_bit_row_{}", row_idx),
                        self.config.actual_friendship_check_bit,
                        row_idx,
                        || Value::known(actual_friendship_bit_f_val),
                    )?;

                    // 如果是实际的友谊关系，则启用 shuffle 的 RHS 选择器
                    if actual_friendship_bit_f_val == F::ONE {
                        self.config.q_result_pkp_shuffle[1].enable(&mut region, row_idx)?;
                    }
                }

                for (row_idx, p_row_data) in person_data.iter().enumerate() {
                    for col_idx in 0..p_row_data.len() {
                        region.assign_advice(
                            || format!("person_data_row_{}_col_{}", row_idx, col_idx),
                            self.config.person_table_cols[col_idx],
                            row_idx,
                            || Value::known(F::from(p_row_data[col_idx])),
                        )?;
                    }
                    self.config.q_result_person_lookup[1].enable(&mut region, row_idx)?;
                }

                for (row_idx, r_row_data) in result_witness_table.iter().enumerate() {
                    for col_idx in 0..r_row_data.len() {
                        region.assign_advice(
                            || format!("result_witness_table_row_{}_col_{}", row_idx, col_idx),
                            self.config.result_table_cols[col_idx],
                            row_idx,
                            || Value::known(F::from(r_row_data[col_idx])),
                        )?;
                    }
                    self.config.q_result_person_lookup[0].enable(&mut region, row_idx)?;
                    self.config.q_result_pkp_shuffle[0].enable(&mut region, row_idx)?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

// 电路结构体定义
pub struct MyCircuit<F: Field> {
    pub person: Vec<Vec<u64>>,
    pub person_knows_person: Vec<Vec<u64>>, // 将接收预处理过的数据
    pub person_id: u64,
    pub _marker: PhantomData<F>,
}

// 为 MyCircuit 实现 Default 特质
impl<F: Copy + Default + Field> Default for MyCircuit<F> {
    // 移除 Ord
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Vec::new(),
            person_id: Default::default(),
            _marker: PhantomData,
        }
    }
}

// 为 MyCircuit 实现 Circuit 特质
impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = Is3CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner; // 使用简单的地板规划器

    // 返回一个没有见证（witnesses）的电路实例，用于生成 proving key 和 verifying key
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    /// 配置电路的约束
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Is3Chip::configure(meta)
    }

    /// 合成电路：创建并使用我们的 Is3Chip 来分配见证
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let chip = Is3Chip::construct(config);

        chip.assign(
            &mut layouter,
            self.person.clone(),
            self.person_knows_person.clone(),
            self.person_id,
        )
        .unwrap(); // assign 返回 Result<(), Error>

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::utils::{parse_datetime, read_csv, string_to_u64};

    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    // use utils::{parse_datetime, string_to_u64}; // 使用上面定义的 mock utils
    use std::collections::HashSet;
    use std::time::Instant; // 用于去重

    #[test]
    fn test_is3() {
        let k = 17; // 电路规模参数

        // 读取 person 数据 (id, firstName, lastName)
        // !! 注意：请确保您的 CSV 文件路径正确 !!
        let person_csv_data = read_csv(
            // 请替换为您的实际文件路径
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("未能读取 person 数据");

        // 读取 person_knows_person 数据 (person1Id, person2Id, creationDate)
        // !! 注意：请确保您的 CSV 文件路径正确 !!
        let relation_csv_data = read_csv(
            // 请替换为您的实际文件路径
            "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("未能读取 relation 数据");

        let mut person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in person_csv_data.iter().enumerate() {
            let person_row = vec![
                row[0].parse::<u64>().expect("无效的 Person ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[2]),
            ];
            person.push(person_row);
        }
        println!("person.len:{:?}", person.len());

        let mut original_pkp_data_fr: Vec<Vec<u64>> = Vec::new();
        for row_str in relation_csv_data.iter() {
            if row_str.len() >= 3 {
                // 确保至少有3列 (person1Id, person2Id, creationDate)
                let relation_row_fr = vec![
                    row_str[0].parse::<u64>().expect("无效的 person1Id"),
                    row_str[1].parse::<u64>().expect("无效的 person2Id"),
                    parse_datetime(&row_str[2]), // creationDate
                ];
                original_pkp_data_fr.push(relation_row_fr);
            } else {
                eprintln!("警告: person_knows_person 数据行少于3列: {:?}", row_str);
            }
        }
        println!("pkp_data_fr.len: {:?}", original_pkp_data_fr.len());

        let mut processed_pkp_data_fr: Vec<Vec<u64>> = Vec::new();
        for row_fr in &original_pkp_data_fr {
            let p1 = row_fr[0];
            let p2 = row_fr[1];
            let date = row_fr[2];

            // 添加原始方向 (p1, p2, date)
            processed_pkp_data_fr.push(vec![p1, p2, date]);

            // 添加反向 (p2, p1, date)，前提是 p1 和 p2 不同
            if p1 != p2 {
                processed_pkp_data_fr.push(vec![p2, p1, date]);
            }
        }
        println!("original_pkp_data_fr.len: {:?}", original_pkp_data_fr.len());
        println!(
            "processed_pkp_data_fr.len: {:?}",
            processed_pkp_data_fr.len()
        );

        // 测试用的 target_person_id
        let target_person_id_val = 933; // 从示例数据中选取一个 ID

        // 创建电路实例
        let circuit = MyCircuit::<Fr> {
            person: person,
            person_id: target_person_id_val,
            person_knows_person: processed_pkp_data_fr,
            _marker: PhantomData,
        };

        let public_inputs = vec![vec![]]; // 假设 instance 列不用于传递主要输入/输出

        // 使用 MockProver 进行测试
        println!("开始 MockProver 执行...");
        let start_time = Instant::now();
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        println!("MockProver 执行时间: {:?}", start_time.elapsed());

        // 验证约束是否满足
        println!("开始验证约束...");
        match prover.verify() {
            Ok(_) => println!("验证成功!"),
            Err(e) => {
                panic!("验证失败{:?}", e);
            }
        }
    }
}
