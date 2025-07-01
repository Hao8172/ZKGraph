use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;
use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};

/*
MATCH (n:Person {id: $personId })-[r:KNOWS]-(friend)
RETURN
    friend.id AS personId,
    friend.firstName AS firstName,
    friend.lastName AS lastName,
    r.creationDate AS friendshipCreationDate
*/
pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct Is3CircuitConfig<F: Field> {

    pub q_personid_ops: Selector, 


    pub person_table_cols: Vec<Column<Advice>>,

    pub pkp_table_cols: Vec<Column<Advice>>,

    pub target_person_id: Column<Advice>, 

    pub is_pkp0_eq_target_chip: IsZeroConfig<F>,
    pub is_pkp0_eq_target_output_col: Column<Advice>,

    pub is_pkp1_eq_target_chip: IsZeroConfig<F>,
    pub is_pkp1_eq_target_output_col: Column<Advice>,     

    pub actual_friendship_check_bit: Column<Advice>,

    // friend_id | friend_firstName | friend_lastName | CreationDate | source_personid
    pub result_table_cols: Vec<Column<Advice>>,
    pub q_result_person_lookup: Vec<Selector>, 
    pub q_result_pkp_shuffle: Vec<Selector>,  
    pub q_verify_shuffle_participation: Selector, 

    pub instance_col: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is3Chip<F: Field> {
    config: Is3CircuitConfig<F>,
}

impl<F: Field> Is3Chip<F> {
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

        meta.shuffle("shuffle_result_pkp_connection", |meta| {
            let q_shuffle_lhs = meta.query_selector(q_result_pkp_shuffle[0]);
            let q_shuffle_rhs = meta.query_selector(q_result_pkp_shuffle[1]); 

            let lhs_source_pid = meta.query_advice(result_table_cols[4], Rotation::cur());
            let lhs_friend_pid = meta.query_advice(result_table_cols[0], Rotation::cur());
            let lhs_date = meta.query_advice(result_table_cols[3], Rotation::cur());

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
            is_pkp1_eq_target_chip,
            is_pkp1_eq_target_output_col,
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
        let mut result_witness_table: Vec<Vec<u64>> = Vec::new();
        for relation_row in &person_knows_person_data {
            let p1_in_relation = relation_row[0];
            let p2_in_relation = relation_row[1]; 
            let creationdate = relation_row[2];

            if p1_in_relation == target_person_id_val && p2_in_relation != target_person_id_val {
                for friend_detail_row in &person_data {
                    if friend_detail_row[0] == p2_in_relation {
                        let result_row = vec![
                            friend_detail_row[0],
                            friend_detail_row[1],
                            friend_detail_row[2],
                            creationdate,
                            target_person_id_val,
                        ];
                        result_witness_table.push(result_row);
                        break;
                    }
                }
            }
        }

        let chip_is_pkp0_eq_target =
            IsZeroChip::construct(self.config.is_pkp0_eq_target_chip.clone());
        let chip_is_pkp1_eq_target =
            IsZeroChip::construct(self.config.is_pkp1_eq_target_chip.clone());

        layouter.assign_region(
            || "witness",
            |mut region| {
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

pub struct MyCircuit<F: Field> {
    pub person: Vec<Vec<u64>>,
    pub person_knows_person: Vec<Vec<u64>>,
    pub person_id: u64,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Vec::new(),
            person_id: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = Is3CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Is3Chip::configure(meta)
    }

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
        .unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::utils::{parse_datetime, read_csv, string_to_u64};

    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    // use utils::{parse_datetime, string_to_u64};
    use std::collections::HashSet;
    use std::time::Instant;

    #[test]
    fn test_is3() {
        let k = 17; 

        let person_csv_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");

        let relation_csv_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");

        let mut person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in person_csv_data.iter().enumerate() {
            let person_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[2]),
            ];
            person.push(person_row);
        }
        println!("person.len:{:?}", person.len());

        let mut original_pkp_data_fr: Vec<Vec<u64>> = Vec::new();
        for row_str in relation_csv_data.iter() {
            if row_str.len() >= 3 {
                let relation_row_fr = vec![
                    row_str[0].parse::<u64>().expect("invalid person1Id"),
                    row_str[1].parse::<u64>().expect("invalid person2Id"),
                    parse_datetime(&row_str[2]), // creationDate
                ];
                original_pkp_data_fr.push(relation_row_fr);
            } else {
                eprintln!("person_knows_person num of columns : {:?}", row_str);
            }
        }
        println!("pkp_data_fr.len: {:?}", original_pkp_data_fr.len());

        let mut processed_pkp_data_fr: Vec<Vec<u64>> = Vec::new();
        for row_fr in &original_pkp_data_fr {
            let p1 = row_fr[0];
            let p2 = row_fr[1];
            let date = row_fr[2];

            processed_pkp_data_fr.push(vec![p1, p2, date]);

            if p1 != p2 {
                processed_pkp_data_fr.push(vec![p2, p1, date]);
            }
        }
        println!("original_pkp_data_fr.len: {:?}", original_pkp_data_fr.len());
        println!(
            "processed_pkp_data_fr.len: {:?}",
            processed_pkp_data_fr.len()
        );


        let target_person_id_val = 933; 

        let circuit = MyCircuit::<Fr> {
            person: person,
            person_id: target_person_id_val,
            person_knows_person: processed_pkp_data_fr,
            _marker: PhantomData,
        };

        let public_inputs = vec![vec![]];

        let start_time = Instant::now();
        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        println!("MockProving time: {:?}", start_time.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("verification failed{:?}", e);
            }
        }
    }
}
