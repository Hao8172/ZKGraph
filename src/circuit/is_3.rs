use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use rayon::result;
use std::marker::PhantomData;

/*
IS3. Friends of a person
MATCH (n:Person {id: $personId })-[r:KNOWS]-(friend)
RETURN
    friend.id AS personId,
    friend.firstName AS firstName,
    friend.lastName AS lastName,
    r.creationDate AS friendshipCreationDate
ORDER BY
    friendshipCreationDate DESC,
    toInteger(personId) ASC
*/
const NUM_BYTES: usize = 6;
pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct is3CircuitConfig<F: Field + Ord> {
    pub q_personid: Selector,

    // id | firstname | lastname
    pub person: Vec<Column<Advice>>,
    pub person_knows_person: Vec<Column<Advice>>,

    pub min_id: Column<Advice>,
    pub max_id: Column<Advice>,

    pub person_id: Column<Advice>,
    pub relation_check_bits: Column<Advice>,
    pub relation_zero: IsZeroConfig<F>,

    // friend_id | friend_firstName | friend_lastName | CreationDate | source_personid
    pub result: Vec<Column<Advice>>,
    pub q_result_person: Vec<Selector>,
    pub q_result_shuffle: Vec<Selector>,
    pub q_verify: Selector,
    pub q_normalize: Selector,

    pub result_min_id: Column<Advice>,
    pub result_max_id: Column<Advice>,
    pub q_result_normalize: Selector,

    pub creationdate_config: LtEqGenericConfig<F, NUM_BYTES>,
    pub date_zero: IsZeroConfig<F>,
    pub date_check_bits: Column<Advice>,
    pub friendid_config: LtEqGenericConfig<F, NUM_BYTES>,
    pub q_sort: Selector,

    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct is3Chip<F: Field + Ord> {
    config: is3CircuitConfig<F>,
}

impl<F: Field + Ord> is3Chip<F> {
    pub fn construct(config: is3CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> is3CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_personid = meta.selector();
        let q_normalize = meta.selector();

        // personid | firstname | lastname |
        let mut person = Vec::new();
        for _ in 0..3 {
            person.push(meta.advice_column());
        }

        let mut person_knows_person = Vec::new();
        for _ in 0..3 {
            person_knows_person.push(meta.advice_column());
        }

        let min_id = meta.advice_column();
        let max_id = meta.advice_column();

        let person_id = meta.advice_column();
        let relation_check_bits = meta.advice_column();

        let iz1 = meta.advice_column();

        let relation_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_personid),
            |meta| {
                let min_id_expr = meta.query_advice(min_id, Rotation::cur());
                let max_id_expr = meta.query_advice(max_id, Rotation::cur());
                let person_id_expr = meta.query_advice(person_id, Rotation::cur());

                let diff_min = min_id_expr.clone() - person_id_expr.clone();
                let diff_max = max_id_expr.clone() - person_id_expr;

                diff_min * diff_max
            },
            iz1,
            relation_check_bits,
        );

        meta.create_gate("normalize relationship", |meta| {
            let q = meta.query_selector(q_normalize);

            let id1 = meta.query_advice(person_knows_person[0], Rotation::cur());
            let id2 = meta.query_advice(person_knows_person[1], Rotation::cur());

            let m = meta.query_advice(min_id, Rotation::cur());
            let M = meta.query_advice(max_id, Rotation::cur());

            // 1. m ≤ M
            // 2. m + M = id1 + id2
            // 3. m * M = id1 * id2
            let sum_constraint = (m.clone() + M.clone()) - (id1.clone() + id2.clone());
            let product_constraint = (m * M) - (id1 * id2);

            vec![q.clone() * sum_constraint, q.clone() * product_constraint]
        });

        let mut result = Vec::new();
        for _ in 0..5 {
            result.push(meta.advice_column());
        }

        let result_min_id = meta.advice_column();
        let result_max_id = meta.advice_column();
        let q_result_normalize = meta.selector();
        meta.create_gate("normalize relationship", |meta| {
            let q = meta.query_selector(q_result_normalize);

            let id1 = meta.query_advice(result[0], Rotation::cur());
            let id2 = meta.query_advice(result[4], Rotation::cur());

            let m = meta.query_advice(result_min_id, Rotation::cur());
            let M = meta.query_advice(result_max_id, Rotation::cur());
            let sum_constraint = (m.clone() + M.clone()) - (id1.clone() + id2.clone());
            let product_constraint = (m * M) - (id1 * id2);

            vec![q.clone() * sum_constraint, q.clone() * product_constraint]
        });

        let one = Expression::Constant(F::ONE);
        let mut q_result_person = Vec::new();
        for _ in 0..2 {
            q_result_person.push(meta.complex_selector());
        }
        meta.lookup_any(format!("lookup"), |meta| {
            let q1 = meta.query_selector(q_result_person[0]);
            let q2 = meta.query_selector(q_result_person[1]);
            let r1 = meta.query_advice(result[0], Rotation::cur());
            let r2 = meta.query_advice(result[1], Rotation::cur());
            let r3 = meta.query_advice(result[2], Rotation::cur());
            let p1 = meta.query_advice(person[0], Rotation::cur());
            let p2 = meta.query_advice(person[1], Rotation::cur());
            let p3 = meta.query_advice(person[2], Rotation::cur());
            let lhs = [one.clone(), r1, r2, r3].map(|c| c * q1.clone());
            let rhs = [one.clone(), p1, p2, p3].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut q_result_shuffle = Vec::new();
        for _ in 0..2 {
            q_result_shuffle.push(meta.complex_selector());
        }

        meta.shuffle(format!("shuffle"), |meta| {
            let q1 = meta.query_selector(q_result_shuffle[0]);
            let q2 = meta.query_selector(q_result_shuffle[1]);
            let a = meta.query_advice(result_min_id, Rotation::cur());
            let b = meta.query_advice(result_max_id, Rotation::cur());
            let c = meta.query_advice(result[3], Rotation::cur());
            let d = meta.query_advice(min_id, Rotation::cur());
            let e = meta.query_advice(max_id, Rotation::cur());
            let f = meta.query_advice(person_knows_person[2], Rotation::cur());
            let lhs = [one.clone(), a, b, c].map(|c| c * q1.clone());
            let rhs = [one.clone(), d, e, f].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_verify = meta.selector();
        meta.create_gate("verify q_result_shuffle", |meta| {
            let q_c = meta.query_selector(q_verify);
            let q = meta.query_selector(q_result_shuffle[1]);
            let check = meta.query_advice(relation_check_bits, Rotation::cur());
            vec![q_c * (q.clone() - check)]
        });

        let q_sort = meta.selector();
        let iz2 = meta.advice_column();
        let date_check_bits = meta.advice_column();
        let date_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_sort),
            |meta| {
                let next = meta.query_advice(result[3], Rotation::next());
                let cur = meta.query_advice(result[3], Rotation::cur());

                next - cur
            },
            iz2,
            date_check_bits,
        );

        let creationdate_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_sort),
            |meta| vec![meta.query_advice(result[3], Rotation::next())],
            |meta| vec![meta.query_advice(result[3], Rotation::cur())],
        );
        let friendid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_sort),
            |meta| vec![meta.query_advice(result[0], Rotation::cur())],
            |meta| vec![meta.query_advice(result[0], Rotation::next())],
        );
        meta.create_gate("verifies order", |meta| {
            let q_sort = meta.query_selector(q_sort);
            let date_lt = creationdate_config.is_lt(meta, None);
            let date_eq = meta.query_advice(date_check_bits, Rotation::cur());
            let id_lt = friendid_config.is_lt(meta, None);

            vec![
                q_sort.clone() * (one.clone() - date_lt.clone()),
                q_sort * date_eq * (one - id_lt),
            ]
        });

        is3CircuitConfig {
            q_personid,
            person,
            person_id,
            relation_check_bits,
            instance,
            person_knows_person,
            relation_zero,
            result,
            q_result_person,
            q_result_shuffle,
            q_verify,
            min_id,
            max_id,
            q_normalize,
            creationdate_config,
            friendid_config,
            q_sort,
            result_min_id,
            result_max_id,
            q_result_normalize,
            date_zero,
            date_check_bits,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<u64>>,
        person_knows_person: Vec<Vec<u64>>,
        person_id_val: u64,
    ) -> Result<(), Error> {
        let mut result: Vec<Vec<u64>> = Vec::new();

        for relation_row in &person_knows_person {
            let id1 = relation_row[0];
            let id2 = relation_row[1];
            let creationdate = relation_row[2];

            if id1 == person_id_val || id2 == person_id_val {
                let friend_id = if id1 == person_id_val { id2 } else { id1 };

                for friend_detail_row in &person_table {
                    if friend_detail_row[0] == friend_id {
                        let friend_firstname = friend_detail_row[1];
                        let friend_lastname = friend_detail_row[2];

                        let result_row = vec![
                            friend_id,
                            friend_firstname,
                            friend_lastname, 
                            creationdate,
                            person_id_val,  
                        ];
                        result.push(result_row);
                        break;
                    }
                }
            }
        }

        result.sort_by(|a, b| {
            b[3].cmp(&a[3])
                .then_with(|| a[0].cmp(&b[0]))
        });

        let mut normalized_relations = Vec::new();
        let mut relation_check_bits: Vec<u64> = Vec::new();

        for row in &person_knows_person {
            let id1 = row[0];
            let id2 = row[1];
            let creationdate = row[2];

            let min_id = if id1 <= id2 { id1 } else { id2 };
            let max_id = if id1 <= id2 { id2 } else { id1 };

            let is_relevant = if id1 == person_id_val || id2 == person_id_val {
                1u64
            } else {
                0u64
            };

            normalized_relations.push((id1, id2, min_id, max_id));
            relation_check_bits.push(is_relevant);
        }

        let chip_person_eq = IsZeroChip::construct(self.config.relation_zero.clone());
        let chip_date_eq = IsZeroChip::construct(self.config.date_zero.clone());
        let creationdate_chip = LtEqGenericChip::construct(self.config.creationdate_config);
        creationdate_chip.load(layouter).unwrap();
        let friendid_chip = LtEqGenericChip::construct(self.config.friendid_config);
        friendid_chip.load(layouter).unwrap();

        layouter.assign_region(
            || "witness",
            |mut region| {
                for row_idx in 0..person_knows_person.len() {
                    self.config.q_personid.enable(&mut region, row_idx)?;
                    self.config.q_normalize.enable(&mut region, row_idx)?;

                    for col_idx in 0..person_knows_person[row_idx].len() {
                        region.assign_advice(
                            || format!("person_knows_person row {} col {}", row_idx, col_idx),
                            self.config.person_knows_person[col_idx],
                            row_idx,
                            || Value::known(F::from(person_knows_person[row_idx][col_idx])),
                        )?;
                    }

                    let (id1, id2, min_id, max_id) = normalized_relations[row_idx];

                    region.assign_advice(
                        || "min_id",
                        self.config.min_id,
                        row_idx,
                        || Value::known(F::from(min_id)),
                    )?;

                    region.assign_advice(
                        || "max_id",
                        self.config.max_id,
                        row_idx,
                        || Value::known(F::from(max_id)),
                    )?;

                    region.assign_advice(
                        || "person_check",
                        self.config.relation_check_bits,
                        row_idx,
                        || Value::known(F::from(relation_check_bits[row_idx])),
                    )?;

                    if relation_check_bits[row_idx] == 1u64 {
                        self.config.q_result_shuffle[1].enable(&mut region, row_idx)?;
                    }
                    self.config.q_verify.enable(&mut region, row_idx)?;

                    region.assign_advice(
                        || "person_id",
                        self.config.person_id,
                        row_idx,
                        || Value::known(F::from(person_id_val)),
                    )?;

                    let person_id_f = F::from(person_id_val);
                    let min_id_f = F::from(min_id);
                    let max_id_f = F::from(max_id);
                    let min_diff = min_id_f - person_id_f;
                    let max_diff = max_id_f - person_id_f;
                    let combined_diff = min_diff * max_diff;

                    chip_person_eq
                        .assign(&mut region, row_idx, Value::known(combined_diff))
                        .unwrap();
                }

                for (row_idx, p_row) in person_table.iter().enumerate() {
                    for col_idx in 0..p_row.len() {
                        region.assign_advice(
                            || format!("person row {} col {}", row_idx, col_idx),
                            self.config.person[col_idx],
                            row_idx,
                            || Value::known(F::from(p_row[col_idx])),
                        )?;
                    }
                    self.config.q_result_person[1].enable(&mut region, row_idx)?;
                }

                for (row_idx, result_row) in result.iter().enumerate() {
                    for col_idx in 0..result_row.len() {
                        region.assign_advice(
                            || format!("result row {} col {}", row_idx, col_idx),
                            self.config.result[col_idx],
                            row_idx,
                            || Value::known(F::from(result_row[col_idx])),
                        )?;
                    }

                    let current_friend_id = result_row[0];
                    let current_person_id_val = result_row[4];
                    let r_min_id = if current_person_id_val <= current_friend_id {
                        current_person_id_val
                    } else {
                        current_friend_id
                    };
                    let r_max_id = if current_person_id_val <= current_friend_id {
                        current_friend_id
                    } else {
                        current_person_id_val
                    };
                    region.assign_advice(
                        || format!("r_min_id"),
                        self.config.result_min_id,
                        row_idx,
                        || Value::known(F::from(r_min_id)),
                    )?;
                    region.assign_advice(
                        || format!("r_max_id"),
                        self.config.result_max_id,
                        row_idx,
                        || Value::known(F::from(r_max_id)),
                    )?;
                    self.config
                        .q_result_normalize
                        .enable(&mut region, row_idx)?;

                    self.config.q_result_shuffle[0].enable(&mut region, row_idx)?;
                    self.config.q_result_person[0].enable(&mut region, row_idx)?;
                    if row_idx != result.len() - 1 {
                        self.config.q_sort.enable(&mut region, row_idx)?;
                        creationdate_chip
                            .assign(
                                &mut region,
                                row_idx,
                                &[F::from(result[row_idx + 1][3])],
                                &[F::from(result_row[3])],
                            )
                            .unwrap();

                        if result[row_idx + 1][3] == result_row[3] {
                            region.assign_advice(
                                || format!("date_check"),
                                self.config.date_check_bits,
                                row_idx,
                                || Value::known(F::from(1u64)),
                            )?;
                        } else {
                            region.assign_advice(
                                || format!("date_check"),
                                self.config.date_check_bits,
                                row_idx,
                                || Value::known(F::from(0u64)),
                            )?;
                        }

                        chip_date_eq
                            .assign(
                                &mut region,
                                row_idx,
                                Value::known(
                                    F::from(result[row_idx + 1][3]) - F::from(result_row[3]),
                                ),
                            )
                            .unwrap();
                        friendid_chip
                            .assign(
                                &mut region,
                                row_idx,
                                &[F::from(result_row[0])],
                                &[F::from(result[row_idx + 1][0])],
                            )
                            .unwrap();
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord> {
    pub person: Vec<Vec<u64>>,
    pub person_knows_person: Vec<Vec<u64>>,
    pub person_id: u64,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Vec::new(),
            person_id: 0u64,
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = is3CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        is3Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let chip = is3Chip::construct(config);

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
    use super::*;
    use crate::circuit::utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::time::Instant;

    #[test]
    fn test_is3_circuit() {
        let k = 16;

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
                row[0].parse::<u64>().expect("invalid Person ID"),
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

        let person_id = 4194;

        let circuit = MyCircuit::<Fr> {
            person,
            person_id,
            person_knows_person,
            _marker: PhantomData,
        };

        let start = Instant::now();
        let prover = MockProver::run(k, &circuit, vec![vec![Fr::from(1)]]).unwrap();
        println!("Prover execution time: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("verification failed{:?}", e);
            }
        }
    }
}
