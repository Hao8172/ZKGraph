use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{LtEqGenericChip, LtEqGenericConfig};
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
*/
const NUM_BYTES: usize = 5;
pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct is3CircuitConfig<F: Field + Ord> {
    pub q_personid: Selector,

    // id | firstname | lastname
    pub person: Vec<Column<Advice>>,
    pub person_knows_person: Vec<Column<Advice>>,

    pub person_id: Column<Advice>,
    pub relation_check_bits: Column<Advice>,
    pub relation_zero: IsZeroConfig<F>,

    // friend_id | friend_firstName | friend_lastName | CreationDate | source_personid
    pub result: Vec<Column<Advice>>,
    pub q_result_person: Vec<Selector>,
    pub q_result_shuffle: Vec<Selector>,
    pub q_verify: Selector,

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

        // personid | firstname | lastname |
        let mut person = Vec::new();
        for _ in 0..3 {
            person.push(meta.advice_column());
        }

        let mut person_knows_person = Vec::new();
        for _ in 0..3 {
            person_knows_person.push(meta.advice_column());
        }

        let person_id = meta.advice_column();
        let relation_check_bits = meta.advice_column();

        let iz1 = meta.advice_column();
        let relation_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_personid),
            |meta| {
                meta.query_advice(person_knows_person[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz1,
            relation_check_bits,
        );

        let mut result = Vec::new();
        for _ in 0..5 {
            result.push(meta.advice_column());
        }

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
            let a = meta.query_advice(result[4], Rotation::cur());
            let b = meta.query_advice(result[0], Rotation::cur());
            let c = meta.query_advice(result[3], Rotation::cur());
            let d = meta.query_advice(person_knows_person[0], Rotation::cur());
            let e = meta.query_advice(person_knows_person[1], Rotation::cur());
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
            let source_person_id_in_relation = relation_row[0];
            let current_friend_id = relation_row[1];
            let creationdate = relation_row[2];

            if source_person_id_in_relation == person_id_val {
                for friend_detail_row in &person_table {
                    if friend_detail_row[0] == current_friend_id {
                        let friend_actual_id = friend_detail_row[0];
                        let friend_firstname = friend_detail_row[1];
                        let friend_lastname = friend_detail_row[2];

                        let result_row = vec![
                            friend_actual_id,
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
            a[3].cmp(&b[3]) 
                .then_with(|| a[0].cmp(&b[0]))
        });

        let relation_check_bits: Vec<F> = person_knows_person
            .iter()
            .map(|row| {
                if row[0] == person_id_val {
                    F::ONE
                } else {
                    F::ZERO
                }
            })
            .collect();

        let chip_person_eq = IsZeroChip::construct(self.config.relation_zero.clone());

        layouter.assign_region(
            || "witness",
            |mut region| {
                for row_idx in 0..person_knows_person.len() {
                    self.config.q_personid.enable(&mut region, row_idx)?;

                    for col_idx in 0..person_knows_person[row_idx].len() {
                        region.assign_advice(
                            || format!("person_knows_person row {} col {}", row_idx, col_idx),
                            self.config.person_knows_person[col_idx],
                            row_idx,
                            || Value::known(F::from(person_knows_person[row_idx][col_idx])),
                        )?;
                    }
                    region.assign_advice(
                        || "person_check",
                        self.config.relation_check_bits,
                        row_idx,
                        || Value::known(relation_check_bits[row_idx]),
                    )?;

                    if relation_check_bits[row_idx] == F::ONE {
                        self.config.q_result_shuffle[1].enable(&mut region, row_idx)?;
                    }
                    self.config.q_verify.enable(&mut region, row_idx)?;
                    region.assign_advice(
                        || "person_id",
                        self.config.person_id,
                        row_idx,
                        || Value::known(F::from(person_id_val)),
                    )?;

                    let diff = person_knows_person[row_idx][0] - person_id_val;
                    chip_person_eq
                        .assign(&mut region, row_idx, Value::known(F::from(diff)))
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
                    self.config.q_result_shuffle[0].enable(&mut region, row_idx)?;
                    self.config.q_result_person[0].enable(&mut region, row_idx)?;
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
            person_id: Default::default(),
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
                row[0].parse::<u64>().expect("无效的 Person ID"),
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

        let person_id = 933;

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
