use crate::chips::is_zero::IsZeroChip;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use rayon::result;
use std::marker::PhantomData;

/*
IS1. Profile of a person
:param personId: 10995116277794
MATCH (n:Person {id: $personId })-[:IS_LOCATED_IN]->(p:City)
RETURN
    n.firstName AS firstName,
    n.lastName AS lastName,
    n.birthday AS birthday,
    n.locationIP AS locationIP,
    n.browserUsed AS browserUsed,
    p.id AS cityId,
    n.gender AS gender,
    n.creationDate AS creationDate
*/

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct Is1CircuitConfig<F: Field + Ord> {
    pub q_personid: Selector,

    pub person: Vec<Column<Advice>>,
    pub person_isLocatedIn_place: Vec<Column<Advice>>,

    pub person_id: Column<Advice>,
    pub relation_check_bits: Column<Advice>,
    pub located_zero: crate::chips::is_zero::IsZeroConfig<F>,

    pub result: Vec<Column<Advice>>,
    pub q_result_person: Vec<Selector>,
    pub q_result_shuffle: Vec<Selector>,
    pub q_verify: Selector,

    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is1Chip<F: Field + Ord> {
    config: Is1CircuitConfig<F>,
}

impl<F: Field + Ord> Is1Chip<F> {
    pub fn construct(config: Is1CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Is1CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_personid = meta.selector();

        // personid | firstname | lastname | gender | creationDate | birthday | locationip | browser
        let mut person = Vec::new();
        for _ in 0..8 {
            person.push(meta.advice_column());
        }

        let mut person_isLocatedIn_place = Vec::new();
        for _ in 0..2 {
            person_isLocatedIn_place.push(meta.advice_column());
        }

        let person_id = meta.advice_column();
        let relation_check_bits = meta.advice_column();

        let iz1 = meta.advice_column();
        let located_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_personid),
            |meta| {
                meta.query_advice(person_isLocatedIn_place[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz1,
            relation_check_bits,
        );

        let mut result = Vec::new();
        for _ in 0..9 {
            result.push(meta.advice_column());
        }

        let one = Expression::Constant(F::ONE);
        let mut q_result_person = Vec::new();
        for _ in 0..2 {
            q_result_person.push(meta.complex_selector());
        }
        // meta.lookup_any(format!("lookup"), |meta| {
        //     let q1 = meta.query_selector(q_result_person[0]);
        //     let q2 = meta.query_selector(q_result_person[1]);
        //     let r1 = meta.query_advice(result[0], Rotation::cur());
        //     let r2 = meta.query_advice(result[1], Rotation::cur());
        //     let r3 = meta.query_advice(result[2], Rotation::cur());
        //     let r4 = meta.query_advice(result[3], Rotation::cur());
        //     let r5 = meta.query_advice(result[4], Rotation::cur());
        //     let r6 = meta.query_advice(result[5], Rotation::cur());
        //     let r7 = meta.query_advice(result[6], Rotation::cur());
        //     let r8 = meta.query_advice(result[7], Rotation::cur());
        //     let p1 = meta.query_advice(person[0], Rotation::cur());
        //     let p2 = meta.query_advice(person[1], Rotation::cur());
        //     let p3 = meta.query_advice(person[2], Rotation::cur());
        //     let p4 = meta.query_advice(person[3], Rotation::cur());
        //     let p5 = meta.query_advice(person[4], Rotation::cur());
        //     let p6 = meta.query_advice(person[5], Rotation::cur());
        //     let p7 = meta.query_advice(person[6], Rotation::cur());
        //     let p8 = meta.query_advice(person[7], Rotation::cur());
        //     let lhs = [one.clone(), r1, r2, r3, r4, r5, r6, r7, r8].map(|c| c * q1.clone());
        //     let rhs = [one.clone(), p1, p2, p3, p4, p5, p6, p7, p8].map(|c| c * q2.clone());
        //     lhs.into_iter().zip(rhs).collect()
        // });

        let mut q_result_shuffle = Vec::new();
        for _ in 0..2 {
            q_result_shuffle.push(meta.complex_selector());
        }
        meta.shuffle(format!("shuffle"), |meta| {
            let q1 = meta.query_selector(q_result_shuffle[0]);
            let q2 = meta.query_selector(q_result_shuffle[1]);
            let a = meta.query_advice(result[0], Rotation::cur());
            let b = meta.query_advice(result[8], Rotation::cur());
            let c = meta.query_advice(person_isLocatedIn_place[0], Rotation::cur());
            let d = meta.query_advice(person_isLocatedIn_place[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_verify = meta.selector();
        meta.create_gate("verify q_result_shuffle", |meta| {
            let q_c = meta.query_selector(q_verify);
            let q = meta.query_selector(q_result_shuffle[1]);
            let check = meta.query_advice(relation_check_bits, Rotation::cur());
            vec![q_c * (q.clone() - check)]
        });

        Is1CircuitConfig {
            q_personid,
            person,
            person_id,
            relation_check_bits,
            instance,
            person_isLocatedIn_place,
            located_zero,
            result,
            q_result_person,
            q_result_shuffle,
            q_verify,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<F>>,
        person_isLocatedIn_place: Vec<Vec<F>>,
        person_id_val: F,
    ) -> Result<(), Error> {
        let mut result: Vec<Vec<F>> = Vec::new();

        for relation_row in &person_isLocatedIn_place {
            let person_id = relation_row[0];
            let place_id = relation_row[1];

            for person_row in &person_table {
                if person_row[0] == person_id && person_id == person_id_val {
                    let mut result_row = person_row.clone();
                    result_row.push(place_id);
                    result.push(result_row);
                    break;
                }
            }
        }

        let relation_check_bits: Vec<F> = person_isLocatedIn_place
            .iter()
            .map(|row| {
                if row[0] == person_id_val {
                    F::ONE
                } else {
                    F::ZERO
                }
            })
            .collect();

        let chip_person_eq = IsZeroChip::construct(self.config.located_zero.clone());

        layouter.assign_region(
            || "witness",
            |mut region| {
                for row_idx in 0..person_isLocatedIn_place.len() {
                    self.config.q_personid.enable(&mut region, row_idx)?;

                    for col_idx in 0..person_isLocatedIn_place[row_idx].len() {
                        region.assign_advice(
                            || format!("person row {} col {}", row_idx, col_idx),
                            self.config.person_isLocatedIn_place[col_idx],
                            row_idx,
                            || Value::known(person_isLocatedIn_place[row_idx][col_idx]),
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
                        || Value::known(person_id_val),
                    )?;

                    let diff = person_isLocatedIn_place[row_idx][0] - person_id_val;
                    chip_person_eq
                        .assign(&mut region, row_idx, Value::known(diff))
                        .unwrap();
                }
                for (row_idx, p_row) in person_table.iter().enumerate() {
                    for col_idx in 0..p_row.len() {
                        region.assign_advice(
                            || format!("person row {} col {}", row_idx, col_idx),
                            self.config.person[col_idx],
                            row_idx,
                            || Value::known(p_row[col_idx]),
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
                            || Value::known(result_row[col_idx]),
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
    pub person: Vec<Vec<F>>,
    pub person_isLocatedIn_place: Vec<Vec<F>>,
    pub person_id: F,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_isLocatedIn_place: Vec::new(),
            person_id: F::ZERO,
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = Is1CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Is1Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let chip = Is1Chip::construct(config);

        chip.assign(
            &mut layouter,
            self.person.clone(),
            self.person_isLocatedIn_place.clone(),
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
    fn test_is1_circuit() {
        let k = 16;

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read person data");

        let relation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_isLocatedIn_place_0_0.csv",
            '|',
        )
        .expect("Failed to read relation data");

        let mut person: Vec<Vec<Fr>> = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                Fr::from(row[0].parse::<u64>().expect("invalid Person ID")),
                Fr::from(string_to_u64(&row[1])),
                Fr::from(string_to_u64(&row[2])),
                if row[3] == "male" {
                    Fr::one()
                } else {
                    Fr::zero()
                },
                Fr::from(parse_date(&row[4])),
                Fr::from(parse_datetime(&row[5])),
                Fr::from(ipv4_to_u64(&row[6])),
                Fr::from(string_to_u64(&row[7])),
            ];
            person.push(person_row);
        }
        println!("person.len:{:?}", person.len());

        let mut person_isLocatedIn_place: Vec<Vec<Fr>> = Vec::new();
        for row in &relation_data {
            if row.len() >= 2 {
                let relation_row = vec![
                    Fr::from(row[0].parse::<u64>().unwrap()), // Person.id
                    Fr::from(row[1].parse::<u64>().unwrap()), // Place.id
                ];
                person_isLocatedIn_place.push(relation_row);
            }
        }
        println!(
            "person_isLocatedIn_place.len:{:?}",
            person_isLocatedIn_place.len()
        );

        let person_id = Fr::from(933u64);

        let circuit = MyCircuit::<Fr> {
            person,
            person_id,
            person_isLocatedIn_place,
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
