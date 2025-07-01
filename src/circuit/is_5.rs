use crate::chips::is_zero::IsZeroChip;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

/*
IS5. Creator of a message
MATCH (m:Message {id:  $messageId })-[:HAS_CREATOR]->(p:Person)
RETURN
    p.id AS personId,
    p.firstName AS firstName,
    p.lastName AS lastName
*/

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct Is5circuitConfig<F: Field + Ord> {
    pub comment_hasCreator_person: Vec<Column<Advice>>,
    pub post_hasCreator_person: Vec<Column<Advice>>,

    // messageid | personid
    pub picked_comment: Vec<Column<Advice>>,
    pub picked_post: Vec<Column<Advice>>,

    pub message_id: Column<Advice>,
    pub comment_eq: crate::chips::is_zero::IsZeroConfig<F>,
    pub post_eq: crate::chips::is_zero::IsZeroConfig<F>,

    pub comment_check_bits: Column<Advice>,
    pub post_check_bits: Column<Advice>,

    pub q_commentid: Selector,
    pub q_postid: Selector,

    pub q_picked_comment: Vec<Selector>,
    pub q_picked_post: Vec<Selector>,

    // id | firstName | lastName
    pub person: Vec<Column<Advice>>,
    pub result_person: Vec<Column<Advice>>,
    pub q_picked_person: Vec<Selector>,
    pub q_verify: Selector,

    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is5chip<F: Field + Ord> {
    config: Is5circuitConfig<F>,
}

impl<F: Field + Ord> Is5chip<F> {
    pub fn construct(config: Is5circuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Is5circuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_commentid = meta.selector();
        let q_postid = meta.selector();

        let mut comment_hasCreator_person = Vec::new();
        let mut post_hasCreator_person = Vec::new();
        for _ in 0..2 {
            comment_hasCreator_person.push(meta.advice_column());
            post_hasCreator_person.push(meta.advice_column());
        }

        let mut picked_comment = Vec::new();
        let mut picked_post = Vec::new();
        for _ in 0..3 {
            picked_comment.push(meta.advice_column());
            picked_post.push(meta.advice_column());
        }

        let message_id = meta.advice_column();
        let comment_check_bits = meta.advice_column();
        let post_check_bits = meta.advice_column();

        let iz1 = meta.advice_column();
        let comment_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_commentid),
            |meta| {
                meta.query_advice(comment_hasCreator_person[0], Rotation::cur())
                    - meta.query_advice(message_id, Rotation::cur())
            },
            iz1,
            comment_check_bits,
        );

        let iz2 = meta.advice_column();
        let post_eq = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_postid),
            |meta| {
                meta.query_advice(post_hasCreator_person[0], Rotation::cur())
                    - meta.query_advice(message_id, Rotation::cur())
            },
            iz2,
            post_check_bits,
        );

        let one = Expression::Constant(F::ONE);
        let mut q_picked_comment = Vec::new();
        for _ in 0..2 {
            q_picked_comment.push(meta.complex_selector());
        }
        meta.lookup_any(format!("comment lookup"), |meta| {
            let p_is_true = meta.query_advice(picked_comment[2], Rotation::cur());
            let q1 = meta.query_selector(q_picked_comment[0]) * p_is_true;
            let q2 = meta.query_selector(q_picked_comment[1]);
            let p1 = meta.query_advice(picked_comment[0], Rotation::cur());
            let p2 = meta.query_advice(picked_comment[1], Rotation::cur());
            let c1 = meta.query_advice(comment_hasCreator_person[0], Rotation::cur());
            let c2 = meta.query_advice(comment_hasCreator_person[1], Rotation::cur());
            let lhs = [one.clone(), p1, p2].map(|c| c * q1.clone());
            let rhs = [one.clone(), c1, c2].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut q_picked_post = Vec::new();
        for _ in 0..2 {
            q_picked_post.push(meta.complex_selector());
        }
        meta.lookup_any(format!("post lookup"), |meta| {
            let p_is_true = meta.query_advice(picked_post[2], Rotation::cur());
            let q1 = meta.query_selector(q_picked_post[0]) * p_is_true;
            let q2 = meta.query_selector(q_picked_post[1]);
            let p1 = meta.query_advice(picked_post[0], Rotation::cur());
            let p2 = meta.query_advice(picked_post[1], Rotation::cur());
            let c1 = meta.query_advice(post_hasCreator_person[0], Rotation::cur());
            let c2 = meta.query_advice(post_hasCreator_person[1], Rotation::cur());
            let lhs = [one.clone(), p1, p2].map(|c| c * q1.clone());
            let rhs = [one.clone(), c1, c2].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut person = Vec::new();
        for _ in 0..3 {
            person.push(meta.advice_column());
        }
        let mut result_person = Vec::new();
        for _ in 0..3 {
            result_person.push(meta.advice_column());
        }
        let mut q_picked_person = Vec::new();
        for _ in 0..2 {
            q_picked_person.push(meta.complex_selector());
        }
        meta.lookup_any(format!("person lookup"), |meta| {
            let q1 = meta.query_selector(q_picked_person[0]);
            let q2 = meta.query_selector(q_picked_person[1]);
            let p1 = meta.query_advice(result_person[0], Rotation::cur());
            let p2 = meta.query_advice(result_person[1], Rotation::cur());
            let p3 = meta.query_advice(result_person[2], Rotation::cur());
            let c1 = meta.query_advice(person[0], Rotation::cur());
            let c2 = meta.query_advice(person[1], Rotation::cur());
            let c3 = meta.query_advice(person[2], Rotation::cur());
            let lhs = [one.clone(), p1, p2, p3].map(|c| c * q1.clone());
            let rhs = [one.clone(), c1, c2, c3].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_verify = meta.selector();
        meta.create_gate("verify person", |meta| {
            let q = meta.query_selector(q_verify);
            let p = meta.query_advice(result_person[0], Rotation::cur());
            let a = meta.query_advice(picked_comment[1], Rotation::cur());
            let b = meta.query_advice(picked_post[1], Rotation::cur());
            let true1 = meta.query_advice(picked_comment[2], Rotation::cur());
            let true2 = meta.query_advice(picked_post[2], Rotation::cur());
            vec![q * (p - a * true1 - b * true2)]
        });

        Is5circuitConfig {
            picked_comment,
            picked_post,
            message_id,
            comment_eq,
            post_eq,
            comment_check_bits,
            post_check_bits,
            q_commentid,
            q_postid,
            instance,
            q_picked_comment,
            q_picked_post,
            comment_hasCreator_person,
            post_hasCreator_person,
            person,
            result_person,
            q_picked_person,
            q_verify,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        comment_hasCreator_person: Vec<Vec<u64>>,
        post_hasCreator_person: Vec<Vec<u64>>,
        person: Vec<Vec<u64>>,
        message_id: u64,
    ) -> Result<(), Error> {
        let mut res_comment = vec![0u64; 3];
        let mut res_post = vec![0u64; 3];
        let mut person_id = 0u64;

        for row in comment_hasCreator_person.iter() {
            if row[0] == message_id {
                res_comment[0] = row[0];
                res_comment[1] = row[1];
                res_comment[2] = 1;
                person_id = row[1];
            }
        }
        for row in post_hasCreator_person.iter() {
            if row[0] == message_id {
                res_post[0] = row[0];
                res_post[1] = row[1];
                res_post[2] = 1;
                person_id = row[1];
            }
        }

        let mut res_person = vec![0u64; 3];
        for row in person.iter() {
            if row[0] == person_id {
                res_person[0] = row[0];
                res_person[1] = row[1];
                res_person[2] = row[2];
            }
        }

        let comment_check_bits: Vec<u64> = comment_hasCreator_person
            .iter()
            .map(|row| {
                if row[0] == message_id {
                    1
                } else {
                    0
                }
            })
            .collect();

        let post_check_bits: Vec<u64> = post_hasCreator_person
            .iter()
            .map(|row| {
                if row[0] == message_id {
                    1
                } else {
                    0
                }
            })
            .collect();


        let comment_eq = IsZeroChip::construct(self.config.comment_eq.clone());
        let post_eq = IsZeroChip::construct(self.config.post_eq.clone());

        layouter.assign_region(
            || "witness",
            |mut region| {
                for (i, row) in comment_hasCreator_person.iter().enumerate() {
                    self.config.q_picked_comment[1].enable(&mut region, i)?;
                    for j in 0..comment_hasCreator_person[0].len() {
                        region.assign_advice(
                            || format!("comment_hasCreator_person row {} col {}", i, j),
                            self.config.comment_hasCreator_person[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }
                    region.assign_advice(
                        || "comment_check",
                        self.config.comment_check_bits,
                        i,
                        || Value::known(F::from(comment_check_bits[i])),
                    )?;
                    region.assign_advice(
                        || "messageid",
                        self.config.message_id,
                        i,
                        || Value::known(F::from(message_id)),
                    )?;
                    self.config.q_commentid.enable(&mut region, i)?;
                    let diff = F::from(row[0]) - F::from(message_id);
                    comment_eq
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();
                }
                for (i, row) in post_hasCreator_person.iter().enumerate() {
                    self.config.q_picked_post[1].enable(&mut region, i)?;

                    for j in 0..post_hasCreator_person[0].len() {
                        region.assign_advice(
                            || format!("post_hasCreator_person row {} col {}", i, j),
                            self.config.post_hasCreator_person[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }
                    region.assign_advice(
                        || "post_check",
                        self.config.post_check_bits,
                        i,
                        || Value::known(F::from(post_check_bits[i])),
                    )?;
                    region.assign_advice(
                        || "messageid",
                        self.config.message_id,
                        i,
                        || Value::known(F::from(message_id)),
                    )?;
                    self.config.q_postid.enable(&mut region, i)?;
                    let diff = F::from(row[0]) - F::from(message_id);
                    post_eq.assign(&mut region, i, Value::known(diff)).unwrap();
                }
                self.config.q_picked_comment[0].enable(&mut region, 0)?;
                self.config.q_picked_post[0].enable(&mut region, 0)?;
                for i in 0..3 {
                    region.assign_advice(
                        || format!("picked_comment row {} col {}", 0, i),
                        self.config.picked_comment[i],
                        0,
                        || Value::known(F::from(res_comment[i])),
                    )?;
                    region.assign_advice(
                        || format!("picked_post row {} col {}", 0, i),
                        self.config.picked_post[i],
                        0,
                        || Value::known(F::from(res_post[i])),
                    )?;
                }
                for (i, row) in person.iter().enumerate() {
                    self.config.q_picked_person[1].enable(&mut region, i)?;
                    for j in 0..person[0].len() {
                        region.assign_advice(
                            || format!("person row {} col {}", i, j),
                            self.config.person[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }
                }
                for i in 0..3 {
                    region.assign_advice(
                        || format!("result_person row {} col {}", 0, i),
                        self.config.result_person[i],
                        0,
                        || Value::known(F::from(res_person[i])),
                    )?;
                }
                self.config.q_picked_person[0].enable(&mut region, 0)?;
                self.config.q_verify.enable(&mut region, 0)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord> {
    pub comment_hasCreator_person: Vec<Vec<u64>>,
    pub post_hasCreator_person: Vec<Vec<u64>>,
    pub message_id: u64,  
    pub person: Vec<Vec<u64>>,     
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            comment_hasCreator_person: Vec::new(),
            post_hasCreator_person: Vec::new(),
            message_id: Default::default(),
            person: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = Is5circuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }


    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Is5chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let chip = Is5chip::construct(config);

        chip.assign(
            &mut layouter,
            self.comment_hasCreator_person.clone(),
            self.post_hasCreator_person.clone(),
            self.person.clone(),
            self.message_id,
        )
        .unwrap();

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64};
    use ff::Field;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::time::Instant;

    #[test]
    fn test_is5_circuit() {
        let k = 16;


        let post_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/post_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read post data");

        let comment_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/comment_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read comment data");

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read person data");

        let mut person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[2]),
            ];
            person.push(person_row);
        }

        let mut comment_hasCreator_person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in comment_data.iter().enumerate() {
            let comment_row = vec![
                row[0].parse::<u64>().expect("invalid comment ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            comment_hasCreator_person.push(comment_row);
        }

        let mut post_hasCreator_person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in post_data.iter().enumerate() {
            let post_row = vec![
                row[0].parse::<u64>().expect("invalid post ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            post_hasCreator_person.push(post_row);
        }

        let message_id = 137438953926;

        let circuit = MyCircuit::<Fr> {
            comment_hasCreator_person,
            post_hasCreator_person,
            message_id,
            person,
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
