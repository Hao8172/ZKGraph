use crate::chips::is_zero::IsZeroChip;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

/*
IS4. Content of a message
:param messageId: 206158431836
MATCH (m:Message {id:  $messageId })
RETURN
    m.creationDate as messageCreationDate,
    coalesce(m.content, m.imageFile) as messageContent
*/

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

#[derive(Clone, Debug)]
pub struct is4CircuitConfig<F: Field + Ord> {
    // id | imagefile(F::ZERO for comment) | content | creationDate
    pub comment: Vec<Column<Advice>>,
    pub post: Vec<Column<Advice>>,

    // id | imagefile | content | |creationDate | is_true
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

    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct is4Chip<F: Field + Ord> {
    config: is4CircuitConfig<F>,
}

impl<F: Field + Ord> is4Chip<F> {
    pub fn construct(config: is4CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> is4CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_commentid = meta.selector();
        let q_postid = meta.selector();

        // id | imagefile | content
        let mut comment = Vec::new();
        let mut post = Vec::new();
        for _ in 0..4 {
            comment.push(meta.advice_column());
            post.push(meta.advice_column());
        }

        let mut picked_comment = Vec::new();
        let mut picked_post = Vec::new();
        for _ in 0..5 {
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
                meta.query_advice(comment[0], Rotation::cur())
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
                meta.query_advice(post[0], Rotation::cur())
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
            let p_is_true = meta.query_advice(picked_comment[4], Rotation::cur());
            let q1 = meta.query_selector(q_picked_comment[0]) * p_is_true;
            let q2 = meta.query_selector(q_picked_comment[1]);
            let p1 = meta.query_advice(picked_comment[0], Rotation::cur());
            let p2 = meta.query_advice(picked_comment[1], Rotation::cur());
            let p3 = meta.query_advice(picked_comment[2], Rotation::cur());
            let p4 = meta.query_advice(picked_comment[3], Rotation::cur());
            let c1 = meta.query_advice(comment[0], Rotation::cur());
            let c2 = meta.query_advice(comment[1], Rotation::cur());
            let c3 = meta.query_advice(comment[2], Rotation::cur());
            let c4 = meta.query_advice(comment[3], Rotation::cur());
            let lhs = [one.clone(), p1, p2, p3, p4].map(|c| c * q1.clone());
            let rhs = [one.clone(), c1, c2, c3, c4].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut q_picked_post = Vec::new();
        for _ in 0..2 {
            q_picked_post.push(meta.complex_selector());
        }
        meta.lookup_any(format!("post lookup"), |meta| {
            let p_is_true = meta.query_advice(picked_post[4], Rotation::cur());
            let q1 = meta.query_selector(q_picked_post[0]) * p_is_true;
            let q2 = meta.query_selector(q_picked_post[1]);
            let p1 = meta.query_advice(picked_post[0], Rotation::cur());
            let p2 = meta.query_advice(picked_post[1], Rotation::cur());
            let p3 = meta.query_advice(picked_post[2], Rotation::cur());
            let p4 = meta.query_advice(picked_post[3], Rotation::cur());
            let c1 = meta.query_advice(post[0], Rotation::cur());
            let c2 = meta.query_advice(post[1], Rotation::cur());
            let c3 = meta.query_advice(post[2], Rotation::cur());
            let c4 = meta.query_advice(post[3], Rotation::cur());
            let lhs = [one.clone(), p1, p2, p3, p4].map(|c| c * q1.clone());
            let rhs = [one.clone(), c1, c2, c3, c4].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        is4CircuitConfig {
            comment,
            post,
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
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        comment: Vec<Vec<u64>>,
        post: Vec<Vec<u64>>,
        message_id: u64,
    ) -> Result<(), Error> {
        let mut res_comment = vec![0u64; 5];
        let mut res_post = vec![0u64; 5];

        for row in comment.iter() {
            if row[0] == message_id {
                res_comment[0] = row[0];
                res_comment[1] = row[1];
                res_comment[2] = row[2];
                res_comment[3] = row[3];
                res_comment[4] = 1;
            }
        }
        for row in post.iter() {
            if row[0] == message_id {
                res_post[0] = row[0];
                res_post[1] = row[1];
                res_post[2] = row[2];
                res_post[3] = row[3];
                res_post[4] = 1;
            }
        }

        let comment_check_bits: Vec<u64> = comment
            .iter()
            .map(|row| {
                if row[0] == message_id {
                    1
                } else {
                    0
                }
            })
            .collect();

        let post_check_bits: Vec<u64> = post
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
                for (i, row) in comment.iter().enumerate() {
                    self.config.q_picked_comment[1].enable(&mut region, i)?;
                    for j in 0..row.len() {
                        region.assign_advice(
                            || format!("comment row {} col {}", i, j),
                            self.config.comment[j],
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
                for (i, row) in post.iter().enumerate() {
                    self.config.q_picked_post[1].enable(&mut region, i)?;

                    for j in 0..row.len() {
                        region.assign_advice(
                            || format!("post row {} col {}", i, j),
                            self.config.post[j],
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
                for i in 0..5 {
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

                Ok(())
            },
        )?;
        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord> {
    pub comment: Vec<Vec<u64>>,
    pub post: Vec<Vec<u64>>,
    pub message_id: u64,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            comment: Vec::new(),
            post: Vec::new(),
            message_id: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
    type Config = is4CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        is4Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let chip = is4Chip::construct(config);

        chip.assign(
            &mut layouter,
            self.comment.clone(),
            self.post.clone(),
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
    fn test_is4_circuit() {
        let k = 16;

        let post_data = read_csv("/home/wh/zkgraph/src/data/message_fact/60k/post.csv", '|')
            .expect("Failed to read person data");

        let comment_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/comment.csv",
            '|',
        )
        .expect("Failed to read comment data");

        let mut comment: Vec<Vec<u64>> = Vec::new();
        for (_, row) in comment_data.iter().enumerate() {
            let comment_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                0, // F::ZERO
                string_to_u64(&row[4]),
                parse_datetime(&row[1]),
            ];
            comment.push(comment_row);
        }

        let mut post: Vec<Vec<u64>> = Vec::new();
        for (_, row) in post_data.iter().enumerate() {
            let post_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[6]),
                parse_datetime(&row[2]),
            ];
            post.push(post_row);
        }

        let message_id = 618475290624;
        println!("comment.len:{:?}", comment.len());
        println!("post.len:{:?}", post.len());

        let circuit = MyCircuit::<Fr> {
            comment,
            post,
            message_id,
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
