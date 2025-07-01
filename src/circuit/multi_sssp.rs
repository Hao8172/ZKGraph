use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::data::csr::CsrValue;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::cmp::{max, min};
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_FRIENDS: usize = 10;

/*
Q2. Recent messages by your friends
MATCH (:Person {id: $personId })-[:KNOWS]-(friend:Person)<-[:HAS_CREATOR]-(message:Message)
*/

#[derive(Clone, Debug)]
pub struct set_expandCircuitConfig<F: Field + Ord + std::hash::Hash> {
    friendsid: Vec<Column<Advice>>,
    q_friends: Vec<Selector>,

    comment_hasCreator_person: Vec<Column<Advice>>,
    q_comment_has_creator: Selector,

    comment_creator_match_flag: Vec<Column<Advice>>,
    comment_creator_match_config: Vec<IsZeroConfig<F>>,

    post_hasCreator_person: Vec<Column<Advice>>,
    q_post_has_creator: Selector,

    post_creator_match_flag: Vec<Column<Advice>>,
    post_creator_match_config: Vec<IsZeroConfig<F>>,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct set_expandChip<F: Field + Ord + std::hash::Hash> {
    config: set_expandCircuitConfig<F>,
}

impl<F: Field + Ord + std::hash::Hash> set_expandChip<F> {
    pub fn construct(config: set_expandCircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> set_expandCircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let mut friendsid = Vec::new();
        let mut q_friends = Vec::new();
        let mut comment_creator_match_flag = Vec::new();
        let mut post_creator_match_flag = Vec::new();
        let mut iz_comment_match_advice = Vec::new();
        let mut iz_post_match_advice = Vec::new();
        let mut comment_creator_match_config = Vec::new();
        let mut post_creator_match_config = Vec::new();
        for _ in 0..NUM_FRIENDS {
            friendsid.push(meta.advice_column());
            q_friends.push(meta.complex_selector());
            comment_creator_match_flag.push(meta.advice_column());
            post_creator_match_flag.push(meta.advice_column());
            iz_comment_match_advice.push(meta.advice_column());
            iz_post_match_advice.push(meta.advice_column());
        }

        let one = Expression::Constant(F::ONE);
    
        let mut comment_hasCreator_person = Vec::new();
        for _ in 0..2 {
            comment_hasCreator_person.push(meta.advice_column());
        }
        let q_comment_has_creator = meta.complex_selector();

        for i in 0..NUM_FRIENDS {
            let comment_config = IsZeroChip::configure(
                meta,
                |meta| meta.query_selector(q_comment_has_creator),
                |meta| {
                    meta.query_advice(friendsid[i], Rotation::cur())
                        - meta.query_advice(comment_hasCreator_person[1], Rotation::cur())
                },
                iz_comment_match_advice[i],
                comment_creator_match_flag[i],
            );
            comment_creator_match_config.push(comment_config);
        }

        let mut post_hasCreator_person = Vec::new();
        for _ in 0..2 {
            post_hasCreator_person.push(meta.advice_column());
        }
        let q_post_has_creator = meta.complex_selector();

        for i in 0..NUM_FRIENDS {
            let post_config = IsZeroChip::configure(
                meta,
                |meta| meta.query_selector(q_post_has_creator),
                |meta| {
                    meta.query_advice(friendsid[i], Rotation::cur())
                        - meta.query_advice(post_hasCreator_person[1], Rotation::cur())
                },
                iz_post_match_advice[i],
                post_creator_match_flag[i],
            );
            post_creator_match_config.push(post_config);
        }

        set_expandCircuitConfig {
            friendsid,
            q_friends,
            comment_hasCreator_person,
            q_comment_has_creator,
            comment_creator_match_flag,
            comment_creator_match_config,
            post_hasCreator_person,
            q_post_has_creator,
            post_creator_match_flag,
            post_creator_match_config,
            instance,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        comment_hasCreator_person: Vec<Vec<u64>>,
        post_hasCreator_person: Vec<Vec<u64>>,
        friends_ids_val: Vec<u64>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {

        let mut chip_comment_creator_match =Vec::new();
        let mut chip_post_creator_match =Vec::new();
        for i in 0..NUM_FRIENDS{
            chip_comment_creator_match.push(IsZeroChip::construct(self.config.comment_creator_match_config[i].clone()));
            chip_post_creator_match.push(IsZeroChip::construct(self.config.post_creator_match_config[i].clone()));
        }

        let mut friends_ids = friends_ids_val;

        friends_ids.sort();
        friends_ids.dedup();


        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, row) in comment_hasCreator_person.iter().enumerate() {
                    self.config.q_comment_has_creator.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("comment_hasCreator_person[0] at {}", i),
                        self.config.comment_hasCreator_person[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;

                    region.assign_advice(
                        || format!("comment_hasCreator_person[1] at {}", i),
                        self.config.comment_hasCreator_person[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;

                    for j in 0..NUM_FRIENDS{
                        region.assign_advice(
                            || format!("friendsid at {}", i),
                            self.config.friendsid[j],
                            i,
                            || Value::known(F::from(friends_ids[j])),
                        )?;
                        let diff = F::from(friends_ids[j]) - F::from(row[1]);
                        if diff == F::ZERO{
                            region.assign_advice(
                                || format!("comment_creator_match_flag at {}", i),
                                self.config.comment_creator_match_flag[j],
                                i,
                                || Value::known(F::ONE),
                            )?;
                        } else{
                            region.assign_advice(
                                || format!("comment_creator_match_flag at {}", i),
                                self.config.comment_creator_match_flag[j],
                                i,
                                || Value::known(F::ZERO),
                            )?;
                        }
                        chip_comment_creator_match[j]
                           .assign(&mut region, i, Value::known(diff))
                           .unwrap();
                    }

                }

                for (i, row) in post_hasCreator_person.iter().enumerate() {
                    self.config.q_post_has_creator.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("post_hasCreator_person[0] at {}", i),
                        self.config.post_hasCreator_person[0],
                        i,
                        || Value::known(F::from(row[0])),
                    )?;
                    region.assign_advice(
                        || format!("post_hasCreator_person[1] at {}", i),
                        self.config.post_hasCreator_person[1],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;
                    for j in 0..NUM_FRIENDS{
                        region.assign_advice(
                            || format!("friendsid at {}", i),
                            self.config.friendsid[j],
                            i,
                            || Value::known(F::from(friends_ids[j])),
                        )?;
                        let diff = F::from(friends_ids[j]) - F::from(row[1]);
                        if diff == F::ZERO{
                            region.assign_advice(
                                || format!("post_creator_match_flag at {}", i),
                                self.config.post_creator_match_flag[j],
                                i,
                                || Value::known(F::ONE),
                            )?;
                        } else{
                            region.assign_advice(
                                || format!("post_creator_match_flag at {}", i),
                                self.config.post_creator_match_flag[j],
                                i,
                                || Value::known(F::ZERO),
                            )?;
                        }
                        chip_post_creator_match[j]
                          .assign(&mut region, i, Value::known(diff))
                          .unwrap();
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord + std::hash::Hash> {
    pub comment_hasCreator_person: Vec<Vec<u64>>,
    pub post_hasCreator_person: Vec<Vec<u64>>,
    pub friends_ids_val: Vec<u64>,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord + std::hash::Hash> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            comment_hasCreator_person: Vec::new(),
            post_hasCreator_person: Vec::new(),
            friends_ids_val: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord + std::hash::Hash> Circuit<F> for MyCircuit<F> {
    type Config = set_expandCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        set_expandChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip = set_expandChip::construct(config.clone());

        chip.assign(
            &mut layouter.namespace(|| "Assign"),
            self.comment_hasCreator_person.clone(),
            self.post_hasCreator_person.clone(),
            self.friends_ids_val.clone(),
        )?;

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
    fn set_expand_circuit() {
        let k = 16;

        let post_relation = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/post_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read post data");

        let comment_relation = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/comment_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read comment data");


        let mut comment_hasCreator_person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in comment_relation.iter().enumerate() {
            let comment_row = vec![
                row[0].parse::<u64>().expect("invalid comment ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            comment_hasCreator_person.push(comment_row);
        }
        println!("comment relation.len:{:?}", comment_hasCreator_person.len());

        let mut post_hasCreator_person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in post_relation.iter().enumerate() {
            let post_row = vec![
                row[0].parse::<u64>().expect("invalid post ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            post_hasCreator_person.push(post_row);
        }
        println!("post relation.len:{:?}", post_hasCreator_person.len());


        let circuit = MyCircuit::<Fr> {
            comment_hasCreator_person,
            post_hasCreator_person,
            friends_ids_val: vec![933,1786706421429,1649267467990,1924145374989,2061584328475,1374389534797,687194767478,1236950581381,824633720942,1786706421951],
            _marker: PhantomData,
        };

        let public_input = vec![Fr::from(1)];
        let start = Instant::now();
        let prover = MockProver::run(k, &circuit, vec![public_input]).expect("MockProver fail");
        println!("Proving time: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("verification failed{:?}", e);
            }
        }
    }
}
