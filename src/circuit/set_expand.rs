use crate::chips::is_zero::IsZeroChip;
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

const NUM_BYTES: usize = 6;
const MAX_PERSON_ID: u64 = 100000000000000;

/*
Q2. Recent messages by your friends
MATCH (:Person {id: $personId })-[:KNOWS]-(friend:Person)<-[:HAS_CREATOR]-(message:Message)
*/

#[derive(Clone, Debug)]
pub struct set_expandCircuitConfig<F: Field + Ord + std::hash::Hash> {
    friendsid: Column<Advice>,
    q_friends: Selector,

    friendsid_ext: Column<Advice>,
    q_friendsid_ext: Selector,
    q_friendsid_ext_order: Selector,
    friendsid_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_friendsid_ext_internal: Selector,
    q_friendsid_ext_boundary: Selector,
    friendsid_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_friendsid_ext_pairs_lookup: Selector,

    comment_hasCreator_person: Vec<Column<Advice>>,
    q_comment_has_creator: Selector,
    ordered_comment_creator: Vec<Column<Advice>>,
    q_ordered_comment_creator_sort: Selector,
    aligned_comment_creator_friend_id: Column<Advice>,
    next_aligned_comment_creator_friend_id: Column<Advice>,

    ordered_comment_creator_person_id_sort_config: LtEqGenericConfig<F, NUM_BYTES>,

    align_comment_friend_id_le_person_id_config: LtEqGenericConfig<F, NUM_BYTES>,
    person_id_lt_next_aligned_comment_friend_id_config: LtEqGenericConfig<F, NUM_BYTES>,

    comment_creator_match_flag: Column<Advice>,
    comment_creator_match_config: crate::chips::is_zero::IsZeroConfig<F>,

    post_hasCreator_person: Vec<Column<Advice>>,
    q_post_has_creator: Selector,
    ordered_post_creator: Vec<Column<Advice>>,
    q_ordered_post_creator_sort: Selector,
    aligned_post_creator_friend_id: Column<Advice>,
    next_aligned_post_creator_friend_id: Column<Advice>,

    align_post_friend_id_le_person_id_config: LtEqGenericConfig<F, NUM_BYTES>,
    person_id_lt_next_aligned_post_friend_id_config: LtEqGenericConfig<F, NUM_BYTES>,

    ordered_post_creator_person_id_sort_config: LtEqGenericConfig<F, NUM_BYTES>,

    post_creator_match_flag: Column<Advice>,
    post_creator_match_config: crate::chips::is_zero::IsZeroConfig<F>,

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


        let friendsid = meta.advice_column();
        let q_friends = meta.complex_selector();
        let one = Expression::Constant(F::ONE);
        //-----------------------
        let friendsid_ext = meta.advice_column();
        meta.enable_equality(friendsid_ext);
        let q_friendsid_ext = meta.complex_selector();
        let q_friendsid_ext_order = meta.complex_selector();
        let q_friendsid_ext_internal = meta.complex_selector();
        let q_friendsid_ext_boundary = meta.complex_selector();

        let friendsid_ext_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_friendsid_ext_order),
            |meta| vec![meta.query_advice(friendsid_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(friendsid_ext, Rotation::next())],
        );
        meta.create_gate("friendsid_ext order check", |meta| {
            let q = meta.query_selector(q_friendsid_ext_order);
            // friendsid_ext[i] <= friendsid_ext[i+1] means is_lt should be 1.
            vec![q * (friendsid_ext_order_config.is_lt(meta, None) - one.clone())]
        });

        meta.shuffle("friendsid to friendsid_ext internal", |meta| {
            let q_src = meta.query_selector(q_friends);
            let q_dest = meta.query_selector(q_friendsid_ext_internal);
            let a = meta.query_advice(friendsid, Rotation::cur());
            let c = meta.query_advice(friendsid_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q_src.clone());
            let rhs = [one.clone(), c].map(|c| c * q_dest.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("friendsid_ext boundary check", |meta| {
            let q = meta.query_selector(q_friendsid_ext_boundary);
            let current_val = meta.query_advice(friendsid_ext, Rotation::cur());
            vec![
                q * current_val.clone()
                    * (current_val - Expression::Constant(F::from(MAX_PERSON_ID))),
            ]
        });

        meta.create_gate("friendsid_ext selector logic", |meta| {
            let q_ext_active = meta.query_selector(q_friendsid_ext);
            let q_int_active = meta.query_selector(q_friendsid_ext_internal);
            let q_bound_active = meta.query_selector(q_friendsid_ext_boundary);
            vec![q_ext_active * (q_int_active + q_bound_active - one.clone())]
        });

        let mut friendsid_ext_pairs_lookup_table = Vec::new();
        for _ in 0..2 {
            friendsid_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(friendsid_ext_pairs_lookup_table[i]);
        }
        let q_friendsid_ext_pairs_lookup = meta.complex_selector();

        let mut comment_hasCreator_person = Vec::new();
        for _ in 0..2 {
            comment_hasCreator_person.push(meta.advice_column());
        }
        let q_comment_has_creator = meta.complex_selector();

        let mut ordered_comment_creator = Vec::new();
        for _ in 0..2 {
            ordered_comment_creator.push(meta.advice_column());
        }
        meta.shuffle("shuffle comment_hasCreator_person to ordered", |meta| {
            let q = meta.query_selector(q_comment_has_creator);
            let a = meta.query_advice(comment_hasCreator_person[0], Rotation::cur());
            let b = meta.query_advice(comment_hasCreator_person[1], Rotation::cur());
            let c = meta.query_advice(ordered_comment_creator[0], Rotation::cur());
            let d = meta.query_advice(ordered_comment_creator[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_comment_creator_sort = meta.complex_selector();
        let ordered_comment_creator_person_id_sort_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_comment_creator_sort),
            |meta| vec![meta.query_advice(ordered_comment_creator[1], Rotation::cur())], // cur.PersonId
            |meta| vec![meta.query_advice(ordered_comment_creator[1], Rotation::next())], // next.PersonId
        );
        meta.create_gate("verify ordered_comment", |meta| {
            let q = meta.query_selector(q_ordered_comment_creator_sort);
            vec![
                q.clone()
                    * (ordered_comment_creator_person_id_sort_config.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let aligned_comment_creator_friend_id = meta.advice_column();
        let next_aligned_comment_creator_friend_id = meta.advice_column();

        meta.lookup_any(format!("align[i] from friendsid_ext"), |meta| {
            let q = meta.query_selector(q_comment_has_creator);
            let a = meta.query_advice(aligned_comment_creator_friend_id, Rotation::cur());
            let b = meta.query_advice(friendsid_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let align_comment_friend_id_le_person_id_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_comment_has_creator),
            |meta| vec![meta.query_advice(aligned_comment_creator_friend_id, Rotation::cur())], // aligned_friend_id
            |meta| vec![meta.query_advice(ordered_comment_creator[1], Rotation::cur())], // actual Person.id
        );
        meta.create_gate("align_comment_friend_id <= person_id", |meta| {
            let q = meta.query_selector(q_comment_has_creator);
            vec![q * (align_comment_friend_id_le_person_id_config.is_lt(meta, None) - one.clone())]
        });

        let person_id_lt_next_aligned_comment_friend_id_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_comment_has_creator),
            |meta| vec![meta.query_advice(ordered_comment_creator[1], Rotation::cur())], // actual Person.id
            |meta| {
                vec![
                    meta.query_advice(next_aligned_comment_creator_friend_id, Rotation::cur())
                        - one.clone(),
                ]
            }, // next_aligned_id - 1
        );
        meta.create_gate("person_id < next_aligned_comment_friend_id", |meta| {
            let q = meta.query_selector(q_comment_has_creator);
            vec![
                q * (person_id_lt_next_aligned_comment_friend_id_config.is_lt(meta, None)
                    - one.clone()),
            ]
        });

        meta.lookup_any("comment_creator_alignment_lookup", |meta| {
            let q1 = meta.query_selector(q_comment_has_creator);
            let q2 = meta.query_selector(q_friendsid_ext_pairs_lookup);
            let a = meta.query_advice(aligned_comment_creator_friend_id, Rotation::cur());
            let b = meta.query_advice(next_aligned_comment_creator_friend_id, Rotation::cur());
            let c = meta.query_advice(friendsid_ext_pairs_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(friendsid_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let comment_creator_match_flag = meta.advice_column();
        let iz_comment_match_advice = meta.advice_column();
        let comment_creator_match_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_comment_has_creator),
            |meta| {
                meta.query_advice(aligned_comment_creator_friend_id, Rotation::cur())
                    - meta.query_advice(ordered_comment_creator[1], Rotation::cur())
            },
            iz_comment_match_advice,
            comment_creator_match_flag,
        );

        let mut post_hasCreator_person = Vec::new();
        for _ in 0..2 {
            post_hasCreator_person.push(meta.advice_column());
        }
        let q_post_has_creator = meta.complex_selector();

        let mut ordered_post_creator = Vec::new();
        for _ in 0..2 {
            ordered_post_creator.push(meta.advice_column());
        }
        meta.shuffle("shuffle post_hasCreator_person to ordered", |meta| {
            let q = meta.query_selector(q_post_has_creator);
            let a = meta.query_advice(post_hasCreator_person[0], Rotation::cur());
            let b = meta.query_advice(post_hasCreator_person[1], Rotation::cur());
            let c = meta.query_advice(ordered_post_creator[0], Rotation::cur());
            let d = meta.query_advice(ordered_post_creator[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_post_creator_sort = meta.complex_selector();
        let ordered_post_creator_person_id_sort_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_post_creator_sort),
            |meta| vec![meta.query_advice(ordered_post_creator[1], Rotation::cur())], // cur.PersonId
            |meta| vec![meta.query_advice(ordered_post_creator[1], Rotation::next())], // next.PersonId
        );
        meta.create_gate("verify ordered_post", |meta| {
            let q = meta.query_selector(q_ordered_post_creator_sort);
            vec![
                q.clone()
                    * (ordered_post_creator_person_id_sort_config.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let aligned_post_creator_friend_id = meta.advice_column();
        let next_aligned_post_creator_friend_id = meta.advice_column();

        meta.lookup_any(format!("align[i] from friendsid_ext"), |meta| {
            let q = meta.query_selector(q_post_has_creator);
            let a = meta.query_advice(aligned_post_creator_friend_id, Rotation::cur());
            let b = meta.query_advice(friendsid_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let align_post_friend_id_le_person_id_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_post_has_creator),
            |meta| vec![meta.query_advice(aligned_post_creator_friend_id, Rotation::cur())], // aligned_friend_id
            |meta| vec![meta.query_advice(ordered_post_creator[1], Rotation::cur())], // actual Person.id
        );
        meta.create_gate("align_post_friend_id <= person_id", |meta| {
            let q = meta.query_selector(q_post_has_creator);
            vec![q * (align_post_friend_id_le_person_id_config.is_lt(meta, None) - one.clone())]
        });

        let person_id_lt_next_aligned_post_friend_id_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_post_has_creator),
            |meta| vec![meta.query_advice(ordered_post_creator[1], Rotation::cur())], // actual Person.id
            |meta| {
                vec![
                    meta.query_advice(next_aligned_post_creator_friend_id, Rotation::cur())
                        - one.clone(),
                ]
            }, // next_aligned_id - 1
        );
        meta.create_gate("person_id < next_aligned_post_friend_id", |meta| {
            let q = meta.query_selector(q_post_has_creator);
            vec![
                q * (person_id_lt_next_aligned_post_friend_id_config.is_lt(meta, None)
                    - one.clone()),
            ]
        });

        meta.lookup_any("post_creator_alignment_lookup", |meta| {
            let q1 = meta.query_selector(q_post_has_creator);
            let q2 = meta.query_selector(q_friendsid_ext_pairs_lookup);
            let a = meta.query_advice(aligned_post_creator_friend_id, Rotation::cur());
            let b = meta.query_advice(next_aligned_post_creator_friend_id, Rotation::cur());
            let c = meta.query_advice(friendsid_ext_pairs_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(friendsid_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let post_creator_match_flag = meta.advice_column();
        let iz_post_match_advice = meta.advice_column();
        let post_creator_match_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_post_has_creator),
            |meta| {
                meta.query_advice(aligned_post_creator_friend_id, Rotation::cur())
                    - meta.query_advice(ordered_post_creator[1], Rotation::cur())
            },
            iz_post_match_advice,
            post_creator_match_flag,
        );

        set_expandCircuitConfig {
            instance,
            friendsid,
            q_friends,
            friendsid_ext,
            q_friendsid_ext,
            q_friendsid_ext_order,
            friendsid_ext_order_config,
            q_friendsid_ext_internal,
            q_friendsid_ext_boundary,
            friendsid_ext_pairs_lookup_table,
            q_friendsid_ext_pairs_lookup,
            comment_hasCreator_person,
            q_comment_has_creator,
            ordered_comment_creator,
            q_ordered_comment_creator_sort,
            aligned_comment_creator_friend_id,
            next_aligned_comment_creator_friend_id,
            ordered_comment_creator_person_id_sort_config,
            align_comment_friend_id_le_person_id_config,
            person_id_lt_next_aligned_comment_friend_id_config,
            comment_creator_match_flag,
            comment_creator_match_config,
            post_hasCreator_person,
            q_post_has_creator,
            ordered_post_creator,
            q_ordered_post_creator_sort,
            aligned_post_creator_friend_id,
            next_aligned_post_creator_friend_id,
            align_post_friend_id_le_person_id_config,
            person_id_lt_next_aligned_post_friend_id_config,
            ordered_post_creator_person_id_sort_config,
            post_creator_match_flag,
            post_creator_match_config,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        comment_hasCreator_person: Vec<Vec<u64>>,
        post_hasCreator_person: Vec<Vec<u64>>,
        friends_ids_val: Vec<u64>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip_comment_creator_match =
            IsZeroChip::construct(self.config.comment_creator_match_config.clone());
        let chip_post_creator_match =
            IsZeroChip::construct(self.config.post_creator_match_config.clone());

        let friendsid_ext_order_chip =
            LtEqGenericChip::construct(self.config.friendsid_ext_order_config.clone());
        let ordered_comment_creator_person_id_sort_chip = LtEqGenericChip::construct(
            self.config
                .ordered_comment_creator_person_id_sort_config
                .clone(),
        );
        let align_comment_friend_id_le_person_id_chip = LtEqGenericChip::construct(
            self.config
                .align_comment_friend_id_le_person_id_config
                .clone(),
        );
        let person_id_lt_next_aligned_comment_friend_id_chip = LtEqGenericChip::construct(
            self.config
                .person_id_lt_next_aligned_comment_friend_id_config
                .clone(),
        );
        let ordered_post_creator_person_id_sort_chip = LtEqGenericChip::construct(
            self.config
                .ordered_post_creator_person_id_sort_config
                .clone(),
        );
        let align_post_friend_id_le_person_id_chip = LtEqGenericChip::construct(
            self.config.align_post_friend_id_le_person_id_config.clone(),
        );
        let person_id_lt_next_aligned_post_friend_id_chip = LtEqGenericChip::construct(
            self.config
                .person_id_lt_next_aligned_post_friend_id_config
                .clone(),
        );

        friendsid_ext_order_chip.load(layouter).unwrap();
        ordered_comment_creator_person_id_sort_chip
            .load(layouter)
            .unwrap();
        align_comment_friend_id_le_person_id_chip
            .load(layouter)
            .unwrap();
        person_id_lt_next_aligned_comment_friend_id_chip
            .load(layouter)
            .unwrap();
        ordered_post_creator_person_id_sort_chip
            .load(layouter)
            .unwrap();
        align_post_friend_id_le_person_id_chip
            .load(layouter)
            .unwrap();
        person_id_lt_next_aligned_post_friend_id_chip
            .load(layouter)
            .unwrap();

        let mut friends_ids = friends_ids_val;

        friends_ids.sort();
        friends_ids.dedup();

        let mut friendsid_ext_values = vec![0u64];
        for &id in &friends_ids {
            friendsid_ext_values.push(id);
        }
        friendsid_ext_values.push(MAX_PERSON_ID);

        let mut friendsid_ext_pairs: Vec<(u64, u64)> = Vec::new();
        for i in 0..friendsid_ext_values.len() - 1 {
            friendsid_ext_pairs.push((friendsid_ext_values[i], friendsid_ext_values[i + 1]));
        }


        let mut candidate_messages: Vec<Vec<u64>> = Vec::new();


        let mut comment_creators: HashMap<u64, Vec<u64>> = HashMap::new();
        for row in &comment_hasCreator_person {
            let message_id = row[0];
            let person_id = row[1];
            if friends_ids.contains(&person_id) {
                comment_creators
                    .entry(message_id)
                    .or_default()
                    .push(person_id);
            }
        }

        let mut post_creators: HashMap<u64, Vec<u64>> = HashMap::new();
        for row in &post_hasCreator_person {
            let message_id = row[0];
            let person_id = row[1];
            if friends_ids.contains(&person_id) {
                post_creators.entry(message_id).or_default().push(person_id);
            }
        }

        candidate_messages.sort_by(|a, b| {
            if a[1] != b[1] {
                b[1].cmp(&a[1])
            } else {
                a[0].cmp(&b[0])
            }
        });

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, &friend_id) in friends_ids.iter().enumerate() {
                    self.config.q_friends.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("friendsid at {}", i),
                        self.config.friendsid,
                        i,
                        || Value::known(F::from(friend_id)),
                    )?;;
                }

                for (i, &ext_id) in friendsid_ext_values.iter().enumerate() {
                    self.config.q_friendsid_ext.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("friendsid_ext at {}", i),
                        self.config.friendsid_ext,
                        i,
                        || Value::known(F::from(ext_id)),
                    )?;

                    if i > 0 && i < friendsid_ext_values.len() - 1 {
                        self.config
                            .q_friendsid_ext_internal
                            .enable(&mut region, i)?;
                    } else {
                        self.config
                            .q_friendsid_ext_boundary
                            .enable(&mut region, i)?;
                    }

                    if i < friendsid_ext_values.len() - 1 {
                        self.config.q_friendsid_ext_order.enable(&mut region, i)?;

                        friendsid_ext_order_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(ext_id)],
                                &[F::from(friendsid_ext_values[i + 1])],
                            )
                            .unwrap();
                    }
                }

                for (i, (first, second)) in friendsid_ext_pairs.iter().enumerate() {
                    self.config
                        .q_friendsid_ext_pairs_lookup
                        .enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("friendsid_ext_pairs[0] at {}", i),
                        self.config.friendsid_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(F::from(*first)),
                    )?;

                    region.assign_advice(
                        || format!("friendsid_ext_pairs[1] at {}", i),
                        self.config.friendsid_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(F::from(*second)),
                    )?;
                }

                let mut ordered_comment_creators: Vec<(u64, u64)> = Vec::new();
                for row in &comment_hasCreator_person {
                    ordered_comment_creators.push((row[0], row[1]));
                }
                ordered_comment_creators.sort_by(|a, b| a.1.cmp(&b.1));

                for (i, &(message_id, creator_id)) in ordered_comment_creators.iter().enumerate() {
                    self.config.q_comment_has_creator.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("comment_hasCreator_person[0] at {}", i),
                        self.config.comment_hasCreator_person[0],
                        i,
                        || Value::known(F::from(message_id)),
                    )?;

                    region.assign_advice(
                        || format!("comment_hasCreator_person[1] at {}", i),
                        self.config.comment_hasCreator_person[1],
                        i,
                        || Value::known(F::from(creator_id)),
                    )?;

                    region.assign_advice(
                        || format!("ordered_comment_creator[0] at {}", i),
                        self.config.ordered_comment_creator[0],
                        i,
                        || Value::known(F::from(message_id)),
                    )?;

                    region.assign_advice(
                        || format!("ordered_comment_creator[1] at {}", i),
                        self.config.ordered_comment_creator[1],
                        i,
                        || Value::known(F::from(creator_id)),
                    )?;

                    if i < ordered_comment_creators.len() - 1 {
                        self.config
                            .q_ordered_comment_creator_sort
                            .enable(&mut region, i)?;

                        ordered_comment_creator_person_id_sort_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(creator_id)],
                                &[F::from(ordered_comment_creators[i + 1].1)],
                            )
                            .unwrap();
                    }

                    let mut lower_bound = 0u64;
                    let mut upper_bound = MAX_PERSON_ID;

                    for j in 0..friendsid_ext_values.len() - 1 {
                        if friendsid_ext_values[j] <= creator_id
                            && creator_id < friendsid_ext_values[j + 1]
                        {
                            lower_bound = friendsid_ext_values[j];
                            upper_bound = friendsid_ext_values[j + 1];
                            break;
                        }
                    }

                    region.assign_advice(
                        || format!("aligned_comment_creator_friend_id at {}", i),
                        self.config.aligned_comment_creator_friend_id,
                        i,
                        || Value::known(F::from(lower_bound)),
                    )?;

                    region.assign_advice(
                        || format!("next_aligned_comment_creator_friend_id at {}", i),
                        self.config.next_aligned_comment_creator_friend_id,
                        i,
                        || Value::known(F::from(upper_bound)),
                    )?;

                    align_comment_friend_id_le_person_id_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(lower_bound)],
                            &[F::from(creator_id)],
                        )
                        .unwrap();

                    person_id_lt_next_aligned_comment_friend_id_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(creator_id)],
                            &[F::from(upper_bound - 1)],
                        )
                        .unwrap();

                    let diff = F::from(lower_bound) - F::from(creator_id);
                    chip_comment_creator_match
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();

                    let match_flag = lower_bound == creator_id;

                    region.assign_advice(
                        || "comment_creator_match_flag",
                        self.config.comment_creator_match_flag,
                        i,
                        || Value::known(F::from(match_flag as u64)),
                    )?;
                }

                let mut ordered_post_creators: Vec<(u64, u64)> = Vec::new();
                for row in &post_hasCreator_person {
                    ordered_post_creators.push((row[0], row[1]));
                }
                ordered_post_creators.sort_by(|a, b| a.1.cmp(&b.1));

                for (i, &(message_id, creator_id)) in ordered_post_creators.iter().enumerate() {
                    self.config.q_post_has_creator.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("post_hasCreator_person[0] at {}", i),
                        self.config.post_hasCreator_person[0],
                        i,
                        || Value::known(F::from(message_id)),
                    )?;

                    region.assign_advice(
                        || format!("post_hasCreator_person[1] at {}", i),
                        self.config.post_hasCreator_person[1],
                        i,
                        || Value::known(F::from(creator_id)),
                    )?;

                    region.assign_advice(
                        || format!("ordered_post_creator[0] at {}", i),
                        self.config.ordered_post_creator[0],
                        i,
                        || Value::known(F::from(message_id)),
                    )?;

                    region.assign_advice(
                        || format!("ordered_post_creator[1] at {}", i),
                        self.config.ordered_post_creator[1],
                        i,
                        || Value::known(F::from(creator_id)),
                    )?;

                    if i < ordered_post_creators.len() - 1 {
                        self.config
                            .q_ordered_post_creator_sort
                            .enable(&mut region, i)?;

                        ordered_post_creator_person_id_sort_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(creator_id)],
                                &[F::from(ordered_post_creators[i + 1].1)],
                            )
                            .unwrap();
                    }

                    let mut lower_bound = 0u64;
                    let mut upper_bound = MAX_PERSON_ID;

                    for j in 0..friendsid_ext_values.len() - 1 {
                        if friendsid_ext_values[j] <= creator_id
                            && creator_id < friendsid_ext_values[j + 1]
                        {
                            lower_bound = friendsid_ext_values[j];
                            upper_bound = friendsid_ext_values[j + 1];
                            break;
                        }
                    }

                    region.assign_advice(
                        || format!("aligned_post_creator_friend_id at {}", i),
                        self.config.aligned_post_creator_friend_id,
                        i,
                        || Value::known(F::from(lower_bound)),
                    )?;

                    region.assign_advice(
                        || format!("next_aligned_post_creator_friend_id at {}", i),
                        self.config.next_aligned_post_creator_friend_id,
                        i,
                        || Value::known(F::from(upper_bound)),
                    )?;

                    align_post_friend_id_le_person_id_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(lower_bound)],
                            &[F::from(creator_id)],
                        )
                        .unwrap();

                    person_id_lt_next_aligned_post_friend_id_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(creator_id)],
                            &[F::from(upper_bound - 1)],
                        )
                        .unwrap();

                    let diff = F::from(lower_bound) - F::from(creator_id);
                    chip_post_creator_match
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();

                    let match_flag = lower_bound == creator_id;

                    region.assign_advice(
                        || "post_creator_match_flag",
                        self.config.post_creator_match_flag,
                        i,
                        || Value::known(F::from(match_flag as u64)),
                    )?;
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
            friends_ids_val: vec![933,1786706421429,1649267467990,1924145374989,2061584328475,1374389534797,687194767478,1236950581381,824633720942],
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
