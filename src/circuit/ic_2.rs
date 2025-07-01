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
    WHERE message.creationDate <= $maxDate
    RETURN
        friend.id AS personId,
        friend.firstName AS personFirstName,
        friend.lastName AS personLastName,
        message.id AS postOrCommentId,
        coalesce(message.content,message.imageFile) AS postOrCommentContent,
        message.creationDate AS postOrCommentCreationDate
    ORDER BY
        postOrCommentCreationDate DESC,
        toInteger(postOrCommentId) ASC
    LIMIT 20
*/

#[derive(Clone, Debug)]
pub struct ic2CircuitConfig<F: Field + Ord + std::hash::Hash> {
    person: Vec<Column<Advice>>,
    q_person: Selector,
    person_id: Column<Advice>,

    person_relation_check_bits: Column<Advice>,

    person_knows_person: Vec<Column<Advice>>,
    q_pkp: Selector,
    q_picked_pkp: Selector,
    person_relation_zero: crate::chips::is_zero::IsZeroConfig<F>,

    pkp_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    pkp_min_id: Column<Advice>,
    pkp_max_id: Column<Advice>,

    friendsid: Column<Advice>,
    friends_min: Column<Advice>,
    friends_max: Column<Advice>,
    q_friends: Selector,
    friends_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>,

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
    q_picked_comment: Selector,

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
    q_picked_post: Selector,

    // messageId | messageimagefile(F::ZERO for comment)  | messagecreationdate | messagecontent
    comment: Vec<Column<Advice>>,
    post: Vec<Column<Advice>>,
    q_comment: Selector,
    q_post: Selector,

    // messageId | messagecreationdate | messagetype(F::ZERO for comment ,F::ONE for post)
    candidate: Vec<Column<Advice>>,
    q_candidate: Selector,
    q_candidate_comment: Selector,
    q_candidate_post: Selector,
    q_candidate_top20: Selector,
    q_candidate_remain: Selector,

    max_date: Column<Advice>,
    message_date_config: LtEqGenericConfig<F, NUM_BYTES>,
    message_processed: Column<Advice>,

    // friend_id | firstname | lastname | messageId | messageimagefile(F::ZERO for comment)  | messagecreationdate | messagecontent | messagetype
    top20: Vec<Column<Advice>>,
    q_top20: Selector,
    q_top20_comment: Selector,
    q_top20_post: Selector,
    q_top20_order: Selector,
    top20_date_check_bits: Column<Advice>,

    // messageId | messagecreationdate
    last_top20_message: Vec<Column<Advice>>,
    last_vs_top_date_check_bits: Column<Advice>,

    top20_date_zero: crate::chips::is_zero::IsZeroConfig<F>,
    top20_creationdate_config: LtEqGenericConfig<F, NUM_BYTES>,
    top20_id_config: LtEqGenericConfig<F, NUM_BYTES>,

    last_vs_top_date_zero: crate::chips::is_zero::IsZeroConfig<F>,
    last_vs_top_date: LtEqGenericConfig<F, NUM_BYTES>,
    last_vs_top_id: LtEqGenericConfig<F, NUM_BYTES>,

    last_vs_remain_date_check_bits: Column<Advice>,
    last_vs_remain_date_zero: crate::chips::is_zero::IsZeroConfig<F>,
    last_vs_remain_date: LtEqGenericConfig<F, NUM_BYTES>,
    last_vs_remain_id: LtEqGenericConfig<F, NUM_BYTES>,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct ic2Chip<F: Field + Ord + std::hash::Hash> {
    config: ic2CircuitConfig<F>,
}

impl<F: Field + Ord + std::hash::Hash> ic2Chip<F> {
    pub fn construct(config: ic2CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> ic2CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_pkp = meta.selector();

        // personid | firstname | lastname |
        let mut person = Vec::new();
        for _ in 0..3 {
            person.push(meta.advice_column());
        }

        let q_person = meta.complex_selector();

        let mut person_knows_person = Vec::new();
        for _ in 0..3 {
            person_knows_person.push(meta.advice_column());
        }

        let mut comment = Vec::new();
        let mut post = Vec::new();
        for _ in 0..4 {
            comment.push(meta.advice_column());
            post.push(meta.advice_column());
        }

        let pkp_min_id = meta.advice_column();
        let pkp_max_id = meta.advice_column();

        let person_id = meta.advice_column();
        let person_relation_check_bits = meta.advice_column();

        let iz1 = meta.advice_column();
        let person_relation_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                let min_id_expr = meta.query_advice(pkp_min_id, Rotation::cur());
                let max_id_expr = meta.query_advice(pkp_max_id, Rotation::cur());
                let person_id_expr = meta.query_advice(person_id, Rotation::cur());

                let diff_min = min_id_expr.clone() - person_id_expr.clone();
                let diff_max = max_id_expr.clone() - person_id_expr.clone();

                diff_min * diff_max
            },
            iz1,
            person_relation_check_bits,
        );
        let pkp_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(pkp_max_id, Rotation::cur())], // M = max(pkp[0],pkp[1])
            |meta| vec![meta.query_advice(pkp_min_id, Rotation::cur())], // m = min(pkp[0],pkp[1])
        );

        // normalization constraint
        meta.create_gate("normalize_pkp_relationship", |meta| {
            let q = meta.query_selector(q_pkp);

            let id1 = meta.query_advice(person_knows_person[0], Rotation::cur());
            let id2 = meta.query_advice(person_knows_person[1], Rotation::cur());

            let m = meta.query_advice(pkp_min_id, Rotation::cur());
            let M = meta.query_advice(pkp_max_id, Rotation::cur());

            // 1. m ≤ M
            // 2. m + M = id1 + id2
            // 3. m * M = id1 * id2
            let sum_constraint = (m.clone() + M.clone()) - (id1.clone() + id2.clone());
            let product_constraint = (m * M) - (id1 * id2);
            let order_check = pkp_norm_order_config.is_lt(meta, None);

            vec![
                q.clone() * sum_constraint,
                q.clone() * product_constraint,
                q * order_check,
            ]
        });

        let friendsid = meta.advice_column();
        let friends_min = meta.advice_column();
        let friends_max = meta.advice_column();
        let q_friends = meta.complex_selector();

        let friends_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_friends),
            |meta| vec![meta.query_advice(friends_max, Rotation::cur())], // M = max(P,C)
            |meta| vec![meta.query_advice(friends_min, Rotation::cur())], // m = min(P,C)
        );

        meta.create_gate("normalize_friends_relationship", |meta| {
            let q = meta.query_selector(q_friends);

            let id1 = meta.query_advice(person_id, Rotation::cur());
            let id2 = meta.query_advice(friendsid, Rotation::cur());

            let m = meta.query_advice(friends_min, Rotation::cur());
            let M = meta.query_advice(friends_max, Rotation::cur());

            let sum_constraint = (m.clone() + M.clone()) - (id1.clone() + id2.clone());
            let product_constraint = (m * M) - (id1 * id2);
            let order_check = friends_norm_order_config.is_lt(meta, None);

            vec![
                q.clone() * sum_constraint,
                q.clone() * product_constraint,
                q * order_check,
            ]
        });

        let one = Expression::Constant(F::ONE);
        let mut q_picked_pkp = meta.complex_selector();
        meta.shuffle(format!("friends id norm"), |meta| {
            let q1 = meta.query_selector(q_friends);
            let q2 = meta.query_selector(q_picked_pkp);
            let a = meta.query_advice(friends_min, Rotation::cur());
            let b = meta.query_advice(friends_max, Rotation::cur());
            let d = meta.query_advice(pkp_min_id, Rotation::cur());
            let e = meta.query_advice(pkp_max_id, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), d, e].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

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

        // Shuffle from `friendsid` (unique friend IDs) to `friendsid_ext` (internal part)
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

        let q_picked_comment = meta.complex_selector();
        meta.create_gate("picked comment", |meta| {
            let q = meta.query_selector(q_comment_has_creator);
            let q_picked = meta.query_selector(q_picked_comment);
            let flag = meta.query_advice(comment_creator_match_flag, Rotation::cur());
            vec![q * (q_picked - flag)]
        });

        let mut candidate = Vec::new();
        for _ in 0..4 {
            candidate.push(meta.advice_column());
        }
        let q_candidate_comment = meta.complex_selector();
        meta.shuffle("shuffle created_comment", |meta| {
            let q1 = meta.query_selector(q_candidate_comment);
            let q2 = meta.query_selector(q_picked_comment);
            let a = meta.query_advice(candidate[0], Rotation::cur());
            let c = meta.query_advice(ordered_comment_creator[0], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), c].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_picked_post = meta.complex_selector();
        meta.create_gate("picked post", |meta| {
            let q = meta.query_selector(q_post_has_creator);
            let q_picked = meta.query_selector(q_picked_post);
            let flag = meta.query_advice(post_creator_match_flag, Rotation::cur());
            vec![q * (q_picked - flag)]
        });

        let q_candidate_post = meta.complex_selector();
        meta.shuffle("shuffle created_post", |meta| {
            let q1 = meta.query_selector(q_candidate_post);
            let q2 = meta.query_selector(q_picked_post);
            let a = meta.query_advice(candidate[0], Rotation::cur());
            let c = meta.query_advice(ordered_post_creator[0], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), c].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut comment = Vec::new();
        for _ in 0..4 {
            comment.push(meta.advice_column());
        }
        let q_comment = meta.complex_selector();

        meta.lookup_any("candidate from comment", |meta| {
            let q1 = meta.query_selector(q_candidate_comment);
            let q2 = meta.query_selector(q_comment);
            let a = meta.query_advice(candidate[0], Rotation::cur());
            let b = meta.query_advice(candidate[1], Rotation::cur());
            let c = meta.query_advice(comment[0], Rotation::cur());
            let d = meta.query_advice(comment[2], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let mut post = Vec::new();
        for _ in 0..4 {
            post.push(meta.advice_column());
        }
        let q_post = meta.complex_selector();
        meta.lookup_any("candidate from post", |meta| {
            let q1 = meta.query_selector(q_candidate_post);
            let q2 = meta.query_selector(q_post);
            let a = meta.query_advice(candidate[0], Rotation::cur());
            let b = meta.query_advice(candidate[1], Rotation::cur());
            let c = meta.query_advice(post[0], Rotation::cur());
            let d = meta.query_advice(post[2], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_candidate = meta.selector();

        meta.create_gate("verify candidate messagetype", |meta| {
            let q_c = meta.query_selector(q_candidate);
            let q1 = meta.query_selector(q_candidate_post);
            let q2 = meta.query_selector(q_candidate_comment);
            let messagetype = meta.query_advice(candidate[2], Rotation::cur());
            vec![
                q_c.clone() * (q1.clone() - messagetype.clone()),
                q_c * (q2.clone() + messagetype - one.clone()),
            ]
        });

        let mut top20 = Vec::new();
        for _ in 0..8 {
            top20.push(meta.advice_column());
        }
        let q_top20 = meta.complex_selector();
        meta.lookup_any(format!("top20 lookup person"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_person);
            let r1 = meta.query_advice(top20[0], Rotation::cur());
            let r2 = meta.query_advice(top20[1], Rotation::cur());
            let r3 = meta.query_advice(top20[2], Rotation::cur());
            let p1 = meta.query_advice(person[0], Rotation::cur());
            let p2 = meta.query_advice(person[1], Rotation::cur());
            let p3 = meta.query_advice(person[2], Rotation::cur());
            let lhs = [one.clone(), r1, r2, r3].map(|c| c * q1.clone());
            let rhs = [one.clone(), p1, p2, p3].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_top20_comment = meta.complex_selector();
        let q_top20_post = meta.complex_selector();

        meta.lookup_any(format!("top20 lookup comment"), |meta| {
            let q1 = meta.query_selector(q_top20_comment);
            let q2 = meta.query_selector(q_comment);
            let r1 = meta.query_advice(top20[3], Rotation::cur());
            let r2 = meta.query_advice(top20[4], Rotation::cur());
            let r3 = meta.query_advice(top20[5], Rotation::cur());
            let r4 = meta.query_advice(top20[6], Rotation::cur());
            let p1 = meta.query_advice(comment[0], Rotation::cur());
            let p2 = meta.query_advice(comment[1], Rotation::cur());
            let p3 = meta.query_advice(comment[2], Rotation::cur());
            let p4 = meta.query_advice(comment[3], Rotation::cur());
            let lhs = [one.clone(), r1, r2, r3, r4].map(|c| c * q1.clone());
            let rhs = [one.clone(), p1, p2, p3, p4].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any(format!("top20 lookup post"), |meta| {
            let q1 = meta.query_selector(q_top20_post);
            let q2 = meta.query_selector(q_post);
            let r1 = meta.query_advice(top20[3], Rotation::cur());
            let r2 = meta.query_advice(top20[4], Rotation::cur());
            let r3 = meta.query_advice(top20[5], Rotation::cur());
            let r4 = meta.query_advice(top20[6], Rotation::cur());
            let p1 = meta.query_advice(post[0], Rotation::cur());
            let p2 = meta.query_advice(post[1], Rotation::cur());
            let p3 = meta.query_advice(post[2], Rotation::cur());
            let p4 = meta.query_advice(post[3], Rotation::cur());
            let lhs = [one.clone(), r1, r2, r3, r4].map(|c| c * q1.clone());
            let rhs = [one.clone(), p1, p2, p3, p4].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("verify top20 messagetype", |meta| {
            let q_c = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_top20_comment);
            let q1 = meta.query_selector(q_top20_post);
            let messagetype = meta.query_advice(top20[7], Rotation::cur());
            vec![
                q_c.clone() * (q1.clone() - messagetype.clone()),
                q_c * (q2.clone() + messagetype - one.clone()),
            ]
        });

        let q_candidate_top20 = meta.complex_selector();
        let q_candidate_remain = meta.complex_selector();
        meta.shuffle(format!("top20 from candidate"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let q2 = meta.query_selector(q_candidate_top20);
            let r1 = meta.query_advice(top20[3], Rotation::cur());
            let p1 = meta.query_advice(candidate[0], Rotation::cur());
            let lhs = [one.clone(), r1].map(|c| c * q1.clone());
            let rhs = [one.clone(), p1].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("verify q_candidate_top20", |meta| {
            let q_c = meta.query_selector(q_candidate);
            let q2 = meta.query_selector(q_candidate_remain);
            let q1 = meta.query_selector(q_candidate_top20);
            vec![q_c * (q1.clone() + q2.clone() - one.clone())]
        });

        // order
        let q_top20_order = meta.selector();
        let top20_date_check_bits = meta.advice_column();
        let iz4 = meta.advice_column();

        let top20_date_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| {
                // Check if current date equals next date
                meta.query_advice(top20[5], Rotation::cur())
                    - meta.query_advice(top20[5], Rotation::next())
            },
            iz4,
            top20_date_check_bits,
        );

        let top20_creationdate_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| vec![meta.query_advice(top20[5], Rotation::next())],
            |meta| vec![meta.query_advice(top20[5], Rotation::cur())],
        );
        let top20_id_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20_order),
            |meta| vec![meta.query_advice(top20[3], Rotation::cur())],
            |meta| vec![meta.query_advice(top20[3], Rotation::next())],
        );
        meta.create_gate("verifies top20 order", |meta| {
            let q_sort = meta.query_selector(q_top20_order);
            let date_lt = top20_creationdate_config.is_lt(meta, None);
            let date_eq = meta.query_advice(top20_date_check_bits, Rotation::cur());
            let id_lt = top20_id_config.is_lt(meta, None);

            vec![
                q_sort.clone() * (one.clone() - date_lt.clone()),
                q_sort * date_eq * (one.clone() - id_lt),
            ]
        });

        let mut last_top20_message = Vec::new();
        for _ in 0..2 {
            last_top20_message.push(meta.advice_column());
        }
        meta.lookup_any(format!("last_vs_top20"), |meta| {
            let q1 = meta.query_selector(q_top20);
            let l1 = meta.query_advice(last_top20_message[0], Rotation::cur());
            let l2 = meta.query_advice(last_top20_message[1], Rotation::cur());
            let t1 = meta.query_advice(top20[3], Rotation::cur());
            let t2 = meta.query_advice(top20[5], Rotation::cur());
            let lhs = [one.clone(), l1, l2].map(|c| c * q1.clone());
            let rhs = [one.clone(), t1, t2].map(|c| c * q1.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let last_vs_top_date_check_bits = meta.advice_column();
        let iz5 = meta.advice_column();
        let last_vs_top_date_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_top20),
            |meta| {
                meta.query_advice(top20[5], Rotation::cur())
                    - meta.query_advice(last_top20_message[1], Rotation::cur())
            },
            iz5,
            last_vs_top_date_check_bits,
        );

        let last_vs_top_date = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20),
            |meta| vec![meta.query_advice(last_top20_message[1], Rotation::cur())],
            |meta| vec![meta.query_advice(top20[5], Rotation::cur())],
        );
        let last_vs_top_id = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_top20),
            |meta| vec![meta.query_advice(top20[3], Rotation::cur())],
            |meta| vec![meta.query_advice(last_top20_message[0], Rotation::cur())],
        );
        meta.create_gate("verifies last_vs_top20 order", |meta| {
            let q_sort = meta.query_selector(q_top20);
            let date_lt = last_vs_top_date.is_lt(meta, None);
            let date_eq = meta.query_advice(last_vs_top_date_check_bits, Rotation::cur());
            let id_lt = last_vs_top_id.is_lt(meta, None);

            vec![
                q_sort.clone() * (one.clone() - date_lt.clone()),
                q_sort * date_eq * (one.clone() - id_lt),
            ]
        });

        // last vs remain
        let last_vs_remain_date_check_bits = meta.advice_column();
        let iz6 = meta.advice_column();
        let last_vs_remain_date_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_remain),
            |meta| {
                meta.query_advice(candidate[1], Rotation::cur())
                    - meta.query_advice(last_top20_message[1], Rotation::cur())
            },
            iz6,
            last_vs_remain_date_check_bits,
        );
        let last_vs_remain_date = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_remain),
            |meta| vec![meta.query_advice(candidate[1], Rotation::cur())],
            |meta| vec![meta.query_advice(last_top20_message[1], Rotation::cur())],
        );
        let last_vs_remain_id = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate_remain),
            |meta| vec![meta.query_advice(last_top20_message[0], Rotation::cur())],
            |meta| vec![meta.query_advice(candidate[0], Rotation::cur())],
        );
        meta.create_gate("verifies last_vs_remain order", |meta| {
            let q_sort = meta.query_selector(q_candidate_remain);
            let date_lt = last_vs_remain_date.is_lt(meta, None);
            let date_eq = meta.query_advice(last_vs_remain_date_check_bits, Rotation::cur());
            let id_lt = last_vs_remain_id.is_lt(meta, None);

            vec![
                q_sort.clone() * (one.clone() - date_lt.clone()),
                q_sort * date_eq * (one.clone() - id_lt),
            ]
        });

        let max_date = meta.advice_column();

        let message_processed = meta.advice_column();

        let message_date_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_candidate),
            |meta| vec![meta.query_advice(candidate[1], Rotation::cur())],
            |meta| vec![meta.query_advice(max_date, Rotation::cur())],
        );

        meta.create_gate("date filter constraint", |meta| {
            let q = meta.query_selector(q_candidate);
            let is_lte = message_date_config.is_lt(meta, None);
            let processed = meta.query_advice(message_processed, Rotation::cur());

            let date_condition = is_lte.clone() - processed.clone();

            vec![q * date_condition]
        });

        meta.create_gate("message processing completeness", |meta| {
            let q = meta.query_selector(q_candidate);
            let processed = meta.query_advice(message_processed, Rotation::cur());
            let in_top20 = meta.query_selector(q_candidate_top20);
            let in_remain = meta.query_selector(q_candidate_remain);

            let completeness_check = processed.clone() - (in_top20.clone() + in_remain.clone());

            vec![q * completeness_check]
        });

        ic2CircuitConfig {
            q_person,
            person,
            person_id,
            person_knows_person,
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
            q_picked_comment,
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
            q_picked_post,
            comment,
            post,
            q_comment,
            q_post,
            candidate,
            q_candidate,
            q_candidate_comment,
            q_candidate_post,
            q_candidate_top20,
            q_candidate_remain,
            max_date,
            message_date_config,
            message_processed,
            top20,
            q_top20,
            q_top20_comment,
            q_top20_post,
            q_top20_order,
            top20_date_check_bits,
            last_top20_message,
            last_vs_top_date_check_bits,
            top20_date_zero,
            top20_creationdate_config,
            top20_id_config,
            last_vs_top_date_zero,
            last_vs_top_date,
            last_vs_top_id,
            last_vs_remain_date_check_bits,
            last_vs_remain_date_zero,
            last_vs_remain_date,
            last_vs_remain_id,
            person_relation_check_bits,
            q_pkp,
            q_picked_pkp,
            person_relation_zero,
            pkp_min_id,
            pkp_max_id,
            friends_min,
            friends_max,
            pkp_norm_order_config,
            friends_norm_order_config,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<u64>>,
        person_knows_person: Vec<Vec<u64>>,
        comment_hasCreator_person: Vec<Vec<u64>>,
        post_hasCreator_person: Vec<Vec<u64>>,
        comment_table: Vec<Vec<u64>>,
        post_table: Vec<Vec<u64>>,
        person_id_val: u64,
        max_date_val: u64,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip_person_eq = IsZeroChip::construct(self.config.person_relation_zero.clone());
        let chip_comment_creator_match =
            IsZeroChip::construct(self.config.comment_creator_match_config.clone());
        let chip_post_creator_match =
            IsZeroChip::construct(self.config.post_creator_match_config.clone());
        let chip_top20_date_zero = IsZeroChip::construct(self.config.top20_date_zero.clone());
        let chip_last_vs_top_date_zero =
            IsZeroChip::construct(self.config.last_vs_top_date_zero.clone());
        let chip_last_vs_remain_date_zero =
            IsZeroChip::construct(self.config.last_vs_remain_date_zero.clone());

        let friendsid_ext_order_chip =
            LtEqGenericChip::construct(self.config.friendsid_ext_order_config.clone());
        let pkp_norm_order_chip =
            LtEqGenericChip::construct(self.config.pkp_norm_order_config.clone());
        let friends_norm_order_chip =
            LtEqGenericChip::construct(self.config.friends_norm_order_config.clone());
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
        let message_date_chip = LtEqGenericChip::construct(self.config.message_date_config.clone());
        let top20_creationdate_chip =
            LtEqGenericChip::construct(self.config.top20_creationdate_config.clone());
        let top20_id_chip = LtEqGenericChip::construct(self.config.top20_id_config.clone());
        let last_vs_top_date_chip =
            LtEqGenericChip::construct(self.config.last_vs_top_date.clone());
        let last_vs_top_id_chip = LtEqGenericChip::construct(self.config.last_vs_top_id.clone());
        let last_vs_remain_date_chip =
            LtEqGenericChip::construct(self.config.last_vs_remain_date.clone());
        let last_vs_remain_id_chip =
            LtEqGenericChip::construct(self.config.last_vs_remain_id.clone());

        friendsid_ext_order_chip.load(layouter).unwrap();
        pkp_norm_order_chip.load(layouter).unwrap();
        friends_norm_order_chip.load(layouter).unwrap();
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
        message_date_chip.load(layouter).unwrap();
        top20_creationdate_chip.load(layouter).unwrap();
        top20_id_chip.load(layouter).unwrap();
        last_vs_top_date_chip.load(layouter).unwrap();
        last_vs_top_id_chip.load(layouter).unwrap();
        last_vs_remain_date_chip.load(layouter).unwrap();
        last_vs_remain_id_chip.load(layouter).unwrap();

        let mut friends_ids = Vec::new();
        for edge in &person_knows_person {
            if edge[0] == person_id_val {
                friends_ids.push(edge[1]);
            } else if edge[1] == person_id_val {
                friends_ids.push(edge[0]);
            }
        }
        friends_ids.sort();
        friends_ids.dedup();

        // created extended friends id table
        let mut friendsid_ext_values = vec![0u64];
        for &id in &friends_ids {
            friendsid_ext_values.push(id);
        }
        friendsid_ext_values.push(MAX_PERSON_ID);

        // create lookup table for friendsid_ext pairs
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

        for row in &comment_table {
            let message_id = row[0];
            let creation_date = row[2];

            if let Some(creators) = comment_creators.get(&message_id) {
                for &creator_id in creators {
                    // [messageId, messageCreationDate, messageType(0=comment), maxDateCheck]
                    candidate_messages.push(vec![message_id, creation_date, 0, creator_id]);
                }
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

        for row in &post_table {
            let message_id = row[0];
            let creation_date = row[2];

            if let Some(creators) = post_creators.get(&message_id) {
                for &creator_id in creators {
                    // [messageId, messageCreationDate, messageType(1=post), maxDateCheck]
                    candidate_messages.push(vec![message_id, creation_date, 1, creator_id]);
                }
            }
        }

        candidate_messages.sort_by(|a, b| {
            if a[1] != b[1] {
                b[1].cmp(&a[1])
            } else {
                a[0].cmp(&b[0])
            }
        });

        let mut top20_messages: Vec<Vec<u64>> = Vec::new();
        let mut last_top20_message: Vec<u64> = Vec::new();

        if !candidate_messages.is_empty() {
            for (i, msg) in candidate_messages.iter().enumerate() {
                if i < 20 && msg[1] <= max_date_val {
                    top20_messages.push(msg.clone());

                    if i == 19 {
                        last_top20_message = vec![msg[0], msg[1]];
                    }
                }
            }

            if top20_messages.len() < 20 && !top20_messages.is_empty() {
                let last = top20_messages.last().unwrap();
                last_top20_message = vec![last[0], last[1]];
            }
        }

        let mut message_processed: Vec<bool> = Vec::new();
        for msg in &candidate_messages {
            if msg[1] > max_date_val {
                message_processed.push(false);
            } else {
                message_processed.push(true);
            }
        }

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;

                    for j in 0..3 {
                        region.assign_advice(
                            || format!("person col {} row {}", j, i),
                            self.config.person[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }

                    region.assign_advice(
                        || "person_id",
                        self.config.person_id,
                        i,
                        || Value::known(F::from(person_id_val)),
                    )?;
                }

                for (i, edge) in person_knows_person.iter().enumerate() {
                    self.config.q_pkp.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("person_id_val_for_pkp_check at offset {}", i),
                        self.config.person_id,
                        i,
                        || Value::known(F::from(person_id_val)),
                    )?;

                    let id1 = edge[0];
                    let id2 = edge[1];

                    region.assign_advice(
                        || format!("person_knows_person[0] at {}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(F::from(id1)),
                    )?;

                    region.assign_advice(
                        || format!("person_knows_person[1] at {}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(F::from(id2)),
                    )?;

                    let min_id = min(id1, id2);
                    let max_id = max(id1, id2);

                    region.assign_advice(
                        || format!("pkp_min_id at {}", i),
                        self.config.pkp_min_id,
                        i,
                        || Value::known(F::from(min_id)),
                    )?;

                    region.assign_advice(
                        || format!("pkp_max_id at {}", i),
                        self.config.pkp_max_id,
                        i,
                        || Value::known(F::from(max_id)),
                    )?;

                    let diff_min = F::from(min_id) - F::from(person_id_val);
                    let diff_max = F::from(max_id) - F::from(person_id_val);

                    let product = diff_min * diff_max;
                    chip_person_eq
                        .assign(&mut region, i, Value::known(product))
                        .unwrap();

                    if product == F::ZERO {
                        region.assign_advice(
                            || format!("person_relation_check_bits at {}", i),
                            self.config.person_relation_check_bits,
                            i,
                            || Value::known(F::from(1u64)),
                        )?;
                    } else {
                        region.assign_advice(
                            || format!("person_relation_check_bits at {}", i),
                            self.config.person_relation_check_bits,
                            i,
                            || Value::known(F::from(0u64)),
                        )?;
                    }

                    if id1 == person_id_val || id2 == person_id_val {
                        self.config.q_picked_pkp.enable(&mut region, i)?;
                    }

                    pkp_norm_order_chip
                        .assign(&mut region, i, &[F::from(max_id)], &[F::from(min_id)])
                        .unwrap();
                }

                for (i, &friend_id) in friends_ids.iter().enumerate() {
                    self.config.q_friends.enable(&mut region, i)?;

                    region.assign_advice(
                        || format!("friendsid at {}", i),
                        self.config.friendsid,
                        i,
                        || Value::known(F::from(friend_id)),
                    )?;

                    let min_id = min(person_id_val, friend_id);
                    let max_id = max(person_id_val, friend_id);

                    region.assign_advice(
                        || format!("friends_min at {}", i),
                        self.config.friends_min,
                        i,
                        || Value::known(F::from(min_id)),
                    )?;

                    region.assign_advice(
                        || format!("friends_max at {}", i),
                        self.config.friends_max,
                        i,
                        || Value::known(F::from(max_id)),
                    )?;

                    friends_norm_order_chip
                        .assign(&mut region, i, &[F::from(max_id)], &[F::from(min_id)])
                        .unwrap();
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

                    if match_flag {
                        self.config.q_picked_comment.enable(&mut region, i)?;
                    }
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

                    if match_flag {
                        self.config.q_picked_post.enable(&mut region, i)?;
                    }
                }

                for (i, row) in comment_table.iter().enumerate() {
                    self.config.q_comment.enable(&mut region, i)?;

                    // [messageId, messageImageFile(0 for comment), messageCreationDate, messageContent]
                    for j in 0..4 {
                        let value = if j == 1 {
                            0u64
                        } else if j >= row.len() {
                            0u64
                        } else {
                            row[j]
                        };

                        region.assign_advice(
                            || format!("comment col {} row {}", j, i),
                            self.config.comment[j],
                            i,
                            || Value::known(F::from(value)),
                        )?;
                    }
                }

                for (i, row) in post_table.iter().enumerate() {
                    self.config.q_post.enable(&mut region, i)?;

                    // [messageId, messageImageFile, messageCreationDate, messageContent]
                    for j in 0..4 {
                        let value = if j >= row.len() {
                            0u64
                        } else {
                            row[j]
                        };

                        region.assign_advice(
                            || format!("post col {} row {}", j, i),
                            self.config.post[j],
                            i,
                            || Value::known(F::from(value)),
                        )?;
                    }
                }

                for (i, row) in candidate_messages.iter().enumerate() {
                    self.config.q_candidate.enable(&mut region, i)?;

                    // [messageId, messageCreationDate, messageType]
                    for j in 0..3 {
                        region.assign_advice(
                            || format!("candidate col {} row {}", j, i),
                            self.config.candidate[j],
                            i,
                            || Value::known(F::from(row[j])),
                        )?;
                    }

                    region.assign_advice(
                        || "max_date",
                        self.config.max_date,
                        i,
                        || Value::known(F::from(max_date_val)),
                    )?;

                    region.assign_advice(
                        || "message_processed",
                        self.config.message_processed,
                        i,
                        || Value::known(F::from(message_processed[i] as u64)),
                    )?;

                    message_date_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[1])],       // messageCreationDate
                            &[F::from(max_date_val)], // maxDate
                        )
                        .unwrap();

                    if row[2] == 0 {
                        self.config.q_candidate_comment.enable(&mut region, i)?;
                    } else {
                        self.config.q_candidate_post.enable(&mut region, i)?;
                    }

                    let in_top20 = i < 20 && row[1] <= max_date_val;
                    if in_top20 {
                        self.config.q_candidate_top20.enable(&mut region, i)?;
                    } else if row[1] <= max_date_val {
                        self.config.q_candidate_remain.enable(&mut region, i)?;
                    }
                }

                for (i, row) in top20_messages.iter().enumerate() {
                    self.config.q_top20.enable(&mut region, i)?;

                    let message_id = row[0];
                    let message_type = row[2];
                    let creator_id = row[3];

                    let mut person_info = Vec::new();
                    for p in &person_table {
                        if p[0] == creator_id {
                            person_info = p.clone();
                            break;
                        }
                    }

                    // [person_id, firstName, lastName, messageId, messageImageFile, messageCreationDate, messageContent, messageType]
                    region.assign_advice(
                        || format!("top20[0] (person_id) at {}", i),
                        self.config.top20[0],
                        i,
                        || Value::known(F::from(person_info[0])),
                    )?;

                    region.assign_advice(
                        || format!("top20[1] (firstName) at {}", i),
                        self.config.top20[1],
                        i,
                        || Value::known(F::from(person_info[1])),
                    )?;

                    region.assign_advice(
                        || format!("top20[2] (lastName) at {}", i),
                        self.config.top20[2],
                        i,
                        || Value::known(F::from(person_info[2])),
                    )?;

                    // message
                    region.assign_advice(
                        || format!("top20[3] (messageId) at {}", i),
                        self.config.top20[3],
                        i,
                        || Value::known(F::from(message_id)),
                    )?;

                    // messageContent and messageImageFile
                    let content_val;
                    let image_val;

                    if message_type == 0 {
                        self.config.q_top20_comment.enable(&mut region, i)?;

                        let mut comment_row = Vec::new();
                        for c in &comment_table {
                            if c[0] == message_id {
                                comment_row = c.clone();
                                break;
                            }
                        }

                        content_val = if comment_row.len() > 3 {
                            comment_row[3]
                        } else {
                            0
                        };
                        image_val = 0;
                    } else {
                        self.config.q_top20_post.enable(&mut region, i)?;

                        let mut post_row = Vec::new();
                        for p in &post_table {
                            if p[0] == message_id {
                                post_row = p.clone();
                                break;
                            }
                        }

                        content_val = if post_row.len() > 3 { post_row[3] } else { 0 };
                        image_val = if post_row.len() > 1 { post_row[1] } else { 0 };
                    }

                    region.assign_advice(
                        || format!("top20[4] (imageFile) at {}", i),
                        self.config.top20[4],
                        i,
                        || Value::known(F::from(image_val)),
                    )?;

                    region.assign_advice(
                        || format!("top20[5] (creationDate) at {}", i),
                        self.config.top20[5],
                        i,
                        || Value::known(F::from(row[1])),
                    )?;

                    region.assign_advice(
                        || format!("top20[6] (content) at {}", i),
                        self.config.top20[6],
                        i,
                        || Value::known(F::from(content_val)),
                    )?;

                    region.assign_advice(
                        || format!("top20[7] (messageType) at {}", i),
                        self.config.top20[7],
                        i,
                        || Value::known(F::from(message_type)),
                    )?;

                    if i < top20_messages.len() - 1 {
                        self.config.q_top20_order.enable(&mut region, i)?;

                        let date_diff = F::from(row[1]) - F::from(top20_messages[i + 1][1]);
                        chip_top20_date_zero
                            .assign(&mut region, i, Value::known(date_diff))
                            .unwrap();

                        let date_eq = row[1] == top20_messages[i + 1][1];
                        region.assign_advice(
                            || "top20_date_check_bits",
                            self.config.top20_date_check_bits,
                            i,
                            || Value::known(F::from(date_eq as u64)),
                        )?;

                        top20_creationdate_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(top20_messages[i + 1][1])], // next date
                                &[F::from(row[1])],                   // current date
                            )
                            .unwrap();

                        top20_id_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[0])],                   // current id
                                &[F::from(top20_messages[i + 1][0])], // next id
                            )
                            .unwrap();
                    }

                    region.assign_advice(
                        || format!("last_top20_message[0] (id) at {}", i),
                        self.config.last_top20_message[0],
                        i,
                        || Value::known(F::from(last_top20_message[0])),
                    )?;

                    region.assign_advice(
                        || format!("last_top20_message[1] (date) at {}", i),
                        self.config.last_top20_message[1],
                        i,
                        || Value::known(F::from(last_top20_message[1])),
                    )?;

                    let last_vs_top_date_diff = F::from(row[1]) - F::from(last_top20_message[1]);
                    chip_last_vs_top_date_zero
                        .assign(&mut region, i, Value::known(last_vs_top_date_diff))
                        .unwrap();

                    let last_vs_top_date_eq = row[1] == last_top20_message[1];
                    region.assign_advice(
                        || "last_vs_top_date_check_bits",
                        self.config.last_vs_top_date_check_bits,
                        i,
                        || Value::known(F::from(last_vs_top_date_eq as u64)),
                    )?;

                    last_vs_top_date_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(last_top20_message[1])], // last date
                            &[F::from(row[1])],                // current date
                        )
                        .unwrap();

                    last_vs_top_id_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(row[0])],                // current id
                            &[F::from(last_top20_message[0])], // last id
                        )
                        .unwrap();
                }

                for (i, row) in candidate_messages.iter().enumerate() {
                    if row[1] <= max_date_val && i >= 20 {

                        let last_vs_remain_date_diff =
                            F::from(row[1]) - F::from(last_top20_message[1]);
                        chip_last_vs_remain_date_zero
                            .assign(&mut region, i, Value::known(last_vs_remain_date_diff))
                            .unwrap();

                        let last_vs_remain_date_eq = row[1] == last_top20_message[1];
                        region.assign_advice(
                            || "last_vs_remain_date_check_bits",
                            self.config.last_vs_remain_date_check_bits,
                            i,
                            || Value::known(F::from(last_vs_remain_date_eq as u64)),
                        )?;
                        region.assign_advice(
                            || format!("last_top20_message[0] (id) at {}", i),
                            self.config.last_top20_message[0],
                            i,
                            || Value::known(F::from(last_top20_message[0])),
                        )?;

                        region.assign_advice(
                            || format!("last_top20_message[1] (date) at {}", i),
                            self.config.last_top20_message[1],
                            i,
                            || Value::known(F::from(last_top20_message[1])),
                        )?;

                        last_vs_remain_date_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(row[1])],                // current date
                                &[F::from(last_top20_message[1])], // last date
                            )
                            .unwrap();

                        last_vs_remain_id_chip
                            .assign(
                                &mut region,
                                i,
                                &[F::from(last_top20_message[0])], // last id
                                &[F::from(row[0])],                // current id
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

pub struct MyCircuit<F: Field + Ord + std::hash::Hash> {
    pub person_table: Vec<Vec<u64>>,
    pub person_knows_person: Vec<Vec<u64>>,
    pub comment_hasCreator_person: Vec<Vec<u64>>,
    pub post_hasCreator_person: Vec<Vec<u64>>,
    pub comment_table: Vec<Vec<u64>>,
    pub post_table: Vec<Vec<u64>>,
    pub person_id_val: u64,
    pub max_date_val: u64,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord + std::hash::Hash> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person_table: Vec::new(),
            person_knows_person: Default::default(),
            comment_hasCreator_person: Vec::new(),
            post_hasCreator_person: Vec::new(),
            comment_table: Vec::new(),
            post_table: Vec::new(),
            person_id_val: 0,
            max_date_val: 0,
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord + std::hash::Hash> Circuit<F> for MyCircuit<F> {
    type Config = ic2CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ic2Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip = ic2Chip::construct(config.clone());

        chip.assign(
            &mut layouter.namespace(|| "Assign"),
            self.person_table.clone(),
            self.person_knows_person.clone(),
            self.comment_hasCreator_person.clone(),
            self.post_hasCreator_person.clone(),
            self.comment_table.clone(),
            self.post_table.clone(),
            self.person_id_val,
            self.max_date_val,
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
    fn test_ic2_circuit() {
        let k = 16;

        let post_relation = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/post_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read post data");
        let post_data = read_csv("/home/wh/zkgraph/src/data/message_fact/60k/post.csv", '|')
            .expect("Failed to read post data");

        let comment_relation = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/comment_hasCreator_person.csv",
            '|',
        )
        .expect("Failed to read comment data");
        let comment_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/comment.csv",
            '|',
        )
        .expect("Failed to read comment data");

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read person data");
        let person_relation = read_csv(
            "/home/wh/zkgraph/src/data/message_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("Failed to read comment data");

        let mut person: Vec<Vec<u64>> = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
                string_to_u64(&row[2]),
                if row[3] == "male" { 1 } else { 0 },
                parse_date(&row[4]),
                parse_datetime(&row[5]),
                ipv4_to_u64(&row[6]),
                string_to_u64(&row[7]),
            ];
            person.push(person_row);
        }
        println!("person.len:{:?}", person.len());

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

        let mut comment: Vec<Vec<u64>> = Vec::new();
        for (_, row) in comment_data.iter().enumerate() {
            let comment_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                0,
                parse_datetime(&row[1]),
                string_to_u64(&row[4]),
            ];
            comment.push(comment_row);
        }
        println!("comment.len:{:?}", comment.len());

        let mut post: Vec<Vec<u64>> = Vec::new();
        for (_, row) in post_data.iter().enumerate() {
            let post_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                string_to_u64(&row[1]),
                parse_datetime(&row[2]),
                string_to_u64(&row[6]),
            ];
            post.push(post_row);
        }
        println!("post.len:{:?}", post.len());

        let mut person_knows_person = Vec::new();
        for (_, row) in person_relation.iter().enumerate() {
            let r_row = vec![
                row[0].parse::<u64>().expect("invalid Person ID"),
                row[1].parse::<u64>().expect("invalid Person ID"),
            ];
            person_knows_person.push(r_row);
        }

        let person_id = 19791209301454;
        let circuit = MyCircuit::<Fr> {
            person_table: person.clone(),
            comment_table: comment.clone(),
            post_table: post.clone(),
            person_knows_person: person_knows_person,
            comment_hasCreator_person,
            post_hasCreator_person,
            person_id_val: person_id,
            max_date_val: 1354060800000,
            _marker: PhantomData,
        };

        let public_input = vec![Fr::from(1)];
        let start = Instant::now();
        let prover = MockProver::run(k, &circuit, vec![public_input]).expect("MockProver fail");
        println!("Proving time: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("success fail {:?}", e);
            }
        }
    }
}
