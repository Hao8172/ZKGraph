use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::data::csr::CsrValue;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_BYTES: usize = 6;
const MAX_PERSON_ID: u64 = 100000000000000;

/*
MATCH path = shortestPath((p)-[:KNOWS*1..2]->(friend))
*/

#[derive(Clone, Debug)]
pub struct Is1CircuitConfig<F: Field + Ord + std::hash::Hash> {
    q_person: Selector,

    person: Vec<Column<Advice>>,
    person_id: Column<Advice>,
    source_check: Column<Advice>,
    person_zero: crate::chips::is_zero::IsZeroConfig<F>,

    person_knows_person: Vec<Column<Advice>>,
    q_pkp: Selector,

    ordered_pkp: Vec<Column<Advice>>,
    q_ordered_pkp_sort: Selector,
    ordered_pkp_person_id_sort_config: LtEqGenericConfig<F, NUM_BYTES>,

    aligned_h1_pkp_personid: Column<Advice>,
    next_aligned_h1_pkp_personid: Column<Advice>,
    aligned_h1_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h1_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h1_match_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h1_match_flag: Column<Advice>,

    aligned_h1_pkp_to_personid: Column<Advice>,
    next_aligned_h1_pkp_to_personid: Column<Advice>,
    aligned_h1_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h1_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h1_pkp_to_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h1_pkp_to_flag: Column<Advice>,

    potential_friend_hop1: Column<Advice>,
    potential_friend_hop2: Column<Advice>,
    dist0_node: Column<Advice>,
    dist1_node: Column<Advice>,
    q_dist1_node: Selector,
    dist2_node: Column<Advice>,
    q_dist2_node: Selector,

    source_pkp_zero: crate::chips::is_zero::IsZeroConfig<F>,
    dist1_pkp_check: Column<Advice>,

    source_pkp_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    source_pkp_to_check: Column<Advice>,

    q_hop1_to: Selector,
    distinct_hop1_to: Column<Advice>,
    q_distinct_hop1_to: Selector,
    q_distinct_hop1_to_order: Selector,
    distinct_hop1_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop1_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop1_to_check: Column<Advice>,

    distinct_hop1_to_ext: Column<Advice>,
    q_distinct_hop1_to_ext: Selector,
    q_distinct_hop1_to_ext_order: Selector,
    distinct_hop1_to_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_distinct_hop1_to_ext_internal: Selector,
    q_distinct_hop1_to_ext_boundary: Selector,
    distinct_hop1_to_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_distinct_hop1_to_ext_pairs_lookup: Selector,

    q_hop2_to: Selector,
    distinct_hop2_to: Column<Advice>,
    q_distinct_hop2_to: Selector,
    q_distinct_hop2_to_order: Selector,
    distinct_hop2_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop2_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop2_to_check: Column<Advice>,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is1Chip<F: Field + Ord + std::hash::Hash> {
    config: Is1CircuitConfig<F>,
}

impl<F: Field + Ord + std::hash::Hash> Is1Chip<F> {
    pub fn construct(config: Is1CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Is1CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let mut person = Vec::new();
        for _ in 0..8 {
            person.push(meta.advice_column());
        }

        let person_id = meta.advice_column();
        let source_check = meta.advice_column();
        meta.enable_equality(source_check);

        let q_person = meta.selector();

        // verify if person[0] = person_id
        let iz_person_advice = meta.advice_column();
        let person_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_person),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(person[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz_person_advice,
            source_check,
        );

        let mut person_knows_person = Vec::new();
        for _ in 0..2 {
            person_knows_person.push(meta.advice_column());
        }
        let q_pkp = meta.complex_selector();
        let mut ordered_pkp = Vec::new();
        for _ in 0..2 {
            ordered_pkp.push(meta.advice_column());
        }
        let one = Expression::Constant(F::ONE);
        meta.shuffle("shuffle person_knows_person to ordered_pkp", |meta| {
            let q = meta.query_selector(q_pkp);
            let a = meta.query_advice(person_knows_person[0], Rotation::cur());
            let b = meta.query_advice(person_knows_person[1], Rotation::cur());
            let c = meta.query_advice(ordered_pkp[0], Rotation::cur());
            let d = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_pkp_sort = meta.complex_selector();
        let ordered_pkp_person_id_sort_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_pkp_sort),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())], // cur.PersonId
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::next())], // next.PersonId
        );
        meta.create_gate("verify ordered_comment", |meta| {
            let q = meta.query_selector(q_ordered_pkp_sort);
            vec![
                q.clone()
                    * (ordered_pkp_person_id_sort_config.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let mut dist0_node = meta.advice_column();

        // hop 0
        meta.create_gate("init_h0_states", |meta| {
            let q = meta.query_selector(q_person);

            let source_check = meta.query_advice(source_check, Rotation::cur());

            let current_node = meta.query_advice(dist0_node, Rotation::cur());

            vec![q.clone() * (current_node - source_check.clone())]
        });

        // ---------------------------
        // hop 1
        let iz_source_pkp_zero = meta.advice_column();
        let dist1_pkp_check = meta.advice_column();
        let source_pkp_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(ordered_pkp[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz_source_pkp_zero,
            dist1_pkp_check,
        );

        let iz_source_pkp_to_zero = meta.advice_column();
        let source_pkp_to_check = meta.advice_column();
        let source_pkp_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(ordered_pkp[1], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz_source_pkp_to_zero,
            source_pkp_to_check,
        );

        let q_hop1_to = meta.complex_selector();
        meta.create_gate("set_q_hop1_to_selector", |meta| {
            let q = meta.query_selector(q_pkp);

            let q1 = meta.query_selector(q_hop1_to);
            let check = meta.query_advice(dist1_pkp_check, Rotation::cur());
            vec![q.clone() * (q1 - check)]
        });

        let distinct_hop1_to = meta.advice_column();
        let q_distinct_hop1_to = meta.complex_selector();
        let q_distinct_hop1_to_order = meta.selector();

        meta.lookup_any("distinct_hop1_to1", |meta| {
            let q1 = meta.query_selector(q_distinct_hop1_to);
            let q2 = meta.query_selector(q_hop1_to);
            let a = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), b].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any("distinct_hop1_to2", |meta| {
            let q1 = meta.query_selector(q_distinct_hop1_to);
            let q2 = meta.query_selector(q_hop1_to);
            let a = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), b].map(|c| c * q2.clone());
            let rhs = [one.clone(), a].map(|c| c * q1.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let distinct_hop1_to_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_order),
            |meta| vec![meta.query_advice(distinct_hop1_to, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop1_to, Rotation::next())],
        );

        let iz_distinct_hop1_to_zero = meta.advice_column();
        let distinct_hop1_to_check = meta.advice_column();
        let distinct_hop1_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(distinct_hop1_to, Rotation::cur())
                    - meta.query_advice(distinct_hop1_to, Rotation::next())
            },
            iz_distinct_hop1_to_zero,
            distinct_hop1_to_check,
        );

        meta.create_gate("distinct_hop1_to_order", |meta| {
            let q = meta.query_selector(q_distinct_hop1_to_order);
            let check = meta.query_advice(distinct_hop1_to_check, Rotation::cur());
            vec![q.clone() * check]
        });

        let potential_friend_hop1 = meta.advice_column();
        let dist1_node = meta.advice_column();
        let q_dist1_node = meta.complex_selector();

        meta.create_gate("init_h1_states", |meta| {
            let q = meta.query_selector(q_person);
            let potential_friend = meta.query_advice(dist1_node, Rotation::cur());
            let q1 = meta.query_selector(q_dist1_node);
            vec![q.clone() * (potential_friend - q1)]
        });

        meta.shuffle("hop1", |meta| {
            let q1 = meta.query_selector(q_distinct_hop1_to);
            let q2 = meta.query_selector(q_dist1_node);
            let a = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let b = meta.query_advice(person[0], Rotation::cur());
            let lhs = [one.clone(), b].map(|c| c * q2.clone());
            let rhs = [one.clone(), a].map(|c| c * q1.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("q_dist1_node", |meta| {
            let q = meta.query_selector(q_person);

            let d1 = meta.query_advice(dist1_node, Rotation::cur());
            let d0 = meta.query_advice(dist0_node, Rotation::cur());
            let p1 = meta.query_advice(potential_friend_hop1, Rotation::cur());
            vec![q.clone() * (p1 - (d1.clone() + d0.clone() - d1 * d0))]
        });

        // hop1_ext
        let distinct_hop1_to_ext = meta.advice_column();
        meta.enable_equality(distinct_hop1_to_ext);
        let q_distinct_hop1_to_ext = meta.complex_selector();
        let q_distinct_hop1_to_ext_order = meta.complex_selector();
        let q_distinct_hop1_to_ext_internal = meta.complex_selector();
        let q_distinct_hop1_to_ext_boundary = meta.complex_selector();

        let distinct_hop1_to_ext_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_ext_order),
            |meta| vec![meta.query_advice(distinct_hop1_to_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop1_to_ext, Rotation::next())],
        );
        meta.create_gate("distinct_hop1_to_ext order check", |meta| {
            let q = meta.query_selector(q_distinct_hop1_to_ext_order);
            // distinct_hop1_to_ext[i] <= distinct_hop1_to_ext[i+1] means is_lt should be 1.
            vec![q * (distinct_hop1_to_ext_order_config.is_lt(meta, None) - one.clone())]
        });

        // Shuffle from `distinct_hop1_to` (unique friend IDs) to `distinct_hop1_to_ext` (internal part)
        meta.shuffle(
            "distinct_hop1_to to distinct_hop1_to_ext internal",
            |meta| {
                let q_src = meta.query_selector(q_distinct_hop1_to);
                let q_dest = meta.query_selector(q_distinct_hop1_to_ext_internal);
                let a = meta.query_advice(distinct_hop1_to, Rotation::cur());
                let c = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs = [one.clone(), a].map(|c| c * q_src.clone());
                let rhs = [one.clone(), c].map(|c| c * q_dest.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );

        meta.create_gate("distinct_hop1_to_ext boundary check", |meta| {
            let q = meta.query_selector(q_distinct_hop1_to_ext_boundary);
            let current_val = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
            vec![
                q * current_val.clone()
                    * (current_val - Expression::Constant(F::from(MAX_PERSON_ID))),
            ]
        });

        meta.create_gate("distinct_hop1_to_ext selector logic", |meta| {
            let q_ext_active = meta.query_selector(q_distinct_hop1_to_ext);
            let q_int_active = meta.query_selector(q_distinct_hop1_to_ext_internal);
            let q_bound_active = meta.query_selector(q_distinct_hop1_to_ext_boundary);
            vec![q_ext_active * (q_int_active + q_bound_active - one.clone())]
        });

        let mut distinct_hop1_to_ext_pairs_lookup_table = Vec::new();
        for _ in 0..2 {
            distinct_hop1_to_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(distinct_hop1_to_ext_pairs_lookup_table[i]);
        }
        let q_distinct_hop1_to_ext_pairs_lookup = meta.complex_selector();

        let aligned_h1_pkp_personid = meta.advice_column();
        let next_aligned_h1_pkp_personid = meta.advice_column();

        meta.lookup_any(format!("align[i] from distinct_hop1_to_ext"), |meta| {
            let q = meta.query_selector(q_pkp);
            let a = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
            let b = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h1_pkp_personid, Rotation::cur())], // aligned_friend_id
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())], // actual Person.id
        );
        meta.create_gate("aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        let next_aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())], // actual Person.id
            |meta| {
                vec![meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur()) - one.clone()]
            },
        );
        meta.create_gate("next_aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        meta.lookup_any("distinct_hop1_to_ext_pairs_lookup_table from ", |meta| {
            let q1 = meta.query_selector(q_pkp);
            let q2 = meta.query_selector(q_distinct_hop1_to_ext_pairs_lookup);
            let a = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur());
            let c = meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let aligned_h1_pkp_to_personid = meta.advice_column();
        let next_aligned_h1_pkp_to_personid = meta.advice_column();

        meta.lookup_any(format!("align[i] from distinct_hop1_to_ext"), |meta| {
            let q = meta.query_selector(q_pkp);
            let a = meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur());
            let b = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q.clone());
            let rhs = [one.clone(), b].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let aligned_h1_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur())], // aligned_friend_id
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())], // actual Person.id
        );
        meta.create_gate("aligned_h1_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h1_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });

        let next_aligned_h1_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())], // actual Person.id
            |meta| {
                vec![
                    meta.query_advice(next_aligned_h1_pkp_to_personid, Rotation::cur())
                        - one.clone(),
                ]
            },
        );
        meta.create_gate("next_aligned_h1_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h1_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });

        meta.lookup_any("distinct_hop1_to_ext_pairs_lookup_table to", |meta| {
            let q1 = meta.query_selector(q_pkp);
            let q2 = meta.query_selector(q_distinct_hop1_to_ext_pairs_lookup);
            let a = meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur());
            let b = meta.query_advice(next_aligned_h1_pkp_to_personid, Rotation::cur());
            let c = meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[0], Rotation::cur());
            let d = meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let h1_pkp_to_flag = meta.advice_column();
        let iz_h1_pkp_to_flag = meta.advice_column();
        let h1_pkp_to_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[1], Rotation::cur())
            },
            iz_h1_pkp_to_flag,
            h1_pkp_to_flag,
        );

        // hop 2

        let h1_match_flag = meta.advice_column();
        let iz_h1_match_flag = meta.advice_column();
        let h1_match_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h1_pkp_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[0], Rotation::cur())
            },
            iz_h1_match_flag,
            h1_match_flag,
        );

        let dist2_node = meta.advice_column();
        let potential_friend_hop2 = meta.advice_column();
        let q_dist2_node = meta.complex_selector();

        meta.create_gate("q_dist2_node", |meta| {
            let q = meta.query_selector(q_person);
            let potential_friend = meta.query_advice(dist2_node, Rotation::cur());
            let q1 = meta.query_selector(q_dist2_node);
            vec![q.clone() * (potential_friend - q1)]
        });
        // ---------------------
        let distinct_hop2_to = meta.advice_column();
        let q_distinct_hop2_to = meta.complex_selector();
        let q_distinct_hop2_to_order = meta.selector();
        let q_hop2_to = meta.complex_selector();

        meta.create_gate("set_q_hop2_to_selector", |meta| {
            let q = meta.query_selector(q_pkp);
            let q_hop2 = meta.query_selector(q_hop2_to);
            let h1_match_from = meta.query_advice(h1_match_flag, Rotation::cur());
            let h1_match_to = meta.query_advice(h1_pkp_to_flag, Rotation::cur());
            let source_match_to = meta.query_advice(source_pkp_to_check, Rotation::cur());
            vec![
                q * (q_hop2
                    - h1_match_from
                        * (one.clone() - h1_match_to)
                        * (one.clone() - source_match_to)),
            ]
        });

        meta.lookup_any("distinct_hop2_to1", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_hop2_to);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), b].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any("distinct_hop2_to2", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_hop2_to);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), b].map(|c| c * q2.clone());
            let rhs = [one.clone(), a].map(|c| c * q1.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let distinct_hop2_to_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop2_to_order),
            |meta| vec![meta.query_advice(distinct_hop2_to, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop2_to, Rotation::next())],
        );

        let iz_distinct_hop2_to_zero = meta.advice_column();
        let distinct_hop2_to_check = meta.advice_column();
        let distinct_hop2_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop2_to_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(distinct_hop2_to, Rotation::cur())
                    - meta.query_advice(distinct_hop2_to, Rotation::next())
            },
            iz_distinct_hop2_to_zero,
            distinct_hop2_to_check,
        );

        meta.create_gate("distinct_hop2_to_order", |meta| {
            let q = meta.query_selector(q_distinct_hop2_to_order);
            let check = meta.query_advice(distinct_hop2_to_check, Rotation::cur());
            vec![q.clone() * check]
        });

        meta.shuffle("dist2_node", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_dist2_node);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(person[0], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), b].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("hop2_status", |meta| {
            let q = meta.query_selector(q_person);

            let q1 = meta.query_advice(dist2_node, Rotation::cur());
            let q2 = meta.query_advice(potential_friend_hop1, Rotation::cur());
            let q3 = meta.query_advice(potential_friend_hop2, Rotation::cur());
            vec![q.clone() * (q3 - (q1.clone() + q2.clone() - q1 * q2))]
        });

        Is1CircuitConfig {
            q_person,
            person,
            person_id,
            source_check,
            person_zero,
            person_knows_person,
            instance,
            q_pkp,
            ordered_pkp,
            q_ordered_pkp_sort,
            ordered_pkp_person_id_sort_config,
            aligned_h1_pkp_personid,
            next_aligned_h1_pkp_personid,
            aligned_h1_pkp_personid_config,
            next_aligned_h1_pkp_personid_config,
            potential_friend_hop1,
            dist0_node,
            dist1_node,
            source_pkp_zero,
            dist1_pkp_check,
            q_hop1_to,
            distinct_hop1_to,
            q_distinct_hop1_to,
            q_distinct_hop1_to_order,
            distinct_hop1_to_order,
            distinct_hop1_to_zero,
            distinct_hop1_to_check,
            distinct_hop1_to_ext,
            q_distinct_hop1_to_ext,
            q_distinct_hop1_to_ext_order,
            distinct_hop1_to_ext_order_config,
            q_distinct_hop1_to_ext_internal,
            q_distinct_hop1_to_ext_boundary,
            distinct_hop1_to_ext_pairs_lookup_table,
            q_distinct_hop1_to_ext_pairs_lookup,
            h1_match_flag_config,
            h1_match_flag,
            potential_friend_hop2,
            dist2_node,
            q_dist1_node,
            q_dist2_node,
            distinct_hop2_to,
            q_distinct_hop2_to,
            q_distinct_hop2_to_order,
            distinct_hop2_to_order,
            distinct_hop2_to_zero,
            distinct_hop2_to_check,
            aligned_h1_pkp_to_personid,
            next_aligned_h1_pkp_to_personid,
            aligned_h1_pkp_to_personid_config,
            next_aligned_h1_pkp_to_personid_config,
            h1_pkp_to_flag_config,
            h1_pkp_to_flag,
            source_pkp_to_zero,
            source_pkp_to_check,
            q_hop2_to,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<F>>,
        person_knows_person_input: Vec<Vec<F>>,
        person_id_val: F,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        fn f_to_u64<F: Field>(f: &F) -> u64 {
            let repr_bytes = f.to_repr();
            let bytes_ref: &[u8] = repr_bytes.as_ref();
            let mut u64_bytes = [0u8; 8];
            let len_to_copy = std::cmp::min(bytes_ref.len(), 8);
            u64_bytes[0..len_to_copy].copy_from_slice(&bytes_ref[0..len_to_copy]);
            u64::from_le_bytes(u64_bytes)
        }

        // Construct all chips from config
        let person_zero_chip = IsZeroChip::construct(self.config.person_zero.clone());
        let ordered_pkp_person_id_sort_chip =
            LtEqGenericChip::construct(self.config.ordered_pkp_person_id_sort_config.clone());

        let source_pkp_zero_chip = IsZeroChip::construct(self.config.source_pkp_zero.clone());
        let source_pkp_to_zero_chip = IsZeroChip::construct(self.config.source_pkp_to_zero.clone());

        let distinct_hop1_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop1_to_order.clone());
        let distinct_hop1_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop1_to_zero.clone());

        let distinct_hop1_to_ext_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop1_to_ext_order_config.clone());

        let aligned_h1_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h1_pkp_personid_config.clone());
        let next_aligned_h1_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h1_pkp_personid_config.clone());
        let h1_match_flag_chip = IsZeroChip::construct(self.config.h1_match_flag_config.clone());

        let aligned_h1_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h1_pkp_to_personid_config.clone());
        let next_aligned_h1_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h1_pkp_to_personid_config.clone());
        let h1_pkp_to_flag_chip = IsZeroChip::construct(self.config.h1_pkp_to_flag_config.clone());

        let distinct_hop2_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop2_to_order.clone());
        let distinct_hop2_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop2_to_zero.clone());

        // Load lookup tables
        ordered_pkp_person_id_sort_chip.load(layouter).unwrap();
        distinct_hop1_to_order_chip.load(layouter).unwrap();
        distinct_hop1_to_ext_order_chip.load(layouter).unwrap();
        aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop2_to_order_chip.load(layouter).unwrap();

        // BFS and data preprocessing (same as before)
        let max_hops = 2;
        let dummy_distance_u64: u64 = (max_hops + 1) as u64;
        let mut adj: HashMap<F, Vec<F>> = HashMap::new();
        for edge in &person_knows_person_input {
            adj.entry(edge[0]).or_default().push(edge[1]);
        }
        let mut distances: HashMap<F, u64> = HashMap::new();
        let mut q_bfs: VecDeque<F> = VecDeque::new();
        for p_row in &person_table {
            distances.insert(p_row[0], dummy_distance_u64);
        }
        if distances.contains_key(&person_id_val) {
            distances.insert(person_id_val, 0);
            q_bfs.push_back(person_id_val);
        } else {
            println!(
                "Person ID {:?} isnot in person_table",
                person_id_val
            );
        }
        while let Some(u_id) = q_bfs.pop_front() {
            let dist_u = distances[&u_id];
            if dist_u >= max_hops {
                continue;
            }
            if let Some(neighbors) = adj.get(&u_id) {
                for &v_id in neighbors {
                    if distances
                        .get(&v_id)
                        .map_or(false, |&d| d == dummy_distance_u64)
                    {
                        distances.insert(v_id, dist_u + 1);
                        q_bfs.push_back(v_id);
                    }
                }
            }
        }
        let mut ordered_pkp_table = person_knows_person_input.clone();
        ordered_pkp_table.sort_by(|a, b| f_to_u64(&a[1]).cmp(&f_to_u64(&b[1])));
        let mut hop1_friends = Vec::new();
        for edge in &ordered_pkp_table {
            if edge[0] == person_id_val {
                hop1_friends.push(edge[1]);
            }
        }
        hop1_friends.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop1_friends.dedup();
        let hop1_friends_distinct_sorted = hop1_friends;
        let mut distinct_hop1_to_ext_values = vec![F::ZERO];
        distinct_hop1_to_ext_values.extend(hop1_friends_distinct_sorted.iter().cloned());
        distinct_hop1_to_ext_values.push(F::from(MAX_PERSON_ID));
        distinct_hop1_to_ext_values.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        distinct_hop1_to_ext_values.dedup();
        let mut distinct_hop1_to_ext_pairs_table = Vec::new();
        if distinct_hop1_to_ext_values.len() >= 2 {
            for i in 0..(distinct_hop1_to_ext_values.len() - 1) {
                distinct_hop1_to_ext_pairs_table.push((
                    distinct_hop1_to_ext_values[i],
                    distinct_hop1_to_ext_values[i + 1],
                ));
            }
        }

        // Corrected distinct_hop2_to_table generation
        let mut hop2_friends_from_pkp_raw = Vec::new();
        for ordered_edge in &ordered_pkp_table {
            let pkp_source_node = ordered_edge[0];
            let pkp_target_node = ordered_edge[1];

            let is_pkp_source_a_1hop_friend = hop1_friends_distinct_sorted
                .binary_search(&pkp_source_node)
                .is_ok();
            if is_pkp_source_a_1hop_friend {
                let is_pkp_target_person_id = pkp_target_node == person_id_val;
                let is_pkp_target_a_1hop_friend = hop1_friends_distinct_sorted
                    .binary_search(&pkp_target_node)
                    .is_ok();

                if !is_pkp_target_person_id && !is_pkp_target_a_1hop_friend {
                    let bfs_dist_to_target = distances
                        .get(&pkp_target_node)
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    if bfs_dist_to_target == 2 {
                        hop2_friends_from_pkp_raw.push(pkp_target_node);
                    }
                }
            }
        }
        hop2_friends_from_pkp_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop2_friends_from_pkp_raw.dedup();
        let distinct_hop2_to_table = hop2_friends_from_pkp_raw;

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, p_row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;
                    for j in 0..8 {
                        region.assign_advice(
                            || format!("person col {} row {}", j, i),
                            self.config.person[j],
                            i,
                            || Value::known(p_row[j]),
                        )?;
                    }
                    region.assign_advice(
                        || format!("person_id for person row {}", i),
                        self.config.person_id,
                        i,
                        || Value::known(person_id_val),
                    )?;
                    let is_source_node = p_row[0] == person_id_val;
                    let source_check_val = F::from(is_source_node as u64);
                    region.assign_advice(
                        || format!("source_check for person row {}", i),
                        self.config.source_check,
                        i,
                        || Value::known(source_check_val),
                    )?;
                    person_zero_chip
                        .assign(&mut region, i, Value::known(p_row[0] - person_id_val))
                        .unwrap();
                    let dist = distances
                        .get(&p_row[0])
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    let is_dist0 = dist == 0;
                    let is_dist1 = dist == 1;
                    let is_dist2 = dist == 2;
                    let dist0_val = F::from(is_dist0 as u64);
                    let dist1_val = F::from(is_dist1 as u64);
                    let dist2_val = F::from(is_dist2 as u64);
                    region.assign_advice(
                        || format!("dist0_node at {}", i),
                        self.config.dist0_node,
                        i,
                        || Value::known(dist0_val),
                    )?;
                    region.assign_advice(
                        || format!("dist1_node at {}", i),
                        self.config.dist1_node,
                        i,
                        || Value::known(dist1_val),
                    )?;
                    region.assign_advice(
                        || format!("dist2_node at {}", i),
                        self.config.dist2_node,
                        i,
                        || Value::known(dist2_val),
                    )?;
                    if is_dist1 {
                        self.config.q_dist1_node.enable(&mut region, i)?;
                    }
                    if is_dist2 {
                        self.config.q_dist2_node.enable(&mut region, i)?;
                    }
                    let pot_friend_h1_val = if is_dist0 || is_dist1 {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    let pot_friend_h2_val = if is_dist0 || is_dist1 || is_dist2 {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("potential_friend_hop1 at {}", i),
                        self.config.potential_friend_hop1,
                        i,
                        || Value::known(pot_friend_h1_val),
                    )?;
                    region.assign_advice(
                        || format!("potential_friend_hop2 at {}", i),
                        self.config.potential_friend_hop2,
                        i,
                        || Value::known(pot_friend_h2_val),
                    )?;
                }

                // Assign ordered_pkp table and related flags
                for (i, ordered_edge) in ordered_pkp_table.iter().enumerate() {
                    self.config.q_pkp.enable(&mut region, i)?;
                    let pkp_source_node = ordered_edge[0];
                    let pkp_target_node = ordered_edge[1];

                    region.assign_advice(
                        || format!("pkp_shuffle_col0 row {}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(pkp_source_node),
                    )?;
                    region.assign_advice(
                        || format!("pkp_shuffle_col1 row {}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(pkp_target_node),
                    )?;
                    region.assign_advice(
                        || format!("ordered_pkp[0] row {}", i),
                        self.config.ordered_pkp[0],
                        i,
                        || Value::known(pkp_source_node),
                    )?;
                    region.assign_advice(
                        || format!("ordered_pkp[1] row {}", i),
                        self.config.ordered_pkp[1],
                        i,
                        || Value::known(pkp_target_node),
                    )?;
                    region.assign_advice(
                        || format!("person_id for pkp row {}", i),
                        self.config.person_id,
                        i,
                        || Value::known(person_id_val),
                    )?;

                    if i < ordered_pkp_table.len() - 1 {
                        self.config.q_ordered_pkp_sort.enable(&mut region, i)?;
                        ordered_pkp_person_id_sort_chip
                            .assign(
                                &mut region,
                                i,
                                &[pkp_target_node],
                                &[ordered_pkp_table[i + 1][1]],
                            )
                            .unwrap();
                    }

                    // dist1_pkp_check: pkp_source_node == person_id_val
                    let diff_source_pkp = pkp_source_node - person_id_val;
                    source_pkp_zero_chip
                        .assign(&mut region, i, Value::known(diff_source_pkp))
                        .unwrap();
                    let dist1_pkp_check_val = if diff_source_pkp == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("dist1_pkp_check row {}", i),
                        self.config.dist1_pkp_check,
                        i,
                        || Value::known(dist1_pkp_check_val),
                    )?;
                    if dist1_pkp_check_val == F::ONE {
                        self.config.q_hop1_to.enable(&mut region, i)?;
                    }

                    // source_pkp_to_check: pkp_target_node == person_id_val
                    let diff_source_pkp_to = pkp_target_node - person_id_val;
                    source_pkp_to_zero_chip
                        .assign(&mut region, i, Value::known(diff_source_pkp_to))
                        .unwrap();
                    let source_pkp_to_check_val = if diff_source_pkp_to == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("source_pkp_to_check row {}", i),
                        self.config.source_pkp_to_check,
                        i,
                        || Value::known(source_pkp_to_check_val),
                    )?;

                    // Alignment for pkp_source_node (ordered_edge[0])
                    let mut aligned_val_for_source = F::ZERO;
                    let mut next_aligned_val_for_source = F::from(MAX_PERSON_ID);
                    let search_res_src = distinct_hop1_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_source_node)));
                    match search_res_src {
                        Ok(idx) => {
                            aligned_val_for_source = distinct_hop1_to_ext_values[idx];
                            if idx + 1 < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_for_source = distinct_hop1_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_for_source = distinct_hop1_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_for_source = distinct_hop1_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h1_pkp_personid row {}", i),
                        self.config.aligned_h1_pkp_personid,
                        i,
                        || Value::known(aligned_val_for_source),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h1_pkp_personid row {}", i),
                        self.config.next_aligned_h1_pkp_personid,
                        i,
                        || Value::known(next_aligned_val_for_source),
                    )?;
                    aligned_h1_pkp_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[aligned_val_for_source],
                            &[pkp_source_node],
                        )
                        .unwrap();
                    next_aligned_h1_pkp_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_source_node],
                            &[next_aligned_val_for_source - F::ONE],
                        )
                        .unwrap();

                    // h1_match_flag: pkp_source_node is a 1-hop friend
                    let diff_h1_match_from = aligned_val_for_source - pkp_source_node;
                    h1_match_flag_chip
                        .assign(&mut region, i, Value::known(diff_h1_match_from))
                        .unwrap();
                    let h1_match_flag_val = if diff_h1_match_from == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h1_match_flag row {}", i),
                        self.config.h1_match_flag,
                        i,
                        || Value::known(h1_match_flag_val),
                    )?;

                    // Alignment for pkp_target_node (ordered_edge[1])
                    let mut aligned_val_for_target = F::ZERO;
                    let mut next_aligned_val_for_target = F::from(MAX_PERSON_ID);
                    let search_res_target = distinct_hop1_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_target_node)));
                    match search_res_target {
                        Ok(idx) => {
                            aligned_val_for_target = distinct_hop1_to_ext_values[idx];
                            if idx + 1 < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_for_target = distinct_hop1_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_for_target = distinct_hop1_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_for_target = distinct_hop1_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h1_pkp_to_personid row {}", i),
                        self.config.aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(aligned_val_for_target),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h1_pkp_to_personid row {}", i),
                        self.config.next_aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(next_aligned_val_for_target),
                    )?;
                    aligned_h1_pkp_to_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[aligned_val_for_target],
                            &[pkp_target_node],
                        )
                        .unwrap();
                    next_aligned_h1_pkp_to_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_target_node],
                            &[next_aligned_val_for_target - F::ONE],
                        )
                        .unwrap();

                    // h1_pkp_to_flag: pkp_target_node is a 1-hop friend
                    let diff_h1_pkp_to = aligned_val_for_target - pkp_target_node;
                    h1_pkp_to_flag_chip
                        .assign(&mut region, i, Value::known(diff_h1_pkp_to))
                        .unwrap();
                    let h1_pkp_to_flag_val = if diff_h1_pkp_to == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h1_pkp_to_flag row {}", i),
                        self.config.h1_pkp_to_flag,
                        i,
                        || Value::known(h1_pkp_to_flag_val),
                    )?;

                    region.assign_advice(
                        || format!("distinct_hop1_to_ext for pkp_source_align row {}", i),
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(aligned_val_for_source), // Value for align_pkp_source... lookup
                    )?;

                    region.assign_advice(
                        || format!("distinct_hop1_to_ext for pkp_target_align row {}", i),
                        self.config.distinct_hop1_to_ext,
                        i, // Overwrites previous assignment to this cell
                        || Value::known(aligned_val_for_target),
                    )?;

                    // Enable q_hop2_to selector
                    let enable_q_hop2_val = h1_match_flag_val
                        * (F::ONE - h1_pkp_to_flag_val)
                        * (F::ONE - source_pkp_to_check_val);
                    if enable_q_hop2_val == F::ONE {
                        self.config.q_hop2_to.enable(&mut region, i)?;
                    }
                }

                // Assign distinct_hop1_to table
                for (i, &friend_id) in hop1_friends_distinct_sorted.iter().enumerate() {
                    self.config.q_distinct_hop1_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("distinct_hop1_to row {}", i),
                        self.config.distinct_hop1_to,
                        i,
                        || Value::known(friend_id),
                    )?;
                    if i < hop1_friends_distinct_sorted.len() - 1 {
                        self.config
                            .q_distinct_hop1_to_order
                            .enable(&mut region, i)?;
                        let next_friend_id = hop1_friends_distinct_sorted[i + 1];
                        distinct_hop1_to_order_chip
                            .assign(&mut region, i, &[friend_id], &[next_friend_id])
                            .unwrap();
                        let diff_distinct = friend_id - next_friend_id;
                        distinct_hop1_to_zero_chip
                            .assign(&mut region, i, Value::known(diff_distinct))
                            .unwrap();
                        let distinct_hop1_to_check_val = if diff_distinct == F::ZERO {
                            F::ONE
                        } else {
                            F::ZERO
                        };
                        region.assign_advice(
                            || format!("distinct_hop1_to_check row {}", i),
                            self.config.distinct_hop1_to_check,
                            i,
                            || Value::known(distinct_hop1_to_check_val),
                        )?;
                    }
                }

                // Assign authoritative distinct_hop1_to_ext table
                for (i, &ext_id) in distinct_hop1_to_ext_values.iter().enumerate() {
                    self.config.q_distinct_hop1_to_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("authoritative_distinct_hop1_to_ext row {}", i),
                        self.config.distinct_hop1_to_ext, // The actual table column
                        i,
                        || Value::known(ext_id),
                    )?;
                    if ext_id == F::ZERO || ext_id == F::from(MAX_PERSON_ID) {
                        self.config
                            .q_distinct_hop1_to_ext_boundary
                            .enable(&mut region, i)?;
                    } else {
                        self.config
                            .q_distinct_hop1_to_ext_internal
                            .enable(&mut region, i)?;
                    }
                    if i < distinct_hop1_to_ext_values.len() - 1 {
                        self.config
                            .q_distinct_hop1_to_ext_order
                            .enable(&mut region, i)?;
                        distinct_hop1_to_ext_order_chip
                            .assign(
                                &mut region,
                                i,
                                &[ext_id],
                                &[distinct_hop1_to_ext_values[i + 1]],
                            )
                            .unwrap();
                    }
                }

                // Assign distinct_hop1_to_ext_pairs_lookup_table
                for (i, &(pair_first, pair_second)) in
                    distinct_hop1_to_ext_pairs_table.iter().enumerate()
                {
                    self.config
                        .q_distinct_hop1_to_ext_pairs_lookup
                        .enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d_h1_ext_pairs_lookup_tab[0] row {}", i),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(pair_first),
                    )?;
                    region.assign_advice(
                        || format!("d_h1_ext_pairs_lookup_tab[1] row {}", i),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(pair_second),
                    )?;
                }

                // Assign distinct_hop2_to table
                for (i, &h2_friend_id) in distinct_hop2_to_table.iter().enumerate() {
                    self.config.q_distinct_hop2_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("distinct_hop2_to row {}", i),
                        self.config.distinct_hop2_to,
                        i,
                        || Value::known(h2_friend_id),
                    )?;
                    if i < distinct_hop2_to_table.len() - 1 {
                        self.config
                            .q_distinct_hop2_to_order
                            .enable(&mut region, i)?;
                        let next_h2_friend_id = distinct_hop2_to_table[i + 1];
                        distinct_hop2_to_order_chip
                            .assign(&mut region, i, &[h2_friend_id], &[next_h2_friend_id])
                            .unwrap();
                        let diff_distinct_h2 = h2_friend_id - next_h2_friend_id;
                        distinct_hop2_to_zero_chip
                            .assign(&mut region, i, Value::known(diff_distinct_h2))
                            .unwrap();
                        let distinct_hop2_to_check_val = if diff_distinct_h2 == F::ZERO {
                            F::ONE
                        } else {
                            F::ZERO
                        };
                        region.assign_advice(
                            || format!("distinct_hop2_to_check row {}", i),
                            self.config.distinct_hop2_to_check,
                            i,
                            || Value::known(distinct_hop2_to_check_val),
                        )?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord + std::hash::Hash> {
    pub person: Vec<Vec<F>>,
    pub person_knows_person: Vec<Vec<F>>,
    pub person_id: F,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord + std::hash::Hash> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Default::default(),
            person_id: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord + std::hash::Hash> Circuit<F> for MyCircuit<F> {
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
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip = Is1Chip::construct(config.clone());

        chip.assign(
            &mut layouter.namespace(|| "Assign"),
            self.person.clone(),
            self.person_knows_person.clone(),
            self.person_id,
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
    fn test_bfs_circuit() {
        let k = 16;

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to load data");
        let relation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("Failed to load data");

        let mut person_table: Vec<Vec<Fr>> = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                Fr::from(row[0].parse::<u64>().expect("invalid ID")),
                Fr::from(string_to_u64(&row[1])),
                Fr::from(string_to_u64(&row[2])),
                Fr::from(if row[3] == "male" { 1 } else { 0 }),
                Fr::from(parse_date(&row[4])),
                Fr::from(parse_datetime(&row[5])),
                Fr::from(ipv4_to_u64(&row[6])),
                Fr::from(string_to_u64(&row[7])),
            ];
            person_table.push(person_row);
        }

        let mut person_knows_person: Vec<Vec<Fr>> = Vec::new();
        for (_, row) in relation_data.iter().enumerate() {
            let r_row = vec![
                Fr::from(row[0].parse::<u64>().expect("invalid ID")),
                Fr::from(row[1].parse::<u64>().expect("invalid ID")),
            ];
            person_knows_person.push(r_row);
        }

        println!("person:{:?}", person_table.len());
        println!("person_knows_person.len:{:?}", person_knows_person.len());

        let test_person_id_val: u64 = 21990232556585;
        let person_id_fr = Fr::from(test_person_id_val);

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_knows_person,
            person_id: person_id_fr,
            _marker: PhantomData,
        };

        println!("k = {}", k);

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
