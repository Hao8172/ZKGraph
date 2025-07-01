use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_BYTES: usize = 6;
const MAX_PERSON_ID: u64 = 100000000000000;

/*
MATCH path = shortestPath((p)-[:KNOWS*1..4]->(friend))
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

    source_pkp_zero: crate::chips::is_zero::IsZeroConfig<F>,
    dist1_pkp_check: Column<Advice>,
    source_pkp_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    source_pkp_to_check: Column<Advice>,

    dist0_node: Column<Advice>,
    dist1_node: Column<Advice>,
    q_dist1_node: Selector,
    potential_friend_hop1: Column<Advice>,

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

    dist2_node: Column<Advice>,
    q_dist2_node: Selector,
    potential_friend_hop2: Column<Advice>,
    q_hop2_to: Selector,
    distinct_hop2_to: Column<Advice>,
    q_distinct_hop2_to: Selector,
    q_distinct_hop2_to_order: Selector,
    distinct_hop2_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop2_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop2_to_check: Column<Advice>,

    distinct_hop2_to_ext: Column<Advice>,
    q_distinct_hop2_to_ext: Selector,
    q_distinct_hop2_to_ext_order: Selector,
    distinct_hop2_to_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_distinct_hop2_to_ext_internal: Selector,
    q_distinct_hop2_to_ext_boundary: Selector,
    distinct_hop2_to_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_distinct_hop2_to_ext_pairs_lookup: Selector,

    aligned_h2_pkp_personid: Column<Advice>,
    next_aligned_h2_pkp_personid: Column<Advice>,
    aligned_h2_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h2_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h2_match_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h2_match_flag: Column<Advice>,
    aligned_h2_pkp_to_personid: Column<Advice>,
    next_aligned_h2_pkp_to_personid: Column<Advice>,
    aligned_h2_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h2_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h2_pkp_to_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h2_pkp_to_flag: Column<Advice>,

    dist3_node: Column<Advice>,

    q_dist3_node: Selector,
    potential_friend_hop3: Column<Advice>,
    q_hop3_to: Selector,
    distinct_hop3_to: Column<Advice>,
    q_distinct_hop3_to: Selector,
    q_distinct_hop3_to_order: Selector,
    distinct_hop3_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop3_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop3_to_check: Column<Advice>,

    distinct_hop3_to_ext: Column<Advice>,
    q_distinct_hop3_to_ext: Selector,
    q_distinct_hop3_to_ext_order: Selector,
    distinct_hop3_to_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_distinct_hop3_to_ext_internal: Selector,
    q_distinct_hop3_to_ext_boundary: Selector,
    distinct_hop3_to_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_distinct_hop3_to_ext_pairs_lookup: Selector,

    aligned_h3_pkp_personid: Column<Advice>,
    next_aligned_h3_pkp_personid: Column<Advice>,
    aligned_h3_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h3_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h3_match_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h3_match_flag: Column<Advice>,
    aligned_h3_pkp_to_personid: Column<Advice>,
    next_aligned_h3_pkp_to_personid: Column<Advice>,
    aligned_h3_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h3_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h3_pkp_to_flag_config: crate::chips::is_zero::IsZeroConfig<F>,
    h3_pkp_to_flag: Column<Advice>,

    dist4_node: Column<Advice>,
    q_dist4_node: Selector,
    potential_friend_hop4: Column<Advice>,
    q_hop4_to: Selector,
    distinct_hop4_to: Column<Advice>,
    q_distinct_hop4_to: Selector,
    q_distinct_hop4_to_order: Selector,
    distinct_hop4_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop4_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop4_to_check: Column<Advice>,

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
            let lhs = [one.clone(), a, b].map(|val| val * q.clone());
            let rhs = [one.clone(), c, d].map(|val| val * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_pkp_sort = meta.complex_selector();
        let ordered_pkp_person_id_sort_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_pkp_sort),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::next())],
        );
        meta.create_gate("verify ordered_pkp sort by PersonToId", |meta| {
            let q = meta.query_selector(q_ordered_pkp_sort);
            vec![q.clone() * (ordered_pkp_person_id_sort_config.is_lt(meta, None) - one.clone())]
        });

        let dist0_node = meta.advice_column();
        meta.create_gate("init_h0_states", |meta| {
            let q = meta.query_selector(q_person);
            let source_is_this_person = meta.query_advice(source_check, Rotation::cur());
            let current_node_is_dist0 = meta.query_advice(dist0_node, Rotation::cur());
            vec![q.clone() * (current_node_is_dist0 - source_is_this_person.clone())]
        });

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

        // --- Hop 1 Configuration ---
        let q_hop1_to = meta.complex_selector();
        meta.create_gate("set_q_hop1_to_selector", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_hop1_to_val = meta.query_selector(q_hop1_to);
            let pkp_from_is_source = meta.query_advice(dist1_pkp_check, Rotation::cur());
            vec![q_pkp_active.clone() * (q_hop1_to_val - pkp_from_is_source)]
        });

        let distinct_hop1_to = meta.advice_column();
        let q_distinct_hop1_to = meta.complex_selector();
        let q_distinct_hop1_to_order = meta.selector();

        meta.lookup_any("distinct_hop1_to from pkp.ToId where q_hop1_to", |meta| {
            let q_distinct_active = meta.query_selector(q_distinct_hop1_to);
            let q_pkp_hop1_edge_active = meta.query_selector(q_hop1_to);
            let distinct_friend = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let pkp_target_node = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), distinct_friend].map(|val| val * q_distinct_active.clone());
            let rhs =
                [one.clone(), pkp_target_node].map(|val| val * q_pkp_hop1_edge_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any("pkp.ToId where q_hop1_to into distinct_hop1_to", |meta| {
            let q_distinct_active = meta.query_selector(q_distinct_hop1_to);
            let q_pkp_hop1_edge_active = meta.query_selector(q_hop1_to);
            let distinct_friend = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let pkp_target_node = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs =
                [one.clone(), pkp_target_node].map(|val| val * q_pkp_hop1_edge_active.clone());
            let rhs = [one.clone(), distinct_friend].map(|val| val * q_distinct_active.clone());
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

        meta.create_gate("distinct_hop1_to_order and uniqueness", |meta| {
            let q_order_active = meta.query_selector(q_distinct_hop1_to_order);
            let cur_eq_next_flag = meta.query_advice(distinct_hop1_to_check, Rotation::cur());
            let cur_lte_next_flag = distinct_hop1_to_order.is_lt(meta, None);
            vec![
                q_order_active.clone() * (cur_lte_next_flag - one.clone()),
                q_order_active.clone() * cur_eq_next_flag.clone(),
            ]
        });

        let potential_friend_hop1 = meta.advice_column();
        let dist1_node = meta.advice_column();
        let q_dist1_node = meta.complex_selector();

        meta.create_gate("init_h1_states", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let dist1_node_assigned_val = meta.query_advice(dist1_node, Rotation::cur());
            let q_dist1_node_selector_val = meta.query_selector(q_dist1_node);
            vec![q_person_active.clone() * (dist1_node_assigned_val - q_dist1_node_selector_val)]
        });

        meta.shuffle("mark 1-hop friends in person table", |meta| {
            let q_distinct_h1_active = meta.query_selector(q_distinct_hop1_to);
            let q_person_dist1_active = meta.query_selector(q_dist1_node);
            let friend_id_from_distinct = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let person_id_from_person_table = meta.query_advice(person[0], Rotation::cur());
            let lhs = [one.clone(), person_id_from_person_table]
                .map(|val| val * q_person_dist1_active.clone());
            let rhs = [one.clone(), friend_id_from_distinct]
                .map(|val| val * q_distinct_h1_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("calculate potential_friend_hop1", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let d1 = meta.query_advice(dist1_node, Rotation::cur());
            let d0 = meta.query_advice(dist0_node, Rotation::cur());
            let potential_h1 = meta.query_advice(potential_friend_hop1, Rotation::cur());
            vec![q_person_active.clone() * (potential_h1 - (d1.clone() + d0.clone() - d1 * d0))]
        });

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
            vec![q * (distinct_hop1_to_ext_order_config.is_lt(meta, None) - one.clone())]
        });

        meta.shuffle(
            "distinct_hop1_to to distinct_hop1_to_ext internal part",
            |meta| {
                let q_src_distinct_h1 = meta.query_selector(q_distinct_hop1_to);
                let q_dest_ext_internal = meta.query_selector(q_distinct_hop1_to_ext_internal);
                let val_from_distinct_h1 = meta.query_advice(distinct_hop1_to, Rotation::cur());
                let val_in_ext_internal = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs =
                    [one.clone(), val_from_distinct_h1].map(|v| v * q_src_distinct_h1.clone());
                let rhs =
                    [one.clone(), val_in_ext_internal].map(|v| v * q_dest_ext_internal.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );

        meta.create_gate("distinct_hop1_to_ext boundary check", |meta| {
            let q_boundary_active = meta.query_selector(q_distinct_hop1_to_ext_boundary);
            let current_val = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
            vec![
                q_boundary_active
                    * current_val.clone()
                    * (current_val - Expression::Constant(F::from(MAX_PERSON_ID))),
            ]
        });

        meta.create_gate("distinct_hop1_to_ext selector logic", |meta| {
            let q_ext_row_active = meta.query_selector(q_distinct_hop1_to_ext);
            let q_internal_part_active = meta.query_selector(q_distinct_hop1_to_ext_internal);
            let q_boundary_part_active = meta.query_selector(q_distinct_hop1_to_ext_boundary);
            vec![q_ext_row_active * (q_internal_part_active + q_boundary_part_active - one.clone())]
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

        meta.lookup_any(
            "aligned_h1_pkp_personid is from distinct_hop1_to_ext",
            |meta| {
                let q_pkp_row_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop1_to_ext);
                let val_to_check = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_row_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h1_pkp_personid is from distinct_hop1_to_ext",
            |meta| {
                let q_pkp_row_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop1_to_ext);
                let val_to_check = meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_row_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );

        let aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h1_pkp_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
        );
        meta.create_gate("aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        let next_aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
            |meta| {
                vec![meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur()) - one.clone()]
            },
        );
        meta.create_gate("next_aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        meta.lookup_any("aligned_h1_pkp_personid pair lookup", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_pairs_table_active = meta.query_selector(q_distinct_hop1_to_ext_pairs_lookup);
            let aligned_val = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
            let next_aligned_val = meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur());
            let pair_first =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[0], Rotation::cur());
            let pair_second =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs =
                [one.clone(), aligned_val, next_aligned_val].map(|v| v * q_pkp_active.clone());
            let rhs =
                [one.clone(), pair_first, pair_second].map(|v| v * q_pairs_table_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

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

        let aligned_h1_pkp_to_personid = meta.advice_column();
        let next_aligned_h1_pkp_to_personid = meta.advice_column();

        meta.lookup_any(
            "aligned_h1_pkp_to_personid is from distinct_hop1_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop1_to_ext);
                let val_to_check = meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h1_pkp_to_personid is from distinct_hop1_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop1_to_ext);
                let val_to_check =
                    meta.query_advice(next_aligned_h1_pkp_to_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );

        let aligned_h1_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
        );
        meta.create_gate("aligned_h1_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h1_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });

        let next_aligned_h1_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
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

        meta.lookup_any("aligned_h1_pkp_to_personid pair lookup", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_pairs_table_active = meta.query_selector(q_distinct_hop1_to_ext_pairs_lookup);
            let aligned_val = meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur());
            let next_aligned_val =
                meta.query_advice(next_aligned_h1_pkp_to_personid, Rotation::cur());
            let pair_first =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[0], Rotation::cur());
            let pair_second =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs =
                [one.clone(), aligned_val, next_aligned_val].map(|v| v * q_pkp_active.clone());
            let rhs =
                [one.clone(), pair_first, pair_second].map(|v| v * q_pairs_table_active.clone());
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

        let dist2_node = meta.advice_column();
        let potential_friend_hop2 = meta.advice_column();
        let q_dist2_node = meta.complex_selector();

        meta.create_gate("init_h2_states", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let dist2_node_assigned_val = meta.query_advice(dist2_node, Rotation::cur());
            let q_dist2_node_selector_val = meta.query_selector(q_dist2_node);
            vec![q_person_active.clone() * (dist2_node_assigned_val - q_dist2_node_selector_val)]
        });

        let q_hop2_to = meta.complex_selector();
        meta.create_gate("set_q_hop2_to_selector", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_hop2_to_val = meta.query_selector(q_hop2_to);
            let pkp_from_is_h1_friend = meta.query_advice(h1_match_flag, Rotation::cur());
            let pkp_to_is_h1_friend = meta.query_advice(h1_pkp_to_flag, Rotation::cur());
            let pkp_to_is_source = meta.query_advice(source_pkp_to_check, Rotation::cur());
            let condition = pkp_from_is_h1_friend
                * (one.clone() - pkp_to_is_h1_friend)
                * (one.clone() - pkp_to_is_source);
            vec![q_pkp_active.clone() * (q_hop2_to_val - condition)]
        });

        let distinct_hop2_to = meta.advice_column();
        let q_distinct_hop2_to = meta.complex_selector();
        let q_distinct_hop2_to_order = meta.selector();

        meta.lookup_any("distinct_hop2_to from pkp.ToId where q_hop2_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_hop2_to);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), a]
                .map(|c| c * q1.clone())
                .into_iter()
                .zip([one.clone(), b].map(|c| c * q2.clone()))
                .collect()
        });
        meta.lookup_any("pkp.ToId where q_hop2_to into distinct_hop2_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_hop2_to);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), b]
                .map(|c| c * q2.clone())
                .into_iter()
                .zip([one.clone(), a].map(|c| c * q1.clone()))
                .collect()
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
        meta.create_gate("distinct_hop2_to_order and uniqueness", |meta| {
            let q = meta.query_selector(q_distinct_hop2_to_order);
            let check = meta.query_advice(distinct_hop2_to_check, Rotation::cur());
            let cur_lte_next = distinct_hop2_to_order.is_lt(meta, None);
            vec![q.clone() * (cur_lte_next - one.clone()), q.clone() * check]
        });

        meta.shuffle("mark 2-hop friends in person table", |meta| {
            let q_distinct_h2_active = meta.query_selector(q_distinct_hop2_to);
            let q_person_dist2_active = meta.query_selector(q_dist2_node);
            let friend_id_from_distinct_h2 = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let person_id_from_person_table = meta.query_advice(person[0], Rotation::cur());
            [one.clone(), person_id_from_person_table]
                .map(|v| v * q_person_dist2_active.clone())
                .into_iter()
                .zip(
                    [one.clone(), friend_id_from_distinct_h2]
                        .map(|v| v * q_distinct_h2_active.clone()),
                )
                .collect()
        });

        meta.create_gate("calculate potential_friend_hop2", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let d2 = meta.query_advice(dist2_node, Rotation::cur());
            let pot_h1 = meta.query_advice(potential_friend_hop1, Rotation::cur());
            let pot_h2 = meta.query_advice(potential_friend_hop2, Rotation::cur());
            vec![q_person_active.clone() * (pot_h2 - (d2.clone() + pot_h1.clone() - d2 * pot_h1))]
        });

        let distinct_hop2_to_ext = meta.advice_column();
        meta.enable_equality(distinct_hop2_to_ext);
        let q_distinct_hop2_to_ext = meta.complex_selector();
        let q_distinct_hop2_to_ext_order = meta.complex_selector();
        let q_distinct_hop2_to_ext_internal = meta.complex_selector();
        let q_distinct_hop2_to_ext_boundary = meta.complex_selector();
        let distinct_hop2_to_ext_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop2_to_ext_order),
            |meta| vec![meta.query_advice(distinct_hop2_to_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop2_to_ext, Rotation::next())],
        );
        meta.create_gate("distinct_hop2_to_ext order check", |meta| {
            let q = meta.query_selector(q_distinct_hop2_to_ext_order);
            vec![q * (distinct_hop2_to_ext_order_config.is_lt(meta, None) - one.clone())]
        });
        meta.shuffle(
            "distinct_hop2_to to distinct_hop2_to_ext internal part",
            |meta| {
                let q_s = meta.query_selector(q_distinct_hop2_to);
                let q_d = meta.query_selector(q_distinct_hop2_to_ext_internal);
                let v_s = meta.query_advice(distinct_hop2_to, Rotation::cur());
                let v_d = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                [one.clone(), v_s]
                    .map(|v| v * q_s.clone())
                    .into_iter()
                    .zip([one.clone(), v_d].map(|v| v * q_d.clone()))
                    .collect()
            },
        );
        meta.create_gate("distinct_hop2_to_ext boundary check", |meta| {
            let q = meta.query_selector(q_distinct_hop2_to_ext_boundary);
            let c = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
            vec![q * c.clone() * (c - Expression::Constant(F::from(MAX_PERSON_ID)))]
        });
        meta.create_gate("distinct_hop2_to_ext selector logic", |meta| {
            let q_e = meta.query_selector(q_distinct_hop2_to_ext);
            let q_i = meta.query_selector(q_distinct_hop2_to_ext_internal);
            let q_b = meta.query_selector(q_distinct_hop2_to_ext_boundary);
            vec![q_e * (q_i + q_b - one.clone())]
        });
        let mut distinct_hop2_to_ext_pairs_lookup_table = Vec::new();
        for _ in 0..2 {
            distinct_hop2_to_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(distinct_hop2_to_ext_pairs_lookup_table[i]);
        }
        let q_distinct_hop2_to_ext_pairs_lookup = meta.complex_selector();

        let aligned_h2_pkp_personid = meta.advice_column();
        let next_aligned_h2_pkp_personid = meta.advice_column();
        meta.lookup_any(
            "aligned_h2_pkp_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop2_to_ext);
                let v_c = meta.query_advice(aligned_h2_pkp_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h2_pkp_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop2_to_ext);
                let v_c = meta.query_advice(next_aligned_h2_pkp_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        let aligned_h2_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h2_pkp_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
        );
        meta.create_gate("aligned_h2_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h2_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });
        let next_aligned_h2_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
            |meta| {
                vec![meta.query_advice(next_aligned_h2_pkp_personid, Rotation::cur()) - one.clone()]
            },
        );
        meta.create_gate("next_aligned_h2_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h2_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });
        meta.lookup_any("aligned_h2_pkp_personid pair lookup", |meta| {
            let q_p = meta.query_selector(q_pkp);
            let q_pair = meta.query_selector(q_distinct_hop2_to_ext_pairs_lookup);
            let a_v = meta.query_advice(aligned_h2_pkp_personid, Rotation::cur());
            let n_a_v = meta.query_advice(next_aligned_h2_pkp_personid, Rotation::cur());
            let p_f =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[0], Rotation::cur());
            let p_s =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[1], Rotation::cur());
            [one.clone(), a_v, n_a_v]
                .map(|v| v * q_p.clone())
                .into_iter()
                .zip([one.clone(), p_f, p_s].map(|v| v * q_pair.clone()))
                .collect()
        });
        let h2_match_flag = meta.advice_column();
        let iz_h2_match_flag = meta.advice_column();
        let h2_match_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h2_pkp_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[0], Rotation::cur())
            },
            iz_h2_match_flag,
            h2_match_flag,
        );
        let aligned_h2_pkp_to_personid = meta.advice_column();
        let next_aligned_h2_pkp_to_personid = meta.advice_column();
        meta.lookup_any(
            "aligned_h2_pkp_to_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop2_to_ext);
                let v_c = meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h2_pkp_to_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop2_to_ext);
                let v_c = meta.query_advice(next_aligned_h2_pkp_to_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        let aligned_h2_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
        );
        meta.create_gate("aligned_h2_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h2_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });
        let next_aligned_h2_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_h2_pkp_to_personid, Rotation::cur())
                        - one.clone(),
                ]
            },
        );
        meta.create_gate("next_aligned_h2_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h2_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });
        meta.lookup_any("aligned_h2_pkp_to_personid pair lookup", |meta| {
            let q_p = meta.query_selector(q_pkp);
            let q_pair = meta.query_selector(q_distinct_hop2_to_ext_pairs_lookup);
            let a_v = meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur());
            let n_a_v = meta.query_advice(next_aligned_h2_pkp_to_personid, Rotation::cur());
            let p_f =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[0], Rotation::cur());
            let p_s =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[1], Rotation::cur());
            [one.clone(), a_v, n_a_v]
                .map(|v| v * q_p.clone())
                .into_iter()
                .zip([one.clone(), p_f, p_s].map(|v| v * q_pair.clone()))
                .collect()
        });
        let h2_pkp_to_flag = meta.advice_column();
        let iz_h2_pkp_to_flag = meta.advice_column();
        let h2_pkp_to_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[1], Rotation::cur())
            },
            iz_h2_pkp_to_flag,
            h2_pkp_to_flag,
        );

        let dist3_node = meta.advice_column();
        let potential_friend_hop3 = meta.advice_column();
        let q_dist3_node = meta.complex_selector();
        meta.create_gate("init_h3_states", |meta| {
            let q = meta.query_selector(q_person);
            let d = meta.query_advice(dist3_node, Rotation::cur());
            let s = meta.query_selector(q_dist3_node);
            vec![q.clone() * (d - s)]
        });
        let q_hop3_to = meta.complex_selector();
        meta.create_gate("set_q_hop3_to_selector", |meta| {
            let q_pkp = meta.query_selector(q_pkp);
            let q_h3 = meta.query_selector(q_hop3_to);
            let from_h2 = meta.query_advice(h2_match_flag, Rotation::cur());
            let to_src = meta.query_advice(source_pkp_to_check, Rotation::cur());
            let to_h1 = meta.query_advice(h1_pkp_to_flag, Rotation::cur());
            let to_h2 = meta.query_advice(h2_pkp_to_flag, Rotation::cur());
            let cond =
                from_h2 * (one.clone() - to_src) * (one.clone() - to_h1) * (one.clone() - to_h2);
            vec![q_pkp.clone() * (q_h3 - cond)]
        });
        let distinct_hop3_to = meta.advice_column();
        let q_distinct_hop3_to = meta.complex_selector();
        let q_distinct_hop3_to_order = meta.selector();
        meta.lookup_any("distinct_hop3_to from pkp.ToId where q_hop3_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop3_to);
            let q2 = meta.query_selector(q_hop3_to);
            let a = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), a]
                .map(|c| c * q1.clone())
                .into_iter()
                .zip([one.clone(), b].map(|c| c * q2.clone()))
                .collect()
        });
        meta.lookup_any("pkp.ToId where q_hop3_to into distinct_hop3_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop3_to);
            let q2 = meta.query_selector(q_hop3_to);
            let a = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), b]
                .map(|c| c * q2.clone())
                .into_iter()
                .zip([one.clone(), a].map(|c| c * q1.clone()))
                .collect()
        });
        let distinct_hop3_to_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop3_to_order),
            |meta| vec![meta.query_advice(distinct_hop3_to, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop3_to, Rotation::next())],
        );
        let iz_distinct_hop3_to_zero = meta.advice_column();
        let distinct_hop3_to_check = meta.advice_column();
        let distinct_hop3_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop3_to_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(distinct_hop3_to, Rotation::cur())
                    - meta.query_advice(distinct_hop3_to, Rotation::next())
            },
            iz_distinct_hop3_to_zero,
            distinct_hop3_to_check,
        );
        meta.create_gate("distinct_hop3_to_order and uniqueness", |meta| {
            let q = meta.query_selector(q_distinct_hop3_to_order);
            let chk = meta.query_advice(distinct_hop3_to_check, Rotation::cur());
            let lte = distinct_hop3_to_order.is_lt(meta, None);
            vec![q.clone() * (lte - one.clone()), q.clone() * chk]
        });
        meta.shuffle("mark 3-hop friends in person table", |meta| {
            let q_dist_h3 = meta.query_selector(q_distinct_hop3_to);
            let q_pers_d3 = meta.query_selector(q_dist3_node);
            let id_dist_h3 = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let id_pers = meta.query_advice(person[0], Rotation::cur());
            [one.clone(), id_pers]
                .map(|v| v * q_pers_d3.clone())
                .into_iter()
                .zip([one.clone(), id_dist_h3].map(|v| v * q_dist_h3.clone()))
                .collect()
        });
        meta.create_gate("calculate potential_friend_hop3", |meta| {
            let q = meta.query_selector(q_person);
            let d3 = meta.query_advice(dist3_node, Rotation::cur());
            let p_h2 = meta.query_advice(potential_friend_hop2, Rotation::cur());
            let p_h3 = meta.query_advice(potential_friend_hop3, Rotation::cur());
            vec![q.clone() * (p_h3 - (d3.clone() + p_h2.clone() - d3 * p_h2))]
        });

        let distinct_hop3_to_ext = meta.advice_column();
        meta.enable_equality(distinct_hop3_to_ext);
        let q_distinct_hop3_to_ext = meta.complex_selector();
        let q_distinct_hop3_to_ext_order = meta.complex_selector();
        let q_distinct_hop3_to_ext_internal = meta.complex_selector();
        let q_distinct_hop3_to_ext_boundary = meta.complex_selector();
        let distinct_hop3_to_ext_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop3_to_ext_order),
            |meta| vec![meta.query_advice(distinct_hop3_to_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop3_to_ext, Rotation::next())],
        );
        meta.create_gate("distinct_hop3_to_ext order check", |meta| {
            let q = meta.query_selector(q_distinct_hop3_to_ext_order);
            vec![q * (distinct_hop3_to_ext_order_config.is_lt(meta, None) - one.clone())]
        });
        meta.shuffle(
            "distinct_hop3_to to distinct_hop3_to_ext internal part",
            |meta| {
                let q_s = meta.query_selector(q_distinct_hop3_to);
                let q_d = meta.query_selector(q_distinct_hop3_to_ext_internal);
                let v_s = meta.query_advice(distinct_hop3_to, Rotation::cur());
                let v_d = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
                [one.clone(), v_s]
                    .map(|v| v * q_s.clone())
                    .into_iter()
                    .zip([one.clone(), v_d].map(|v| v * q_d.clone()))
                    .collect()
            },
        );
        meta.create_gate("distinct_hop3_to_ext boundary check", |meta| {
            let q = meta.query_selector(q_distinct_hop3_to_ext_boundary);
            let c = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
            vec![q * c.clone() * (c - Expression::Constant(F::from(MAX_PERSON_ID)))]
        });
        meta.create_gate("distinct_hop3_to_ext selector logic", |meta| {
            let q_e = meta.query_selector(q_distinct_hop3_to_ext);
            let q_i = meta.query_selector(q_distinct_hop3_to_ext_internal);
            let q_b = meta.query_selector(q_distinct_hop3_to_ext_boundary);
            vec![q_e * (q_i + q_b - one.clone())]
        });
        let mut distinct_hop3_to_ext_pairs_lookup_table = Vec::new();
        for _ in 0..2 {
            distinct_hop3_to_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(distinct_hop3_to_ext_pairs_lookup_table[i]);
        }
        let q_distinct_hop3_to_ext_pairs_lookup = meta.complex_selector();

        let aligned_h3_pkp_personid = meta.advice_column();
        let next_aligned_h3_pkp_personid = meta.advice_column();
        meta.lookup_any(
            "aligned_h3_pkp_personid is from distinct_hop3_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop3_to_ext);
                let v_c = meta.query_advice(aligned_h3_pkp_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h3_pkp_personid is from distinct_hop3_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop3_to_ext);
                let v_c = meta.query_advice(next_aligned_h3_pkp_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        let aligned_h3_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h3_pkp_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
        );
        meta.create_gate("aligned_h3_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h3_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });
        let next_aligned_h3_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],
            |meta| {
                vec![meta.query_advice(next_aligned_h3_pkp_personid, Rotation::cur()) - one.clone()]
            },
        );
        meta.create_gate("next_aligned_h3_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h3_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });
        meta.lookup_any("aligned_h3_pkp_personid pair lookup", |meta| {
            let q_p = meta.query_selector(q_pkp);
            let q_pair = meta.query_selector(q_distinct_hop3_to_ext_pairs_lookup);
            let av = meta.query_advice(aligned_h3_pkp_personid, Rotation::cur());
            let nav = meta.query_advice(next_aligned_h3_pkp_personid, Rotation::cur());
            let pf = meta.query_advice(distinct_hop3_to_ext_pairs_lookup_table[0], Rotation::cur());
            let ps = meta.query_advice(distinct_hop3_to_ext_pairs_lookup_table[1], Rotation::cur());
            [one.clone(), av, nav]
                .map(|v| v * q_p.clone())
                .into_iter()
                .zip([one.clone(), pf, ps].map(|v| v * q_pair.clone()))
                .collect()
        });
        let h3_match_flag = meta.advice_column();
        let iz_h3_match_flag = meta.advice_column();
        let h3_match_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h3_pkp_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[0], Rotation::cur())
            },
            iz_h3_match_flag,
            h3_match_flag,
        );
        let aligned_h3_pkp_to_personid = meta.advice_column();
        let next_aligned_h3_pkp_to_personid = meta.advice_column();
        meta.lookup_any(
            "aligned_h3_pkp_to_personid is from distinct_hop3_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop3_to_ext);
                let v_c = meta.query_advice(aligned_h3_pkp_to_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h3_pkp_to_personid is from distinct_hop3_to_ext",
            |meta| {
                let q_p = meta.query_selector(q_pkp);
                let q_e = meta.query_selector(q_distinct_hop3_to_ext);
                let v_c = meta.query_advice(next_aligned_h3_pkp_to_personid, Rotation::cur());
                let v_e = meta.query_advice(distinct_hop3_to_ext, Rotation::cur());
                [one.clone(), v_c]
                    .map(|v| v * q_p.clone())
                    .into_iter()
                    .zip([one.clone(), v_e].map(|v| v * q_e.clone()))
                    .collect()
            },
        );
        let aligned_h3_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h3_pkp_to_personid, Rotation::cur())],
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
        );
        meta.create_gate("aligned_h3_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h3_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });
        let next_aligned_h3_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],
            |meta| {
                vec![
                    meta.query_advice(next_aligned_h3_pkp_to_personid, Rotation::cur())
                        - one.clone(),
                ]
            },
        );
        meta.create_gate("next_aligned_h3_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (next_aligned_h3_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });
        meta.lookup_any("aligned_h3_pkp_to_personid pair lookup", |meta| {
            let q_p = meta.query_selector(q_pkp);
            let q_pair = meta.query_selector(q_distinct_hop3_to_ext_pairs_lookup);
            let av = meta.query_advice(aligned_h3_pkp_to_personid, Rotation::cur());
            let nav = meta.query_advice(next_aligned_h3_pkp_to_personid, Rotation::cur());
            let pf = meta.query_advice(distinct_hop3_to_ext_pairs_lookup_table[0], Rotation::cur());
            let ps = meta.query_advice(distinct_hop3_to_ext_pairs_lookup_table[1], Rotation::cur());
            [one.clone(), av, nav]
                .map(|v| v * q_p.clone())
                .into_iter()
                .zip([one.clone(), pf, ps].map(|v| v * q_pair.clone()))
                .collect()
        });
        let h3_pkp_to_flag = meta.advice_column();
        let iz_h3_pkp_to_flag = meta.advice_column();
        let h3_pkp_to_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                meta.query_advice(aligned_h3_pkp_to_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[1], Rotation::cur())
            },
            iz_h3_pkp_to_flag,
            h3_pkp_to_flag,
        );

        let dist4_node = meta.advice_column();
        let potential_friend_hop4 = meta.advice_column();
        let q_dist4_node = meta.complex_selector();
        meta.create_gate("init_h4_states", |meta| {
            let q = meta.query_selector(q_person);
            let d = meta.query_advice(dist4_node, Rotation::cur());
            let s = meta.query_selector(q_dist4_node);
            vec![q.clone() * (d - s)]
        });
        let q_hop4_to = meta.complex_selector();
        meta.create_gate("set_q_hop4_to_selector", |meta| {
            let q_pkp = meta.query_selector(q_pkp);
            let q_h4 = meta.query_selector(q_hop4_to);
            let from_h3 = meta.query_advice(h3_match_flag, Rotation::cur());
            let to_src = meta.query_advice(source_pkp_to_check, Rotation::cur());
            let to_h1 = meta.query_advice(h1_pkp_to_flag, Rotation::cur());
            let to_h2 = meta.query_advice(h2_pkp_to_flag, Rotation::cur());
            let to_h3 = meta.query_advice(h3_pkp_to_flag, Rotation::cur());
            let cond = from_h3
                * (one.clone() - to_src)
                * (one.clone() - to_h1)
                * (one.clone() - to_h2)
                * (one.clone() - to_h3);
            vec![q_pkp.clone() * (q_h4 - cond)]
        });
        let distinct_hop4_to = meta.advice_column();
        let q_distinct_hop4_to = meta.complex_selector();
        let q_distinct_hop4_to_order = meta.selector();
        meta.lookup_any("distinct_hop4_to from pkp.ToId where q_hop4_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop4_to);
            let q2 = meta.query_selector(q_hop4_to);
            let a = meta.query_advice(distinct_hop4_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), a]
                .map(|c| c * q1.clone())
                .into_iter()
                .zip([one.clone(), b].map(|c| c * q2.clone()))
                .collect()
        });
        meta.lookup_any("pkp.ToId where q_hop4_to into distinct_hop4_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop4_to);
            let q2 = meta.query_selector(q_hop4_to);
            let a = meta.query_advice(distinct_hop4_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            [one.clone(), b]
                .map(|c| c * q2.clone())
                .into_iter()
                .zip([one.clone(), a].map(|c| c * q1.clone()))
                .collect()
        });
        let distinct_hop4_to_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop4_to_order),
            |meta| vec![meta.query_advice(distinct_hop4_to, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop4_to, Rotation::next())],
        );
        let iz_distinct_hop4_to_zero = meta.advice_column();
        let distinct_hop4_to_check = meta.advice_column();
        let distinct_hop4_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop4_to_order),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(distinct_hop4_to, Rotation::cur())
                    - meta.query_advice(distinct_hop4_to, Rotation::next())
            },
            iz_distinct_hop4_to_zero,
            distinct_hop4_to_check,
        );
        meta.create_gate("distinct_hop4_to_order and uniqueness", |meta| {
            let q = meta.query_selector(q_distinct_hop4_to_order);
            let chk = meta.query_advice(distinct_hop4_to_check, Rotation::cur());
            let lte = distinct_hop4_to_order.is_lt(meta, None);
            vec![q.clone() * (lte - one.clone()), q.clone() * chk]
        });
        meta.shuffle("mark 4-hop friends in person table", |meta| {
            let q_dist_h4 = meta.query_selector(q_distinct_hop4_to);
            let q_pers_d4 = meta.query_selector(q_dist4_node);
            let id_dist_h4 = meta.query_advice(distinct_hop4_to, Rotation::cur());
            let id_pers = meta.query_advice(person[0], Rotation::cur());
            [one.clone(), id_pers]
                .map(|v| v * q_pers_d4.clone())
                .into_iter()
                .zip([one.clone(), id_dist_h4].map(|v| v * q_dist_h4.clone()))
                .collect()
        });
        meta.create_gate("calculate potential_friend_hop4", |meta| {
            let q = meta.query_selector(q_person);
            let d4 = meta.query_advice(dist4_node, Rotation::cur());
            let p_h3 = meta.query_advice(potential_friend_hop3, Rotation::cur());
            let p_h4 = meta.query_advice(potential_friend_hop4, Rotation::cur());
            vec![q.clone() * (p_h4 - (d4.clone() + p_h3.clone() - d4 * p_h3))]
        });

        Is1CircuitConfig {
            q_person,
            person,
            person_id,
            source_check,
            person_zero,
            person_knows_person,
            q_pkp,
            ordered_pkp,
            q_ordered_pkp_sort,
            ordered_pkp_person_id_sort_config,
            source_pkp_zero,
            dist1_pkp_check,
            source_pkp_to_zero,
            source_pkp_to_check,
            dist0_node,
            dist1_node,
            q_dist1_node,
            potential_friend_hop1,
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
            aligned_h1_pkp_personid,
            next_aligned_h1_pkp_personid,
            aligned_h1_pkp_personid_config,
            next_aligned_h1_pkp_personid_config,
            h1_match_flag_config,
            h1_match_flag,
            aligned_h1_pkp_to_personid,
            next_aligned_h1_pkp_to_personid,
            aligned_h1_pkp_to_personid_config,
            next_aligned_h1_pkp_to_personid_config,
            h1_pkp_to_flag_config,
            h1_pkp_to_flag,
            dist2_node,
            q_dist2_node,
            potential_friend_hop2,
            q_hop2_to,
            distinct_hop2_to,
            q_distinct_hop2_to,
            q_distinct_hop2_to_order,
            distinct_hop2_to_order,
            distinct_hop2_to_zero,
            distinct_hop2_to_check,
            distinct_hop2_to_ext,
            q_distinct_hop2_to_ext,
            q_distinct_hop2_to_ext_order,
            distinct_hop2_to_ext_order_config,
            q_distinct_hop2_to_ext_internal,
            q_distinct_hop2_to_ext_boundary,
            distinct_hop2_to_ext_pairs_lookup_table,
            q_distinct_hop2_to_ext_pairs_lookup,
            aligned_h2_pkp_personid,
            next_aligned_h2_pkp_personid,
            aligned_h2_pkp_personid_config,
            next_aligned_h2_pkp_personid_config,
            h2_match_flag_config,
            h2_match_flag,
            aligned_h2_pkp_to_personid,
            next_aligned_h2_pkp_to_personid,
            aligned_h2_pkp_to_personid_config,
            next_aligned_h2_pkp_to_personid_config,
            h2_pkp_to_flag_config,
            h2_pkp_to_flag,
            dist3_node,
            q_dist3_node,
            potential_friend_hop3,
            q_hop3_to,
            distinct_hop3_to,
            q_distinct_hop3_to,
            q_distinct_hop3_to_order,
            distinct_hop3_to_order,
            distinct_hop3_to_zero,
            distinct_hop3_to_check,
            distinct_hop3_to_ext,
            q_distinct_hop3_to_ext,
            q_distinct_hop3_to_ext_order,
            distinct_hop3_to_ext_order_config,
            q_distinct_hop3_to_ext_internal,
            q_distinct_hop3_to_ext_boundary,
            distinct_hop3_to_ext_pairs_lookup_table,
            q_distinct_hop3_to_ext_pairs_lookup,
            aligned_h3_pkp_personid,
            next_aligned_h3_pkp_personid,
            aligned_h3_pkp_personid_config,
            next_aligned_h3_pkp_personid_config,
            h3_match_flag_config,
            h3_match_flag,
            aligned_h3_pkp_to_personid,
            next_aligned_h3_pkp_to_personid,
            aligned_h3_pkp_to_personid_config,
            next_aligned_h3_pkp_to_personid_config,
            h3_pkp_to_flag_config,
            h3_pkp_to_flag,
            dist4_node,
            q_dist4_node,
            potential_friend_hop4,
            q_hop4_to,
            distinct_hop4_to,
            q_distinct_hop4_to,
            q_distinct_hop4_to_order,
            distinct_hop4_to_order,
            distinct_hop4_to_zero,
            distinct_hop4_to_check,
            instance,
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

        let person_zero_chip = IsZeroChip::construct(self.config.person_zero.clone());
        let ordered_pkp_person_id_sort_chip =
            LtEqGenericChip::construct(self.config.ordered_pkp_person_id_sort_config.clone());
        let source_pkp_zero_chip = IsZeroChip::construct(self.config.source_pkp_zero.clone());
        let source_pkp_to_zero_chip = IsZeroChip::construct(self.config.source_pkp_to_zero.clone());
        // H1
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
        // H2
        let distinct_hop2_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop2_to_order.clone());
        let distinct_hop2_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop2_to_zero.clone());
        let distinct_hop2_to_ext_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop2_to_ext_order_config.clone());
        let aligned_h2_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h2_pkp_personid_config.clone());
        let next_aligned_h2_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h2_pkp_personid_config.clone());
        let h2_match_flag_chip = IsZeroChip::construct(self.config.h2_match_flag_config.clone());
        let aligned_h2_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h2_pkp_to_personid_config.clone());
        let next_aligned_h2_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h2_pkp_to_personid_config.clone());
        let h2_pkp_to_flag_chip = IsZeroChip::construct(self.config.h2_pkp_to_flag_config.clone());
        // H3
        let distinct_hop3_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop3_to_order.clone());
        let distinct_hop3_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop3_to_zero.clone());
        // H4 (includes H3_ext and H3 alignment)
        let distinct_hop3_to_ext_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop3_to_ext_order_config.clone());
        let aligned_h3_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h3_pkp_personid_config.clone());
        let next_aligned_h3_pkp_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h3_pkp_personid_config.clone());
        let h3_match_flag_chip = IsZeroChip::construct(self.config.h3_match_flag_config.clone());
        let aligned_h3_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.aligned_h3_pkp_to_personid_config.clone());
        let next_aligned_h3_pkp_to_personid_chip =
            LtEqGenericChip::construct(self.config.next_aligned_h3_pkp_to_personid_config.clone());
        let h3_pkp_to_flag_chip = IsZeroChip::construct(self.config.h3_pkp_to_flag_config.clone());
        let distinct_hop4_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop4_to_order.clone());
        let distinct_hop4_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop4_to_zero.clone());

        ordered_pkp_person_id_sort_chip.load(layouter).unwrap();
        distinct_hop1_to_order_chip.load(layouter).unwrap();
        distinct_hop1_to_ext_order_chip.load(layouter).unwrap();
        aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop2_to_order_chip.load(layouter).unwrap();
        distinct_hop2_to_ext_order_chip.load(layouter).unwrap();
        aligned_h2_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h2_pkp_personid_chip.load(layouter).unwrap();
        aligned_h2_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h2_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop3_to_order_chip.load(layouter).unwrap();
        distinct_hop3_to_ext_order_chip.load(layouter).unwrap();
        aligned_h3_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h3_pkp_personid_chip.load(layouter).unwrap();
        aligned_h3_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h3_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop4_to_order_chip.load(layouter).unwrap();

        let max_hops = 4;
        let dummy_distance_u64: u64 = (max_hops + 1) as u64;
        let mut adj: HashMap<F, Vec<F>> = HashMap::new();
        for edge in &person_knows_person_input {
            adj.entry(edge[0]).or_default().push(edge[1]);
        }
        let mut distances: HashMap<F, u64> = HashMap::new();
        for p_row in &person_table {
            distances.insert(p_row[0], dummy_distance_u64);
        }
        let mut q_bfs: VecDeque<F> = VecDeque::new();
        if distances.contains_key(&person_id_val) {
            distances.insert(person_id_val, 0);
            q_bfs.push_back(person_id_val);
        } else {
            println!(
                "Warnung: BFS-Quell-Personen-ID {:?} nicht in person_table gefunden.",
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

        let mut hop1_friends_vec = Vec::new();
        for edge in &person_knows_person_input {
            if edge[0] == person_id_val
                && edge[1] != person_id_val
                && distances.get(&edge[1]).map_or(false, |&d| d == 1)
            {
                hop1_friends_vec.push(edge[1]);
            }
        }
        hop1_friends_vec.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop1_friends_vec.dedup();
        let distinct_hop1_to_table = hop1_friends_vec;
        let mut distinct_hop1_to_ext_values = vec![F::ZERO];
        distinct_hop1_to_ext_values.extend(distinct_hop1_to_table.iter().cloned());
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

        let mut hop2_friends_raw = Vec::new();
        for edge in &person_knows_person_input {
            let pkp_s = edge[0];
            let pkp_t = edge[1];
            if distinct_hop1_to_table.binary_search(&pkp_s).is_ok() &&
               pkp_t != person_id_val &&
               distinct_hop1_to_table.binary_search(&pkp_t).is_err() &&
               distances.get(&pkp_t).map_or(false, |&d| d == 2)
            {
                hop2_friends_raw.push(pkp_t);
            }
        }
        hop2_friends_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop2_friends_raw.dedup();
        let distinct_hop2_to_table = hop2_friends_raw;
        let mut distinct_hop2_to_ext_values = vec![F::ZERO];
        distinct_hop2_to_ext_values.extend(distinct_hop2_to_table.iter().cloned());
        distinct_hop2_to_ext_values.push(F::from(MAX_PERSON_ID));
        distinct_hop2_to_ext_values.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        distinct_hop2_to_ext_values.dedup();
        let mut distinct_hop2_to_ext_pairs_table = Vec::new();
        if distinct_hop2_to_ext_values.len() >= 2 {
            for i in 0..(distinct_hop2_to_ext_values.len() - 1) {
                distinct_hop2_to_ext_pairs_table.push((
                    distinct_hop2_to_ext_values[i],
                    distinct_hop2_to_ext_values[i + 1],
                ));
            }
        }

        let mut hop3_friends_raw = Vec::new();
        for edge in &person_knows_person_input {
            let pkp_s = edge[0];
            let pkp_t = edge[1];
            if distinct_hop2_to_table.binary_search(&pkp_s).is_ok() &&
               pkp_t != person_id_val &&
               distinct_hop1_to_table.binary_search(&pkp_t).is_err() &&
               distinct_hop2_to_table.binary_search(&pkp_t).is_err() &&
               distances.get(&pkp_t).map_or(false, |&d| d == 3)
            {
                hop3_friends_raw.push(pkp_t);
            }
        }
        hop3_friends_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop3_friends_raw.dedup();
        let distinct_hop3_to_table = hop3_friends_raw;
        let mut distinct_hop3_to_ext_values = vec![F::ZERO];
        distinct_hop3_to_ext_values.extend(distinct_hop3_to_table.iter().cloned());
        distinct_hop3_to_ext_values.push(F::from(MAX_PERSON_ID));
        distinct_hop3_to_ext_values.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        distinct_hop3_to_ext_values.dedup();
        let mut distinct_hop3_to_ext_pairs_table = Vec::new();
        if distinct_hop3_to_ext_values.len() >= 2 {
            for i in 0..(distinct_hop3_to_ext_values.len() - 1) {
                distinct_hop3_to_ext_pairs_table.push((
                    distinct_hop3_to_ext_values[i],
                    distinct_hop3_to_ext_values[i + 1],
                ));
            }
        }

        let mut hop4_friends_raw = Vec::new();
        for edge in &person_knows_person_input {
            let pkp_s = edge[0];
            let pkp_t = edge[1];
            if distinct_hop3_to_table.binary_search(&pkp_s).is_ok() &&
               pkp_t != person_id_val &&
               distinct_hop1_to_table.binary_search(&pkp_t).is_err() &&
               distinct_hop2_to_table.binary_search(&pkp_t).is_err() &&
               distinct_hop3_to_table.binary_search(&pkp_t).is_err() &&
               distances.get(&pkp_t).map_or(false, |&d| d == 4)
            {
                hop4_friends_raw.push(pkp_t);
            }
        }
        hop4_friends_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop4_friends_raw.dedup();
        let distinct_hop4_to_table = hop4_friends_raw;

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, p_row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;
                    for j in 0..8 {
                        region.assign_advice(
                            || format!("p{},r{}", j, i),
                            self.config.person[j],
                            i,
                            || Value::known(p_row[j]),
                        )?;
                    }
                    region.assign_advice(
                        || format!("pid_pr{}", i),
                        self.config.person_id,
                        i,
                        || Value::known(person_id_val),
                    )?;
                    let is_src = p_row[0] == person_id_val;
                    let src_chk_v = F::from(is_src as u64);
                    region.assign_advice(
                        || format!("src_chk_pr{}", i),
                        self.config.source_check,
                        i,
                        || Value::known(src_chk_v),
                    )?;
                    person_zero_chip
                        .assign(&mut region, i, Value::known(p_row[0] - person_id_val))
                        .unwrap();
                    let d = distances
                        .get(&p_row[0])
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    let (is_d0, is_d1, is_d2, is_d3, is_d4) =
                        (d == 0, d == 1, d == 2, d == 3, d == 4);
                    let (d0v, d1v, d2v, d3v, d4v) = (
                        F::from(is_d0 as u64),
                        F::from(is_d1 as u64),
                        F::from(is_d2 as u64),
                        F::from(is_d3 as u64),
                        F::from(is_d4 as u64),
                    );
                    region.assign_advice(
                        || format!("d0n{}", i),
                        self.config.dist0_node,
                        i,
                        || Value::known(d0v),
                    )?;
                    region.assign_advice(
                        || format!("d1n{}", i),
                        self.config.dist1_node,
                        i,
                        || Value::known(d1v),
                    )?;
                    region.assign_advice(
                        || format!("d2n{}", i),
                        self.config.dist2_node,
                        i,
                        || Value::known(d2v),
                    )?;
                    region.assign_advice(
                        || format!("d3n{}", i),
                        self.config.dist3_node,
                        i,
                        || Value::known(d3v),
                    )?;
                    region.assign_advice(
                        || format!("d4n{}", i),
                        self.config.dist4_node,
                        i,
                        || Value::known(d4v),
                    )?;
                    if is_d1 {
                        self.config.q_dist1_node.enable(&mut region, i)?;
                    }
                    if is_d2 {
                        self.config.q_dist2_node.enable(&mut region, i)?;
                    }
                    if is_d3 {
                        self.config.q_dist3_node.enable(&mut region, i)?;
                    }
                    if is_d4 {
                        self.config.q_dist4_node.enable(&mut region, i)?;
                    }
                    let pfh1v = if is_d0 || is_d1 { F::ONE } else { F::ZERO };
                    let pfh2v = if is_d0 || is_d1 || is_d2 {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    let pfh3v = if is_d0 || is_d1 || is_d2 || is_d3 {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    let pfh4v = if is_d0 || is_d1 || is_d2 || is_d3 || is_d4 {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("pfh1_{}", i),
                        self.config.potential_friend_hop1,
                        i,
                        || Value::known(pfh1v),
                    )?;
                    region.assign_advice(
                        || format!("pfh2_{}", i),
                        self.config.potential_friend_hop2,
                        i,
                        || Value::known(pfh2v),
                    )?;
                    region.assign_advice(
                        || format!("pfh3_{}", i),
                        self.config.potential_friend_hop3,
                        i,
                        || Value::known(pfh3v),
                    )?;
                    region.assign_advice(
                        || format!("pfh4_{}", i),
                        self.config.potential_friend_hop4,
                        i,
                        || Value::known(pfh4v),
                    )?;
                }

                for (i, edge) in ordered_pkp_table.iter().enumerate() {
                    self.config.q_pkp.enable(&mut region, i)?;
                    let (pkp_s, pkp_t) = (edge[0], edge[1]);
                    region.assign_advice(
                        || format!("pkps0r{}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(pkp_s),
                    )?;
                    region.assign_advice(
                        || format!("pkps1r{}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(pkp_t),
                    )?;
                    region.assign_advice(
                        || format!("opkp0r{}", i),
                        self.config.ordered_pkp[0],
                        i,
                        || Value::known(pkp_s),
                    )?;
                    region.assign_advice(
                        || format!("opkp1r{}", i),
                        self.config.ordered_pkp[1],
                        i,
                        || Value::known(pkp_t),
                    )?;
                    region.assign_advice(
                        || format!("pid_pkpr{}", i),
                        self.config.person_id,
                        i,
                        || Value::known(person_id_val),
                    )?;
                    if i < ordered_pkp_table.len() - 1 {
                        self.config.q_ordered_pkp_sort.enable(&mut region, i)?;
                        ordered_pkp_person_id_sort_chip
                            .assign(&mut region, i, &[pkp_t], &[ordered_pkp_table[i + 1][1]])
                            .unwrap();
                    }

                    let diff_src_pkp_s = pkp_s - person_id_val;
                    source_pkp_zero_chip
                        .assign(&mut region, i, Value::known(diff_src_pkp_s))
                        .unwrap();
                    let d1pkpc_v = if diff_src_pkp_s == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("d1pkpc_r{}", i),
                        self.config.dist1_pkp_check,
                        i,
                        || Value::known(d1pkpc_v),
                    )?;
                    if d1pkpc_v == F::ONE {
                        self.config.q_hop1_to.enable(&mut region, i)?;
                    }
                    let diff_src_pkp_t = pkp_t - person_id_val;
                    source_pkp_to_zero_chip
                        .assign(&mut region, i, Value::known(diff_src_pkp_t))
                        .unwrap();
                    let srcpkptc_v = if diff_src_pkp_t == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("srcpkptc_r{}", i),
                        self.config.source_pkp_to_check,
                        i,
                        || Value::known(srcpkptc_v),
                    )?;

                    let (ah1s, nah1s) = find_aligned_pair(&distinct_hop1_to_ext_values, pkp_s);
                    region.assign_advice(
                        || format!("ah1s{}", i),
                        self.config.aligned_h1_pkp_personid,
                        i,
                        || Value::known(ah1s),
                    )?;
                    region.assign_advice(
                        || format!("nah1s{}", i),
                        self.config.next_aligned_h1_pkp_personid,
                        i,
                        || Value::known(nah1s),
                    )?;
                    aligned_h1_pkp_personid_chip
                        .assign(&mut region, i, &[ah1s], &[pkp_s])
                        .unwrap();
                    next_aligned_h1_pkp_personid_chip
                        .assign(&mut region, i, &[pkp_s], &[nah1s - F::ONE])
                        .unwrap();
                    let diff_h1mfs = ah1s - pkp_s;
                    h1_match_flag_chip
                        .assign(&mut region, i, Value::known(diff_h1mfs))
                        .unwrap();
                    let h1mf_v = if diff_h1mfs == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h1mfv{}", i),
                        self.config.h1_match_flag,
                        i,
                        || Value::known(h1mf_v),
                    )?;
                    let (ah1t, nah1t) = find_aligned_pair(&distinct_hop1_to_ext_values, pkp_t);
                    region.assign_advice(
                        || format!("ah1t{}", i),
                        self.config.aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(ah1t),
                    )?;
                    region.assign_advice(
                        || format!("nah1t{}", i),
                        self.config.next_aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(nah1t),
                    )?;
                    aligned_h1_pkp_to_personid_chip
                        .assign(&mut region, i, &[ah1t], &[pkp_t])
                        .unwrap();
                    next_aligned_h1_pkp_to_personid_chip
                        .assign(&mut region, i, &[pkp_t], &[nah1t - F::ONE])
                        .unwrap();
                    let diff_h1pft = ah1t - pkp_t;
                    h1_pkp_to_flag_chip
                        .assign(&mut region, i, Value::known(diff_h1pft))
                        .unwrap();
                    let h1pft_v = if diff_h1pft == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h1pftv{}", i),
                        self.config.h1_pkp_to_flag,
                        i,
                        || Value::known(h1pft_v),
                    )?;
                    region.assign_advice(
                        || format!("ph_d1ext_s{}", i),
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(ah1s),
                    )?;
                    region.assign_advice(
                        || format!("ph_d1ext_t{}", i),
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(ah1t),
                    )?;

                    let en_qh2t_v = h1mf_v * (F::ONE - h1pft_v) * (F::ONE - srcpkptc_v);
                    if en_qh2t_v == F::ONE {
                        self.config.q_hop2_to.enable(&mut region, i)?;
                    }

                    let (ah2s, nah2s) = find_aligned_pair(&distinct_hop2_to_ext_values, pkp_s);
                    region.assign_advice(
                        || format!("ah2s{}", i),
                        self.config.aligned_h2_pkp_personid,
                        i,
                        || Value::known(ah2s),
                    )?;
                    region.assign_advice(
                        || format!("nah2s{}", i),
                        self.config.next_aligned_h2_pkp_personid,
                        i,
                        || Value::known(nah2s),
                    )?;
                    aligned_h2_pkp_personid_chip
                        .assign(&mut region, i, &[ah2s], &[pkp_s])
                        .unwrap();
                    next_aligned_h2_pkp_personid_chip
                        .assign(&mut region, i, &[pkp_s], &[nah2s - F::ONE])
                        .unwrap();
                    let diff_h2mfs = ah2s - pkp_s;
                    h2_match_flag_chip
                        .assign(&mut region, i, Value::known(diff_h2mfs))
                        .unwrap();
                    let h2mf_v = if diff_h2mfs == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h2mfv{}", i),
                        self.config.h2_match_flag,
                        i,
                        || Value::known(h2mf_v),
                    )?;
                    let (ah2t, nah2t) = find_aligned_pair(&distinct_hop2_to_ext_values, pkp_t);
                    region.assign_advice(
                        || format!("ah2t{}", i),
                        self.config.aligned_h2_pkp_to_personid,
                        i,
                        || Value::known(ah2t),
                    )?;
                    region.assign_advice(
                        || format!("nah2t{}", i),
                        self.config.next_aligned_h2_pkp_to_personid,
                        i,
                        || Value::known(nah2t),
                    )?;
                    aligned_h2_pkp_to_personid_chip
                        .assign(&mut region, i, &[ah2t], &[pkp_t])
                        .unwrap();
                    next_aligned_h2_pkp_to_personid_chip
                        .assign(&mut region, i, &[pkp_t], &[nah2t - F::ONE])
                        .unwrap();
                    let diff_h2pft = ah2t - pkp_t;
                    h2_pkp_to_flag_chip
                        .assign(&mut region, i, Value::known(diff_h2pft))
                        .unwrap();
                    let h2pft_v = if diff_h2pft == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h2pftv{}", i),
                        self.config.h2_pkp_to_flag,
                        i,
                        || Value::known(h2pft_v),
                    )?;
                    region.assign_advice(
                        || format!("ph_d2ext_s{}", i),
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(ah2s),
                    )?;
                    region.assign_advice(
                        || format!("ph_d2ext_t{}", i),
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(ah2t),
                    )?;

                    let en_qh3t_v =
                        h2mf_v * (F::ONE - srcpkptc_v) * (F::ONE - h1pft_v) * (F::ONE - h2pft_v);
                    if en_qh3t_v == F::ONE {
                        self.config.q_hop3_to.enable(&mut region, i)?;
                    }

                    let (ah3s, nah3s) = find_aligned_pair(&distinct_hop3_to_ext_values, pkp_s);
                    region.assign_advice(
                        || format!("ah3s{}", i),
                        self.config.aligned_h3_pkp_personid,
                        i,
                        || Value::known(ah3s),
                    )?;
                    region.assign_advice(
                        || format!("nah3s{}", i),
                        self.config.next_aligned_h3_pkp_personid,
                        i,
                        || Value::known(nah3s),
                    )?;
                    aligned_h3_pkp_personid_chip
                        .assign(&mut region, i, &[ah3s], &[pkp_s])
                        .unwrap();
                    next_aligned_h3_pkp_personid_chip
                        .assign(&mut region, i, &[pkp_s], &[nah3s - F::ONE])
                        .unwrap();
                    let diff_h3mfs = ah3s - pkp_s;
                    h3_match_flag_chip
                        .assign(&mut region, i, Value::known(diff_h3mfs))
                        .unwrap();
                    let h3mf_v = if diff_h3mfs == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h3mfv{}", i),
                        self.config.h3_match_flag,
                        i,
                        || Value::known(h3mf_v),
                    )?;
                    let (ah3t, nah3t) = find_aligned_pair(&distinct_hop3_to_ext_values, pkp_t);
                    region.assign_advice(
                        || format!("ah3t{}", i),
                        self.config.aligned_h3_pkp_to_personid,
                        i,
                        || Value::known(ah3t),
                    )?;
                    region.assign_advice(
                        || format!("nah3t{}", i),
                        self.config.next_aligned_h3_pkp_to_personid,
                        i,
                        || Value::known(nah3t),
                    )?;
                    aligned_h3_pkp_to_personid_chip
                        .assign(&mut region, i, &[ah3t], &[pkp_t])
                        .unwrap();
                    next_aligned_h3_pkp_to_personid_chip
                        .assign(&mut region, i, &[pkp_t], &[nah3t - F::ONE])
                        .unwrap();
                    let diff_h3pft = ah3t - pkp_t;
                    h3_pkp_to_flag_chip
                        .assign(&mut region, i, Value::known(diff_h3pft))
                        .unwrap();
                    let h3pft_v = if diff_h3pft == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h3pftv{}", i),
                        self.config.h3_pkp_to_flag,
                        i,
                        || Value::known(h3pft_v),
                    )?;
                    region.assign_advice(
                        || format!("ph_d3ext_s{}", i),
                        self.config.distinct_hop3_to_ext,
                        i,
                        || Value::known(ah3s),
                    )?;
                    region.assign_advice(
                        || format!("ph_d3ext_t{}", i),
                        self.config.distinct_hop3_to_ext,
                        i,
                        || Value::known(ah3t),
                    )?;

                    let en_qh4t_v = h3mf_v
                        * (F::ONE - srcpkptc_v)
                        * (F::ONE - h1pft_v)
                        * (F::ONE - h2pft_v)
                        * (F::ONE - h3pft_v);
                    if en_qh4t_v == F::ONE {
                        self.config.q_hop4_to.enable(&mut region, i)?;
                    }
                }

                fn find_aligned_pair<F: Field + Ord>(ext_values: &[F], val_to_search: F) -> (F, F) {
                    let mut aligned_val = F::ZERO;
                    let mut next_aligned_val = F::from(MAX_PERSON_ID);
                    match ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&val_to_search)))
                    {
                        Ok(idx) => {
                            aligned_val = ext_values[idx];
                            if idx + 1 < ext_values.len() {
                                next_aligned_val = ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val = ext_values[idx - 1];
                            }
                            if idx < ext_values.len() {
                                next_aligned_val = ext_values[idx];
                            }
                        }
                    }
                    (aligned_val, next_aligned_val)
                }

                for (i, &id) in distinct_hop1_to_table.iter().enumerate() {
                    self.config.q_distinct_hop1_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d1t{}", i),
                        self.config.distinct_hop1_to,
                        i,
                        || Value::known(id),
                    )?;
                    if i < distinct_hop1_to_table.len() - 1 {
                        let next_id = distinct_hop1_to_table[i + 1];
                        self.config
                            .q_distinct_hop1_to_order
                            .enable(&mut region, i)?;
                        distinct_hop1_to_order_chip
                            .assign(&mut region, i, &[id], &[next_id])
                            .unwrap();
                        let diff = id - next_id;
                        distinct_hop1_to_zero_chip
                            .assign(&mut region, i, Value::known(diff))
                            .unwrap();
                        let chk_v = if diff == F::ZERO { F::ONE } else { F::ZERO };
                        region.assign_advice(
                            || format!("d1tc{}", i),
                            self.config.distinct_hop1_to_check,
                            i,
                            || Value::known(chk_v),
                        )?;
                    }
                }
                for (i, &id) in distinct_hop1_to_ext_values.iter().enumerate() {
                    self.config.q_distinct_hop1_to_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d1e{}", i),
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(id),
                    )?;
                    if id == F::ZERO || id == F::from(MAX_PERSON_ID) {
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
                            .assign(&mut region, i, &[id], &[distinct_hop1_to_ext_values[i + 1]])
                            .unwrap();
                    }
                }
                for (i, &(p1, p2)) in distinct_hop1_to_ext_pairs_table.iter().enumerate() {
                    self.config
                        .q_distinct_hop1_to_ext_pairs_lookup
                        .enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d1ep0_{}", i),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(p1),
                    )?;
                    region.assign_advice(
                        || format!("d1ep1_{}", i),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(p2),
                    )?;
                }

                for (i, &id) in distinct_hop2_to_table.iter().enumerate() {
                    self.config.q_distinct_hop2_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d2t{}", i),
                        self.config.distinct_hop2_to,
                        i,
                        || Value::known(id),
                    )?;
                    if i < distinct_hop2_to_table.len() - 1 {
                        let next_id = distinct_hop2_to_table[i + 1];
                        self.config
                            .q_distinct_hop2_to_order
                            .enable(&mut region, i)?;
                        distinct_hop2_to_order_chip
                            .assign(&mut region, i, &[id], &[next_id])
                            .unwrap();
                        let diff = id - next_id;
                        distinct_hop2_to_zero_chip
                            .assign(&mut region, i, Value::known(diff))
                            .unwrap();
                        let chk_v = if diff == F::ZERO { F::ONE } else { F::ZERO };
                        region.assign_advice(
                            || format!("d2tc{}", i),
                            self.config.distinct_hop2_to_check,
                            i,
                            || Value::known(chk_v),
                        )?;
                    }
                }
                for (i, &id) in distinct_hop2_to_ext_values.iter().enumerate() {
                    self.config.q_distinct_hop2_to_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d2e{}", i),
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(id),
                    )?;
                    if id == F::ZERO || id == F::from(MAX_PERSON_ID) {
                        self.config
                            .q_distinct_hop2_to_ext_boundary
                            .enable(&mut region, i)?;
                    } else {
                        self.config
                            .q_distinct_hop2_to_ext_internal
                            .enable(&mut region, i)?;
                    }
                    if i < distinct_hop2_to_ext_values.len() - 1 {
                        self.config
                            .q_distinct_hop2_to_ext_order
                            .enable(&mut region, i)?;
                        distinct_hop2_to_ext_order_chip
                            .assign(&mut region, i, &[id], &[distinct_hop2_to_ext_values[i + 1]])
                            .unwrap();
                    }
                }
                for (i, &(p1, p2)) in distinct_hop2_to_ext_pairs_table.iter().enumerate() {
                    self.config
                        .q_distinct_hop2_to_ext_pairs_lookup
                        .enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d2ep0_{}", i),
                        self.config.distinct_hop2_to_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(p1),
                    )?;
                    region.assign_advice(
                        || format!("d2ep1_{}", i),
                        self.config.distinct_hop2_to_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(p2),
                    )?;
                }

                for (i, &id) in distinct_hop3_to_table.iter().enumerate() {
                    self.config.q_distinct_hop3_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d3t{}", i),
                        self.config.distinct_hop3_to,
                        i,
                        || Value::known(id),
                    )?;
                    if i < distinct_hop3_to_table.len() - 1 {
                        let next_id = distinct_hop3_to_table[i + 1];
                        self.config
                            .q_distinct_hop3_to_order
                            .enable(&mut region, i)?;
                        distinct_hop3_to_order_chip
                            .assign(&mut region, i, &[id], &[next_id])
                            .unwrap();
                        let diff = id - next_id;
                        distinct_hop3_to_zero_chip
                            .assign(&mut region, i, Value::known(diff))
                            .unwrap();
                        let chk_v = if diff == F::ZERO { F::ONE } else { F::ZERO };
                        region.assign_advice(
                            || format!("d3tc{}", i),
                            self.config.distinct_hop3_to_check,
                            i,
                            || Value::known(chk_v),
                        )?;
                    }
                }
                for (i, &id) in distinct_hop3_to_ext_values.iter().enumerate() {
                    self.config.q_distinct_hop3_to_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d3e{}", i),
                        self.config.distinct_hop3_to_ext,
                        i,
                        || Value::known(id),
                    )?;
                    if id == F::ZERO || id == F::from(MAX_PERSON_ID) {
                        self.config
                            .q_distinct_hop3_to_ext_boundary
                            .enable(&mut region, i)?;
                    } else {
                        self.config
                            .q_distinct_hop3_to_ext_internal
                            .enable(&mut region, i)?;
                    }
                    if i < distinct_hop3_to_ext_values.len() - 1 {
                        self.config
                            .q_distinct_hop3_to_ext_order
                            .enable(&mut region, i)?;
                        distinct_hop3_to_ext_order_chip
                            .assign(&mut region, i, &[id], &[distinct_hop3_to_ext_values[i + 1]])
                            .unwrap();
                    }
                }
                for (i, &(p1, p2)) in distinct_hop3_to_ext_pairs_table.iter().enumerate() {
                    self.config
                        .q_distinct_hop3_to_ext_pairs_lookup
                        .enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d3ep0_{}", i),
                        self.config.distinct_hop3_to_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(p1),
                    )?;
                    region.assign_advice(
                        || format!("d3ep1_{}", i),
                        self.config.distinct_hop3_to_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(p2),
                    )?;
                }
                for (i, &id) in distinct_hop4_to_table.iter().enumerate() {
                    self.config.q_distinct_hop4_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d4t{}", i),
                        self.config.distinct_hop4_to,
                        i,
                        || Value::known(id),
                    )?;
                    if i < distinct_hop4_to_table.len() - 1 {
                        let next_id = distinct_hop4_to_table[i + 1];
                        self.config
                            .q_distinct_hop4_to_order
                            .enable(&mut region, i)?;
                        distinct_hop4_to_order_chip
                            .assign(&mut region, i, &[id], &[next_id])
                            .unwrap();
                        let diff = id - next_id;
                        distinct_hop4_to_zero_chip
                            .assign(&mut region, i, Value::known(diff))
                            .unwrap();
                        let chk_v = if diff == F::ZERO { F::ONE } else { F::ZERO };
                        region.assign_advice(
                            || format!("d4tc{}", i),
                            self.config.distinct_hop4_to_check,
                            i,
                            || Value::known(chk_v),
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
            &mut layouter.namespace(|| "Assign full circuit 4hop"),
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
