use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
// use crate::data::csr::CsrValue; // Nicht verwendet, kann entfernt werden
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque}; // BTreeSet, HashSet, VecDeque nicht explizit im Code verwendet, aber gut für Vorverarbeitung
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_BYTES: usize = 6;
const MAX_PERSON_ID: u64 = 100000000000000;

/*
MATCH path = shortestPath((p)-[:KNOWS*1..3]->(friend))
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

    // --- Hop 1 Alignment ---
    aligned_h1_pkp_personid: Column<Advice>, // Aligned source of PKP edge with distinct_hop1_to_ext
    next_aligned_h1_pkp_personid: Column<Advice>,
    aligned_h1_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h1_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h1_match_flag_config: crate::chips::is_zero::IsZeroConfig<F>, // Is PKP source a 1-hop friend?
    h1_match_flag: Column<Advice>,

    aligned_h1_pkp_to_personid: Column<Advice>, // Aligned target of PKP edge with distinct_hop1_to_ext
    next_aligned_h1_pkp_to_personid: Column<Advice>,
    aligned_h1_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h1_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h1_pkp_to_flag_config: crate::chips::is_zero::IsZeroConfig<F>, // Is PKP target a 1-hop friend?
    h1_pkp_to_flag: Column<Advice>,

    // --- Hop 0 & 1 States ---
    potential_friend_hop1: Column<Advice>, // Reachable in 0 or 1 hop
    dist0_node: Column<Advice>,            // Is node the source?
    dist1_node: Column<Advice>,            // Is node 1-hop from source?
    q_dist1_node: Selector,

    source_pkp_zero: crate::chips::is_zero::IsZeroConfig<F>, // PKP source == person_id?
    dist1_pkp_check: Column<Advice>,                         // Flag if PKP source == person_id

    source_pkp_to_zero: crate::chips::is_zero::IsZeroConfig<F>, // PKP target == person_id?
    source_pkp_to_check: Column<Advice>,                        // Flag if PKP target == person_id

    // --- Distinct 1-Hop Friends ---
    q_hop1_to: Selector, // Selector for edges leading to 1-hop friends
    distinct_hop1_to: Column<Advice>,
    q_distinct_hop1_to: Selector,
    q_distinct_hop1_to_order: Selector,
    distinct_hop1_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop1_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop1_to_check: Column<Advice>,

    // --- Extended Distinct 1-Hop Friends (for alignment) ---
    distinct_hop1_to_ext: Column<Advice>,
    q_distinct_hop1_to_ext: Selector,
    q_distinct_hop1_to_ext_order: Selector,
    distinct_hop1_to_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_distinct_hop1_to_ext_internal: Selector,
    q_distinct_hop1_to_ext_boundary: Selector,
    distinct_hop1_to_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_distinct_hop1_to_ext_pairs_lookup: Selector,

    // --- Hop 2 States & Distinct Friends ---
    potential_friend_hop2: Column<Advice>, // Reachable in 0, 1, or 2 hops
    dist2_node: Column<Advice>,            // Is node 2-hops from source?
    q_dist2_node: Selector,
    q_hop2_to: Selector, // Selector for edges leading to 2-hop friends
    distinct_hop2_to: Column<Advice>,
    q_distinct_hop2_to: Selector,
    q_distinct_hop2_to_order: Selector,
    distinct_hop2_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop2_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop2_to_check: Column<Advice>,

    // --- Hop 3 Additions START ---
    // --- Extended Distinct 2-Hop Friends (for alignment for Hop 3) ---
    distinct_hop2_to_ext: Column<Advice>,
    q_distinct_hop2_to_ext: Selector,
    q_distinct_hop2_to_ext_order: Selector,
    distinct_hop2_to_ext_order_config: LtEqGenericConfig<F, NUM_BYTES>,
    q_distinct_hop2_to_ext_internal: Selector,
    q_distinct_hop2_to_ext_boundary: Selector,
    distinct_hop2_to_ext_pairs_lookup_table: Vec<Column<Advice>>,
    q_distinct_hop2_to_ext_pairs_lookup: Selector,

    // --- Hop 2 Alignment (for PKP edges to determine if source/target is a 2-hop friend) ---
    aligned_h2_pkp_personid: Column<Advice>, // Aligned source of PKP edge with distinct_hop2_to_ext
    next_aligned_h2_pkp_personid: Column<Advice>,
    aligned_h2_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h2_pkp_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h2_match_flag_config: crate::chips::is_zero::IsZeroConfig<F>, // Is PKP source a 2-hop friend?
    h2_match_flag: Column<Advice>,

    aligned_h2_pkp_to_personid: Column<Advice>, // Aligned target of PKP edge with distinct_hop2_to_ext
    next_aligned_h2_pkp_to_personid: Column<Advice>,
    aligned_h2_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    next_aligned_h2_pkp_to_personid_config: LtEqGenericConfig<F, NUM_BYTES>,
    h2_pkp_to_flag_config: crate::chips::is_zero::IsZeroConfig<F>, // Is PKP target a 2-hop friend?
    h2_pkp_to_flag: Column<Advice>,

    // --- Hop 3 States & Distinct Friends ---
    potential_friend_hop3: Column<Advice>, // Reachable in 0, 1, 2, or 3 hops
    dist3_node: Column<Advice>,            // Is node 3-hops from source?
    q_dist3_node: Selector,
    q_hop3_to: Selector, // Selector for edges leading to 3-hop friends
    distinct_hop3_to: Column<Advice>,
    q_distinct_hop3_to: Selector,
    q_distinct_hop3_to_order: Selector,
    distinct_hop3_to_order: LtEqGenericConfig<F, NUM_BYTES>,
    distinct_hop3_to_zero: crate::chips::is_zero::IsZeroConfig<F>,
    distinct_hop3_to_check: Column<Advice>,
    // --- Hop 3 Additions END ---
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
            source_check, // Output of IsZeroChip is 1 if input is 0, 0 otherwise. Here it checks if person[0] == person_id
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
            // Ensure that (1,a,b) is a permutation of (1,c,d) when q is active
            // This is a common way to express that the set of (a,b) pairs is the same as (c,d) pairs under q
            let lhs = [one.clone(), a, b].map(|val| val * q.clone());
            let rhs = [one.clone(), c, d].map(|val| val * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_ordered_pkp_sort = meta.complex_selector();
        let ordered_pkp_person_id_sort_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_ordered_pkp_sort),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())], // cur.PersonToId
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::next())], // next.PersonToId
        );
        meta.create_gate("verify ordered_pkp sort by PersonToId", |meta| {
            let q = meta.query_selector(q_ordered_pkp_sort);
            // Constraint: q * (is_lt - 1) == 0  => if q is active, then is_lt must be 1.
            // is_lt is 1 if cur.PersonToId <= next.PersonToId.
            // So, this gate enforces that ordered_pkp is sorted by PersonToId in ascending order.
            vec![
                q.clone()
                    * (ordered_pkp_person_id_sort_config.is_lt(meta, None)
                        - Expression::Constant(F::ONE)),
            ]
        });

        let dist0_node = meta.advice_column();
        meta.create_gate("init_h0_states", |meta| {
            let q = meta.query_selector(q_person);
            let source_is_this_person = meta.query_advice(source_check, Rotation::cur()); // 1 if person[0] == person_id, 0 otherwise
            let current_node_is_dist0 = meta.query_advice(dist0_node, Rotation::cur());
            // Constraint: q * (current_node_is_dist0 - source_is_this_person) == 0
            // If q is active, dist0_node must be equal to source_check.
            // So, dist0_node is 1 if this person is the source, 0 otherwise.
            vec![q.clone() * (current_node_is_dist0 - source_is_this_person.clone())]
        });

        // ---------------------------
        // hop 1: Find friends of the source person
        // ---------------------------
        let iz_source_pkp_zero = meta.advice_column();
        let dist1_pkp_check = meta.advice_column(); // Flag: 1 if ordered_pkp[0] == person_id, 0 otherwise
        let source_pkp_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp), // Active for each row in ordered_pkp
            |meta: &mut VirtualCells<'_, F>| {
                // Input expression for IsZeroChip
                meta.query_advice(ordered_pkp[0], Rotation::cur()) // pkp.FromId
                    - meta.query_advice(person_id, Rotation::cur()) // source_person_id (constant for all pkp rows)
            },
            iz_source_pkp_zero, // Internal advice for IsZeroChip
            dist1_pkp_check, // Output advice: 1 if (pkp.FromId - source_person_id) is zero, 0 otherwise
        );

        let iz_source_pkp_to_zero = meta.advice_column();
        let source_pkp_to_check = meta.advice_column(); // Flag: 1 if ordered_pkp[1] (pkp.ToId) == person_id
        let source_pkp_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(ordered_pkp[1], Rotation::cur()) // pkp.ToId
                    - meta.query_advice(person_id, Rotation::cur()) // source_person_id
            },
            iz_source_pkp_to_zero,
            source_pkp_to_check,
        );

        let q_hop1_to = meta.complex_selector();
        meta.create_gate("set_q_hop1_to_selector", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_hop1_to_val = meta.query_selector(q_hop1_to);
            let pkp_from_is_source = meta.query_advice(dist1_pkp_check, Rotation::cur()); // 1 if pkp.FromId == source_id
                                                                                          // Constraint: q_pkp_active * (q_hop1_to_val - pkp_from_is_source) == 0
                                                                                          // If q_pkp is active, q_hop1_to selector is enabled if and only if pkp.FromId is the source_id.
                                                                                          // This selector identifies edges originating from the source person.
            vec![q_pkp_active.clone() * (q_hop1_to_val - pkp_from_is_source)]
        });

        let distinct_hop1_to = meta.advice_column(); // Stores unique 1-hop friends
        let q_distinct_hop1_to = meta.complex_selector(); // Selector for rows in distinct_hop1_to table
        let q_distinct_hop1_to_order = meta.selector(); // Selector for ordering check of distinct_hop1_to

        // Shuffle to ensure distinct_hop1_to contains exactly the ToId's from pkp where q_hop1_to is active
        meta.lookup_any("distinct_hop1_to from pkp.ToId where q_hop1_to", |meta| {
            let q_distinct_active = meta.query_selector(q_distinct_hop1_to);
            let q_pkp_hop1_edge_active = meta.query_selector(q_hop1_to); // Active if pkp.FromId == source_id
            let distinct_friend = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let pkp_target_node = meta.query_advice(ordered_pkp[1], Rotation::cur()); // pkp.ToId
                                                                                      // (1, distinct_friend) looked up in (1, pkp_target_node)
            let lhs = [one.clone(), distinct_friend].map(|val| val * q_distinct_active.clone());
            let rhs =
                [one.clone(), pkp_target_node].map(|val| val * q_pkp_hop1_edge_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        // And the reverse lookup to ensure completeness (all pkp.ToId where q_hop1_to is active are in distinct_hop1_to)
        meta.lookup_any("pkp.ToId where q_hop1_to into distinct_hop1_to", |meta| {
            let q_distinct_active = meta.query_selector(q_distinct_hop1_to);
            let q_pkp_hop1_edge_active = meta.query_selector(q_hop1_to);
            let distinct_friend = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let pkp_target_node = meta.query_advice(ordered_pkp[1], Rotation::cur());
            // (1, pkp_target_node) looked up in (1, distinct_friend)
            let lhs =
                [one.clone(), pkp_target_node].map(|val| val * q_pkp_hop1_edge_active.clone());
            let rhs = [one.clone(), distinct_friend].map(|val| val * q_distinct_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let distinct_hop1_to_order = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_order), // Active for rows in distinct_hop1_to (except last)
            |meta| vec![meta.query_advice(distinct_hop1_to, Rotation::cur())], // current distinct friend
            |meta| vec![meta.query_advice(distinct_hop1_to, Rotation::next())], // next distinct friend
        );

        let iz_distinct_hop1_to_zero = meta.advice_column();
        let distinct_hop1_to_check = meta.advice_column(); // Flag: 1 if cur_friend == next_friend, 0 otherwise
        let distinct_hop1_to_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_order),
            |meta: &mut VirtualCells<'_, F>| {
                // Input: cur_friend - next_friend
                meta.query_advice(distinct_hop1_to, Rotation::cur())
                    - meta.query_advice(distinct_hop1_to, Rotation::next())
            },
            iz_distinct_hop1_to_zero,
            distinct_hop1_to_check,
        );

        meta.create_gate("distinct_hop1_to_order and uniqueness", |meta| {
            let q_order_active = meta.query_selector(q_distinct_hop1_to_order);
            let cur_eq_next_flag = meta.query_advice(distinct_hop1_to_check, Rotation::cur()); // 1 if cur == next
            let cur_lte_next_flag = distinct_hop1_to_order.is_lt(meta, None); // 1 if cur <= next

            // Constraint 1: q_order_active * (cur_lte_next_flag - 1) == 0
            // Enforces sorted order: distinct_hop1_to[i] <= distinct_hop1_to[i+1]
            // Constraint 2: q_order_active * cur_eq_next_flag == 0
            // Enforces uniqueness: distinct_hop1_to[i] != distinct_hop1_to[i+1]
            // (If they were equal, cur_eq_next_flag would be 1, making the constraint fail unless q_order_active is 0)
            // This should be: q * (1 - cur_eq_next_flag) * (cur_lte_next_flag - Expression::Constant(F::ONE)) if we want to combine.
            // Or, more simply, if sorted distinct_hop1_to[i] < distinct_hop1_to[i+1].
            // The original code has: q.clone() * check. If check is 1 (meaning cur == next), constraint fails.
            // This enforces distinct_hop1_to[i] != distinct_hop1_to[i+1].
            // Combined with LtEqGenericChip (which enforces <=), this implies distinct_hop1_to[i] < distinct_hop1_to[i+1].
            vec![
                q_order_active.clone() * (cur_lte_next_flag - one.clone()), // Ensures sorted: cur <= next
                q_order_active.clone() * cur_eq_next_flag.clone(), // Ensures uniqueness: cur != next (check is 1 if cur == next)
            ]
        });

        let potential_friend_hop1 = meta.advice_column(); // 1 if person is reachable in 0 or 1 hop
        let dist1_node = meta.advice_column(); // 1 if person is exactly 1 hop away
        let q_dist1_node = meta.complex_selector(); // Selector for rows in person table that are 1-hop friends

        meta.create_gate("init_h1_states", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let dist1_node_assigned_val = meta.query_advice(dist1_node, Rotation::cur());
            let q_dist1_node_selector_val = meta.query_selector(q_dist1_node);
            // Constraint: q_person_active * (dist1_node_assigned_val - q_dist1_node_selector_val) == 0
            // Enforces that dist1_node column gets its value from the q_dist1_node selector.
            // q_dist1_node will be enabled for persons who are 1-hop friends via shuffle.
            vec![q_person_active.clone() * (dist1_node_assigned_val - q_dist1_node_selector_val)]
        });

        // Shuffle to connect distinct 1-hop friends to the person table (person[0])
        // This enables q_dist1_node for persons who are in distinct_hop1_to.
        meta.shuffle("mark 1-hop friends in person table", |meta| {
            let q_distinct_h1_active = meta.query_selector(q_distinct_hop1_to); // Source: distinct_hop1_to table
            let q_person_dist1_active = meta.query_selector(q_dist1_node); // Target: person table, q_dist1_node selector
            let friend_id_from_distinct = meta.query_advice(distinct_hop1_to, Rotation::cur());
            let person_id_from_person_table = meta.query_advice(person[0], Rotation::cur());
            // (1, person_id_from_person_table) is a permutation of (1, friend_id_from_distinct)
            // when respective selectors are active.
            let lhs = [one.clone(), person_id_from_person_table]
                .map(|val| val * q_person_dist1_active.clone());
            let rhs = [one.clone(), friend_id_from_distinct]
                .map(|val| val * q_distinct_h1_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("calculate potential_friend_hop1", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let d1 = meta.query_advice(dist1_node, Rotation::cur()); // Is 1-hop friend?
            let d0 = meta.query_advice(dist0_node, Rotation::cur()); // Is source?
            let potential_h1 = meta.query_advice(potential_friend_hop1, Rotation::cur());
            // Constraint: q_person_active * (potential_h1 - (d1 + d0 - d1*d0)) == 0
            // potential_h1 = d0 OR d1 (boolean logic: 1 - (1-d0)(1-d1))
            // This sets potential_friend_hop1 to 1 if the person is the source OR a 1-hop friend.
            vec![q_person_active.clone() * (potential_h1 - (d1.clone() + d0.clone() - d1 * d0))]
        });

        // --- hop1_ext: Padded and sorted list of 1-hop friends for alignment lookups ---
        let distinct_hop1_to_ext = meta.advice_column(); // Stores 0, MAX_PERSON_ID, and distinct 1-hop friends, sorted.
        meta.enable_equality(distinct_hop1_to_ext);
        let q_distinct_hop1_to_ext = meta.complex_selector(); // Selector for rows in distinct_hop1_to_ext table
        let q_distinct_hop1_to_ext_order = meta.complex_selector(); // For ordering check
        let q_distinct_hop1_to_ext_internal = meta.complex_selector(); // For internal (actual friend ID) rows
        let q_distinct_hop1_to_ext_boundary = meta.complex_selector(); // For 0 and MAX_PERSON_ID rows

        let distinct_hop1_to_ext_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_distinct_hop1_to_ext_order),
            |meta| vec![meta.query_advice(distinct_hop1_to_ext, Rotation::cur())],
            |meta| vec![meta.query_advice(distinct_hop1_to_ext, Rotation::next())],
        );
        meta.create_gate("distinct_hop1_to_ext order check", |meta| {
            let q = meta.query_selector(q_distinct_hop1_to_ext_order);
            // Enforces distinct_hop1_to_ext[i] <= distinct_hop1_to_ext[i+1]
            vec![q * (distinct_hop1_to_ext_order_config.is_lt(meta, None) - one.clone())]
        });

        // Shuffle from `distinct_hop1_to` (unique friend IDs) to the internal part of `distinct_hop1_to_ext`
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
            // Constraint: q_boundary_active * current_val * (current_val - MAX_PERSON_ID) == 0
            // If q_boundary_active is 1, then current_val must be 0 or MAX_PERSON_ID.
            vec![
                q_boundary_active
                    * current_val.clone()
                    * (current_val - Expression::Constant(F::from(MAX_PERSON_ID))),
            ]
        });

        meta.create_gate("distinct_hop1_to_ext selector logic", |meta| {
            let q_ext_row_active = meta.query_selector(q_distinct_hop1_to_ext); // Active for any row in ext table
            let q_internal_part_active = meta.query_selector(q_distinct_hop1_to_ext_internal);
            let q_boundary_part_active = meta.query_selector(q_distinct_hop1_to_ext_boundary);
            // Constraint: q_ext_row_active * (q_internal_part_active + q_boundary_part_active - 1) == 0
            // If a row in ext table is active, it must be either internal or boundary, but not both.
            // (Ensures q_internal + q_boundary = 1 if q_ext is active)
            vec![q_ext_row_active * (q_internal_part_active + q_boundary_part_active - one.clone())]
        });

        let mut distinct_hop1_to_ext_pairs_lookup_table = Vec::new(); // Stores (val_i, val_{i+1}) from distinct_hop1_to_ext
        for _ in 0..2 {
            distinct_hop1_to_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(distinct_hop1_to_ext_pairs_lookup_table[i]);
        }
        let q_distinct_hop1_to_ext_pairs_lookup = meta.complex_selector(); // Selector for this pairs table

        // --- Alignment columns for pkp.FromId (ordered_pkp[0]) against distinct_hop1_to_ext ---
        let aligned_h1_pkp_personid = meta.advice_column(); // lower_bound(pkp.FromId) in distinct_hop1_to_ext
        let next_aligned_h1_pkp_personid = meta.advice_column(); // upper_bound(pkp.FromId) in distinct_hop1_to_ext

        // Lookup to ensure aligned_h1_pkp_personid is a value from distinct_hop1_to_ext table
        meta.lookup_any(
            "aligned_h1_pkp_personid is from distinct_hop1_to_ext",
            |meta| {
                let q_pkp_row_active = meta.query_selector(q_pkp); // Active for each pkp row
                let q_ext_table_active = meta.query_selector(q_distinct_hop1_to_ext); // Active for each row in ext table
                let val_to_check = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop1_to_ext, Rotation::cur());
                // (1, val_to_check) looked up in (1, val_in_ext_table)
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_row_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                // Note: This lookup should be constrained by q_pkp_row_active on LHS and q_distinct_hop1_to_ext on RHS.
                // The original code uses q_pkp for both, which is unusual.
                // Correct way:
                // lhs: [one.clone() * q_pkp_row_active.clone(), val_to_check * q_pkp_row_active.clone()]
                // rhs: [one.clone() * q_ext_table_active.clone(), val_in_ext_table * q_ext_table_active.clone()]
                // Sticking to original pattern for now:
                lhs.into_iter().zip(rhs).collect()
            },
        );
        // Lookup for next_aligned_h1_pkp_personid (similar to above)
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

        // Config to check: aligned_h1_pkp_personid <= ordered_pkp[0]
        let aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(aligned_h1_pkp_personid, Rotation::cur())], // aligned_val
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())],          // pkp.FromId
        );
        meta.create_gate("aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            // Enforces aligned_val <= pkp.FromId
            vec![q * (aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        // Config to check: ordered_pkp[0] < next_aligned_h1_pkp_personid  (i.e. ordered_pkp[0] <= next_aligned_h1_pkp_personid - 1)
        let next_aligned_h1_pkp_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[0], Rotation::cur())], // pkp.FromId
            |meta| {
                // next_aligned_val - 1
                vec![meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur()) - one.clone()]
            },
        );
        meta.create_gate("next_aligned_h1_pkp_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            // Enforces pkp.FromId <= next_aligned_val - 1  (meaning pkp.FromId < next_aligned_val)
            vec![q * (next_aligned_h1_pkp_personid_config.is_lt(meta, None) - one.clone())]
        });

        // Lookup to ensure (aligned_h1_pkp_personid, next_aligned_h1_pkp_personid) is a consecutive pair from distinct_hop1_to_ext_pairs_lookup_table
        meta.lookup_any("aligned_h1_pkp_personid pair lookup", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_pairs_table_active = meta.query_selector(q_distinct_hop1_to_ext_pairs_lookup);
            let aligned_val = meta.query_advice(aligned_h1_pkp_personid, Rotation::cur());
            let next_aligned_val = meta.query_advice(next_aligned_h1_pkp_personid, Rotation::cur());
            let pair_first =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[0], Rotation::cur());
            let pair_second =
                meta.query_advice(distinct_hop1_to_ext_pairs_lookup_table[1], Rotation::cur());
            // (1, aligned_val, next_aligned_val) looked up in (1, pair_first, pair_second)
            let lhs =
                [one.clone(), aligned_val, next_aligned_val].map(|v| v * q_pkp_active.clone());
            let rhs =
                [one.clone(), pair_first, pair_second].map(|v| v * q_pairs_table_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        // --- h1_match_flag: Is ordered_pkp[0] (pkp.FromId) a 1-hop friend? ---
        // This flag is 1 if aligned_h1_pkp_personid == ordered_pkp[0]
        let h1_match_flag = meta.advice_column();
        let iz_h1_match_flag = meta.advice_column();
        let h1_match_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                // Input: aligned_val - pkp.FromId
                meta.query_advice(aligned_h1_pkp_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[0], Rotation::cur())
            },
            iz_h1_match_flag,
            h1_match_flag, // Output: 1 if input is zero, 0 otherwise
        );

        // --- Alignment columns for pkp.ToId (ordered_pkp[1]) against distinct_hop1_to_ext (similar to pkp.FromId) ---
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
            |meta| vec![meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur())], // aligned_val
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())],             // pkp.ToId
        );
        meta.create_gate("aligned_h1_pkp_to_personid_config verify", |meta| {
            let q = meta.query_selector(q_pkp);
            vec![q * (aligned_h1_pkp_to_personid_config.is_lt(meta, None) - one.clone())]
        });

        let next_aligned_h1_pkp_to_personid_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| vec![meta.query_advice(ordered_pkp[1], Rotation::cur())], // pkp.ToId
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

        // --- h1_pkp_to_flag: Is ordered_pkp[1] (pkp.ToId) a 1-hop friend? ---
        let h1_pkp_to_flag = meta.advice_column();
        let iz_h1_pkp_to_flag = meta.advice_column();
        let h1_pkp_to_flag_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_pkp),
            |meta| {
                // Input: aligned_val_for_target - pkp.ToId
                meta.query_advice(aligned_h1_pkp_to_personid, Rotation::cur())
                    - meta.query_advice(ordered_pkp[1], Rotation::cur())
            },
            iz_h1_pkp_to_flag,
            h1_pkp_to_flag, // Output: 1 if input is zero, 0 otherwise
        );

        // ---------------------------
        // hop 2: Find friends of 1-hop friends (excluding source and 1-hop friends)
        // ---------------------------
        let dist2_node = meta.advice_column(); // 1 if person is exactly 2 hops away
        let potential_friend_hop2 = meta.advice_column(); // 1 if person is reachable in 0, 1, or 2 hops
        let q_dist2_node = meta.complex_selector(); // Selector for rows in person table that are 2-hop friends

        meta.create_gate("init_h2_states", |meta| {
            // Renamed from q_dist2_node to avoid conflict
            let q_person_active = meta.query_selector(q_person);
            let dist2_node_assigned_val = meta.query_advice(dist2_node, Rotation::cur());
            let q_dist2_node_selector_val = meta.query_selector(q_dist2_node);
            // Enforces dist2_node gets value from q_dist2_node selector (enabled via shuffle)
            vec![q_person_active.clone() * (dist2_node_assigned_val - q_dist2_node_selector_val)]
        });

        let q_hop2_to = meta.complex_selector(); // Selector for edges in pkp leading to 2-hop friends
        meta.create_gate("set_q_hop2_to_selector", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_hop2_to_val = meta.query_selector(q_hop2_to);
            let pkp_from_is_h1_friend = meta.query_advice(h1_match_flag, Rotation::cur()); // 1 if pkp.FromId is a 1-hop friend
            let pkp_to_is_h1_friend = meta.query_advice(h1_pkp_to_flag, Rotation::cur()); // 1 if pkp.ToId is a 1-hop friend
            let pkp_to_is_source = meta.query_advice(source_pkp_to_check, Rotation::cur()); // 1 if pkp.ToId is the source

            // q_hop2_to is active if:
            // 1. pkp.FromId is a 1-hop friend (pkp_from_is_h1_friend == 1)
            // 2. pkp.ToId is NOT a 1-hop friend (1 - pkp_to_is_h1_friend == 1)
            // 3. pkp.ToId is NOT the source (1 - pkp_to_is_source == 1)
            let condition = pkp_from_is_h1_friend
                * (one.clone() - pkp_to_is_h1_friend)
                * (one.clone() - pkp_to_is_source);
            vec![q_pkp_active.clone() * (q_hop2_to_val - condition)]
        });

        let distinct_hop2_to = meta.advice_column(); // Stores unique 2-hop friends
        let q_distinct_hop2_to = meta.complex_selector();
        let q_distinct_hop2_to_order = meta.selector();

        // Shuffle to ensure distinct_hop2_to contains ToId's from pkp where q_hop2_to is active
        meta.lookup_any("distinct_hop2_to from pkp.ToId where q_hop2_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop2_to);
            let q2 = meta.query_selector(q_hop2_to);
            let a = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), b].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any("pkp.ToId where q_hop2_to into distinct_hop2_to", |meta| {
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
        let distinct_hop2_to_check = meta.advice_column(); // Flag: 1 if cur_h2_friend == next_h2_friend
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
            let check = meta.query_advice(distinct_hop2_to_check, Rotation::cur()); // 1 if cur == next
            let cur_lte_next = distinct_hop2_to_order.is_lt(meta, None); // 1 if cur <= next
            vec![
                q.clone() * (cur_lte_next - one.clone()), // Enforce cur <= next
                q.clone() * check,                        // Enforce cur != next
            ]
        });

        // Shuffle to connect distinct 2-hop friends to the person table (person[0])
        // This enables q_dist2_node for persons who are in distinct_hop2_to.
        meta.shuffle("mark 2-hop friends in person table", |meta| {
            let q_distinct_h2_active = meta.query_selector(q_distinct_hop2_to);
            let q_person_dist2_active = meta.query_selector(q_dist2_node);
            let friend_id_from_distinct_h2 = meta.query_advice(distinct_hop2_to, Rotation::cur());
            let person_id_from_person_table = meta.query_advice(person[0], Rotation::cur());
            let lhs = [one.clone(), person_id_from_person_table]
                .map(|v| v * q_person_dist2_active.clone());
            let rhs =
                [one.clone(), friend_id_from_distinct_h2].map(|v| v * q_distinct_h2_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("calculate potential_friend_hop2", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let d2 = meta.query_advice(dist2_node, Rotation::cur()); // Is 2-hop friend?
            let pot_h1 = meta.query_advice(potential_friend_hop1, Rotation::cur()); // Reachable in 0 or 1 hop?
            let pot_h2 = meta.query_advice(potential_friend_hop2, Rotation::cur());
            // Constraint: q_person_active * (pot_h2 - (d2 + pot_h1 - d2*pot_h1)) == 0
            // pot_h2 = pot_h1 OR d2
            // Sets potential_friend_hop2 if person is reachable in 0, 1, OR 2 hops.
            vec![q_person_active.clone() * (pot_h2 - (d2.clone() + pot_h1.clone() - d2 * pot_h1))]
        });

        // --- Hop 3 Additions (Configuration) START ---

        // --- hop2_ext: Padded and sorted list of 2-hop friends for alignment lookups (for Hop 3) ---
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
                let q_src_distinct_h2 = meta.query_selector(q_distinct_hop2_to);
                let q_dest_ext_internal = meta.query_selector(q_distinct_hop2_to_ext_internal);
                let val_from_distinct_h2 = meta.query_advice(distinct_hop2_to, Rotation::cur());
                let val_in_ext_internal = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                let lhs =
                    [one.clone(), val_from_distinct_h2].map(|v| v * q_src_distinct_h2.clone());
                let rhs =
                    [one.clone(), val_in_ext_internal].map(|v| v * q_dest_ext_internal.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );

        meta.create_gate("distinct_hop2_to_ext boundary check", |meta| {
            let q_boundary_active = meta.query_selector(q_distinct_hop2_to_ext_boundary);
            let current_val = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
            vec![
                q_boundary_active
                    * current_val.clone()
                    * (current_val - Expression::Constant(F::from(MAX_PERSON_ID))),
            ]
        });

        meta.create_gate("distinct_hop2_to_ext selector logic", |meta| {
            let q_ext_row_active = meta.query_selector(q_distinct_hop2_to_ext);
            let q_internal_part_active = meta.query_selector(q_distinct_hop2_to_ext_internal);
            let q_boundary_part_active = meta.query_selector(q_distinct_hop2_to_ext_boundary);
            vec![q_ext_row_active * (q_internal_part_active + q_boundary_part_active - one.clone())]
        });

        let mut distinct_hop2_to_ext_pairs_lookup_table = Vec::new();
        for _ in 0..2 {
            distinct_hop2_to_ext_pairs_lookup_table.push(meta.advice_column());
        }
        for i in 0..2 {
            meta.enable_equality(distinct_hop2_to_ext_pairs_lookup_table[i]);
        }
        let q_distinct_hop2_to_ext_pairs_lookup = meta.complex_selector();

        // --- Alignment columns for pkp.FromId (ordered_pkp[0]) against distinct_hop2_to_ext ---
        let aligned_h2_pkp_personid = meta.advice_column();
        let next_aligned_h2_pkp_personid = meta.advice_column();

        meta.lookup_any(
            "aligned_h2_pkp_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop2_to_ext);
                let val_to_check = meta.query_advice(aligned_h2_pkp_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h2_pkp_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop2_to_ext);
                let val_to_check = meta.query_advice(next_aligned_h2_pkp_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
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
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_pairs_table_active = meta.query_selector(q_distinct_hop2_to_ext_pairs_lookup);
            let aligned_val = meta.query_advice(aligned_h2_pkp_personid, Rotation::cur());
            let next_aligned_val = meta.query_advice(next_aligned_h2_pkp_personid, Rotation::cur());
            let pair_first =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[0], Rotation::cur());
            let pair_second =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs =
                [one.clone(), aligned_val, next_aligned_val].map(|v| v * q_pkp_active.clone());
            let rhs =
                [one.clone(), pair_first, pair_second].map(|v| v * q_pairs_table_active.clone());
            lhs.into_iter().zip(rhs).collect()
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

        // --- Alignment columns for pkp.ToId (ordered_pkp[1]) against distinct_hop2_to_ext ---
        let aligned_h2_pkp_to_personid = meta.advice_column();
        let next_aligned_h2_pkp_to_personid = meta.advice_column();

        meta.lookup_any(
            "aligned_h2_pkp_to_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop2_to_ext);
                let val_to_check = meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
            },
        );
        meta.lookup_any(
            "next_aligned_h2_pkp_to_personid is from distinct_hop2_to_ext",
            |meta| {
                let q_pkp_active = meta.query_selector(q_pkp);
                let q_ext_table_active = meta.query_selector(q_distinct_hop2_to_ext);
                let val_to_check =
                    meta.query_advice(next_aligned_h2_pkp_to_personid, Rotation::cur());
                let val_in_ext_table = meta.query_advice(distinct_hop2_to_ext, Rotation::cur());
                let lhs = [one.clone(), val_to_check].map(|v| v * q_pkp_active.clone());
                let rhs = [one.clone(), val_in_ext_table].map(|v| v * q_ext_table_active.clone());
                lhs.into_iter().zip(rhs).collect()
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
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_pairs_table_active = meta.query_selector(q_distinct_hop2_to_ext_pairs_lookup);
            let aligned_val = meta.query_advice(aligned_h2_pkp_to_personid, Rotation::cur());
            let next_aligned_val =
                meta.query_advice(next_aligned_h2_pkp_to_personid, Rotation::cur());
            let pair_first =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[0], Rotation::cur());
            let pair_second =
                meta.query_advice(distinct_hop2_to_ext_pairs_lookup_table[1], Rotation::cur());
            let lhs =
                [one.clone(), aligned_val, next_aligned_val].map(|v| v * q_pkp_active.clone());
            let rhs =
                [one.clone(), pair_first, pair_second].map(|v| v * q_pairs_table_active.clone());
            lhs.into_iter().zip(rhs).collect()
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

        // --- Hop 3: Find friends of 2-hop friends (excluding source, 1-hop, and 2-hop friends) ---
        let dist3_node = meta.advice_column();
        let potential_friend_hop3 = meta.advice_column();
        let q_dist3_node = meta.complex_selector();

        meta.create_gate("init_h3_states", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let dist3_node_assigned_val = meta.query_advice(dist3_node, Rotation::cur());
            let q_dist3_node_selector_val = meta.query_selector(q_dist3_node);
            vec![q_person_active.clone() * (dist3_node_assigned_val - q_dist3_node_selector_val)]
        });

        let q_hop3_to = meta.complex_selector();
        meta.create_gate("set_q_hop3_to_selector", |meta| {
            let q_pkp_active = meta.query_selector(q_pkp);
            let q_hop3_to_val = meta.query_selector(q_hop3_to);
            let pkp_from_is_h2_friend = meta.query_advice(h2_match_flag, Rotation::cur()); // 1 if pkp.FromId is a 2-hop friend
            let pkp_to_is_source = meta.query_advice(source_pkp_to_check, Rotation::cur()); // 1 if pkp.ToId is source
            let pkp_to_is_h1_friend = meta.query_advice(h1_pkp_to_flag, Rotation::cur()); // 1 if pkp.ToId is a 1-hop friend
            let pkp_to_is_h2_friend = meta.query_advice(h2_pkp_to_flag, Rotation::cur()); // 1 if pkp.ToId is a 2-hop friend

            // q_hop3_to is active if:
            // 1. pkp.FromId is a 2-hop friend (pkp_from_is_h2_friend == 1)
            // 2. pkp.ToId is NOT the source (1 - pkp_to_is_source == 1)
            // 3. pkp.ToId is NOT a 1-hop friend (1 - pkp_to_is_h1_friend == 1)
            // 4. pkp.ToId is NOT a 2-hop friend (1 - pkp_to_is_h2_friend == 1)
            let condition = pkp_from_is_h2_friend
                * (one.clone() - pkp_to_is_source)
                * (one.clone() - pkp_to_is_h1_friend)
                * (one.clone() - pkp_to_is_h2_friend);
            vec![q_pkp_active.clone() * (q_hop3_to_val - condition)]
        });

        let distinct_hop3_to = meta.advice_column();
        let q_distinct_hop3_to = meta.complex_selector();
        let q_distinct_hop3_to_order = meta.selector();

        meta.lookup_any("distinct_hop3_to from pkp.ToId where q_hop3_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop3_to);
            let q2 = meta.query_selector(q_hop3_to);
            let a = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), a].map(|c| c * q1.clone());
            let rhs = [one.clone(), b].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });
        meta.lookup_any("pkp.ToId where q_hop3_to into distinct_hop3_to", |meta| {
            let q1 = meta.query_selector(q_distinct_hop3_to);
            let q2 = meta.query_selector(q_hop3_to);
            let a = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let b = meta.query_advice(ordered_pkp[1], Rotation::cur());
            let lhs = [one.clone(), b].map(|c| c * q2.clone());
            let rhs = [one.clone(), a].map(|c| c * q1.clone());
            lhs.into_iter().zip(rhs).collect()
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
            let check = meta.query_advice(distinct_hop3_to_check, Rotation::cur());
            let cur_lte_next = distinct_hop3_to_order.is_lt(meta, None);
            vec![q.clone() * (cur_lte_next - one.clone()), q.clone() * check]
        });

        meta.shuffle("mark 3-hop friends in person table", |meta| {
            let q_distinct_h3_active = meta.query_selector(q_distinct_hop3_to);
            let q_person_dist3_active = meta.query_selector(q_dist3_node);
            let friend_id_from_distinct_h3 = meta.query_advice(distinct_hop3_to, Rotation::cur());
            let person_id_from_person_table = meta.query_advice(person[0], Rotation::cur());
            let lhs = [one.clone(), person_id_from_person_table]
                .map(|v| v * q_person_dist3_active.clone());
            let rhs =
                [one.clone(), friend_id_from_distinct_h3].map(|v| v * q_distinct_h3_active.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("calculate potential_friend_hop3", |meta| {
            let q_person_active = meta.query_selector(q_person);
            let d3 = meta.query_advice(dist3_node, Rotation::cur()); // Is 3-hop friend?
            let pot_h2 = meta.query_advice(potential_friend_hop2, Rotation::cur()); // Reachable in 0, 1 or 2 hops?
            let pot_h3 = meta.query_advice(potential_friend_hop3, Rotation::cur());
            // pot_h3 = pot_h2 OR d3
            vec![q_person_active.clone() * (pot_h3 - (d3.clone() + pot_h2.clone() - d3 * pot_h2))]
        });
        // --- Hop 3 Additions (Configuration) END ---

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
            // Hop 1 align
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
            // Hop 0 & 1 states
            potential_friend_hop1,
            dist0_node,
            dist1_node,
            q_dist1_node,
            // PKP source checks
            source_pkp_zero,
            dist1_pkp_check,
            source_pkp_to_zero,
            source_pkp_to_check,
            // Distinct Hop 1
            q_hop1_to,
            distinct_hop1_to,
            q_distinct_hop1_to,
            q_distinct_hop1_to_order,
            distinct_hop1_to_order,
            distinct_hop1_to_zero,
            distinct_hop1_to_check,
            // Distinct Hop 1 Ext
            distinct_hop1_to_ext,
            q_distinct_hop1_to_ext,
            q_distinct_hop1_to_ext_order,
            distinct_hop1_to_ext_order_config,
            q_distinct_hop1_to_ext_internal,
            q_distinct_hop1_to_ext_boundary,
            distinct_hop1_to_ext_pairs_lookup_table,
            q_distinct_hop1_to_ext_pairs_lookup,
            // Hop 2 states & distinct
            potential_friend_hop2,
            dist2_node,
            q_dist2_node,
            q_hop2_to,
            distinct_hop2_to,
            q_distinct_hop2_to,
            q_distinct_hop2_to_order,
            distinct_hop2_to_order,
            distinct_hop2_to_zero,
            distinct_hop2_to_check,
            // --- Hop 3 Additions START ---
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
            potential_friend_hop3,
            dist3_node,
            q_dist3_node,
            q_hop3_to,
            distinct_hop3_to,
            q_distinct_hop3_to,
            q_distinct_hop3_to_order,
            distinct_hop3_to_order,
            distinct_hop3_to_zero,
            distinct_hop3_to_check,
            // --- Hop 3 Additions END ---
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

        // Hop 1 chips
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

        // Hop 2 chips
        let distinct_hop2_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop2_to_order.clone());
        let distinct_hop2_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop2_to_zero.clone());

        // --- Hop 3 Additions (Chip Construction) START ---
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

        let distinct_hop3_to_order_chip =
            LtEqGenericChip::construct(self.config.distinct_hop3_to_order.clone());
        let distinct_hop3_to_zero_chip =
            IsZeroChip::construct(self.config.distinct_hop3_to_zero.clone());
        // --- Hop 3 Additions (Chip Construction) END ---

        // Load lookup tables for LtEqGenericChips
        ordered_pkp_person_id_sort_chip.load(layouter).unwrap();
        distinct_hop1_to_order_chip.load(layouter).unwrap();
        distinct_hop1_to_ext_order_chip.load(layouter).unwrap();
        aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_personid_chip.load(layouter).unwrap();
        aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h1_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop2_to_order_chip.load(layouter).unwrap();
        // --- Hop 3 Additions (Load LtEq Chips) START ---
        distinct_hop2_to_ext_order_chip.load(layouter).unwrap();
        aligned_h2_pkp_personid_chip.load(layouter).unwrap();
        next_aligned_h2_pkp_personid_chip.load(layouter).unwrap();
        aligned_h2_pkp_to_personid_chip.load(layouter).unwrap();
        next_aligned_h2_pkp_to_personid_chip.load(layouter).unwrap();
        distinct_hop3_to_order_chip.load(layouter).unwrap();
        // --- Hop 3 Additions (Load LtEq Chips) END ---

        // BFS and data preprocessing
        let max_hops = 3; // MODIFIED for 3 hops
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
            // This case should ideally not happen if person_id_val is always in person_table
            // Or, handle as an error/special case depending on requirements.
            // For now, we proceed, but BFS won't find any paths.
            println!(
                "Warnung: BFS-Quell-Personen-ID {:?} nicht in person_table gefunden.",
                person_id_val
            );
        }

        while let Some(u_id) = q_bfs.pop_front() {
            let dist_u = distances[&u_id];
            if dist_u >= max_hops {
                // Stop BFS if max_hops reached
                continue;
            }
            if let Some(neighbors) = adj.get(&u_id) {
                for &v_id in neighbors {
                    // Check if v_id is in distances and its current distance is dummy_distance
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
        ordered_pkp_table.sort_by(|a, b| f_to_u64(&a[1]).cmp(&f_to_u64(&b[1]))); // Sort by ToId

        // Hop 1 friends (distinct_hop1_to_table)
        let mut hop1_friends_vec = Vec::new();
        for edge in &ordered_pkp_table {
            // Iterate over original pkp for this, or filter ordered_pkp_table
            if edge[0] == person_id_val {
                // Ensure target is not the source itself, unless self-loops are allowed as 1-hop
                if edge[1] != person_id_val {
                    let dist_to_target = distances
                        .get(&edge[1])
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    if dist_to_target == 1 {
                        // Double check with BFS distance
                        hop1_friends_vec.push(edge[1]);
                    }
                }
            }
        }
        hop1_friends_vec.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop1_friends_vec.dedup();
        let distinct_hop1_to_table = hop1_friends_vec; // Renamed for clarity

        // distinct_hop1_to_ext_values (for alignment)
        let mut distinct_hop1_to_ext_values = vec![F::ZERO];
        distinct_hop1_to_ext_values.extend(distinct_hop1_to_table.iter().cloned());
        distinct_hop1_to_ext_values.push(F::from(MAX_PERSON_ID));
        distinct_hop1_to_ext_values.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        distinct_hop1_to_ext_values.dedup(); // Should already be sorted and unique from MAX_PERSON_ID and ZERO add

        let mut distinct_hop1_to_ext_pairs_table = Vec::new();
        if distinct_hop1_to_ext_values.len() >= 2 {
            for i in 0..(distinct_hop1_to_ext_values.len() - 1) {
                distinct_hop1_to_ext_pairs_table.push((
                    distinct_hop1_to_ext_values[i],
                    distinct_hop1_to_ext_values[i + 1],
                ));
            }
        }

        // Hop 2 friends (distinct_hop2_to_table)
        let mut hop2_friends_raw = Vec::new();
        for ordered_edge in &ordered_pkp_table {
            let pkp_source_node = ordered_edge[0];
            let pkp_target_node = ordered_edge[1];

            // Check if pkp_source_node is a 1-hop friend
            let is_pkp_source_h1 = distinct_hop1_to_table
                .binary_search(&pkp_source_node)
                .is_ok();

            if is_pkp_source_h1 {
                let is_pkp_target_source = pkp_target_node == person_id_val;
                let is_pkp_target_h1 = distinct_hop1_to_table
                    .binary_search(&pkp_target_node)
                    .is_ok();

                if !is_pkp_target_source && !is_pkp_target_h1 {
                    let bfs_dist_to_target = distances
                        .get(&pkp_target_node)
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    if bfs_dist_to_target == 2 {
                        // Ensure it's truly a 2-hop via BFS
                        hop2_friends_raw.push(pkp_target_node);
                    }
                }
            }
        }
        hop2_friends_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop2_friends_raw.dedup();
        let distinct_hop2_to_table = hop2_friends_raw;

        // --- Hop 3 Additions (Pre-computation) START ---

        // distinct_hop2_to_ext_values (for aligning Hop 3 calculations)
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

        // Hop 3 friends (distinct_hop3_to_table)
        let mut hop3_friends_raw = Vec::new();
        for ordered_edge in &ordered_pkp_table {
            let pkp_source_node = ordered_edge[0];
            let pkp_target_node = ordered_edge[1];

            let is_pkp_source_h2 = distinct_hop2_to_table
                .binary_search(&pkp_source_node)
                .is_ok();

            if is_pkp_source_h2 {
                let is_pkp_target_source = pkp_target_node == person_id_val;
                let is_pkp_target_h1 = distinct_hop1_to_table
                    .binary_search(&pkp_target_node)
                    .is_ok();
                let is_pkp_target_h2 = distinct_hop2_to_table
                    .binary_search(&pkp_target_node)
                    .is_ok();

                if !is_pkp_target_source && !is_pkp_target_h1 && !is_pkp_target_h2 {
                    let bfs_dist_to_target = distances
                        .get(&pkp_target_node)
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    if bfs_dist_to_target == 3 {
                        // Ensure it's truly a 3-hop via BFS
                        hop3_friends_raw.push(pkp_target_node);
                    }
                }
            }
        }
        hop3_friends_raw.sort_by(|a, b| f_to_u64(a).cmp(&f_to_u64(b)));
        hop3_friends_raw.dedup();
        let distinct_hop3_to_table = hop3_friends_raw;
        // --- Hop 3 Additions (Pre-computation) END ---

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                // Assign person table and initial distance states
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
                    let is_dist3 = dist == 3; // Added for Hop 3

                    let dist0_val = F::from(is_dist0 as u64);
                    let dist1_val = F::from(is_dist1 as u64);
                    let dist2_val = F::from(is_dist2 as u64);
                    let dist3_val = F::from(is_dist3 as u64); // Added for Hop 3

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
                    region.assign_advice(
                        || format!("dist3_node at {}", i),
                        self.config.dist3_node,
                        i,
                        || Value::known(dist3_val),
                    )?; // Added for Hop 3

                    if is_dist1 {
                        self.config.q_dist1_node.enable(&mut region, i)?;
                    }
                    if is_dist2 {
                        self.config.q_dist2_node.enable(&mut region, i)?;
                    }
                    if is_dist3 {
                        self.config.q_dist3_node.enable(&mut region, i)?;
                    } // Added for Hop 3

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
                    let pot_friend_h3_val = if is_dist0 || is_dist1 || is_dist2 || is_dist3 {
                        F::ONE
                    } else {
                        F::ZERO
                    }; // Added for Hop 3

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
                    region.assign_advice(
                        || format!("potential_friend_hop3 at {}", i),
                        self.config.potential_friend_hop3,
                        i,
                        || Value::known(pot_friend_h3_val),
                    )?; // Added for Hop 3
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

                    // --- H1 Alignment for pkp_source_node (ordered_edge[0]) ---
                    let mut aligned_val_h1_source = F::ZERO;
                    let mut next_aligned_val_h1_source = F::from(MAX_PERSON_ID);
                    let search_res_h1_src = distinct_hop1_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_source_node)));
                    match search_res_h1_src {
                        Ok(idx) => {
                            aligned_val_h1_source = distinct_hop1_to_ext_values[idx];
                            if idx + 1 < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_h1_source = distinct_hop1_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_h1_source = distinct_hop1_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_h1_source = distinct_hop1_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h1_pkp_personid row {}", i),
                        self.config.aligned_h1_pkp_personid,
                        i,
                        || Value::known(aligned_val_h1_source),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h1_pkp_personid row {}", i),
                        self.config.next_aligned_h1_pkp_personid,
                        i,
                        || Value::known(next_aligned_val_h1_source),
                    )?;
                    aligned_h1_pkp_personid_chip
                        .assign(&mut region, i, &[aligned_val_h1_source], &[pkp_source_node])
                        .unwrap();
                    next_aligned_h1_pkp_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_source_node],
                            &[next_aligned_val_h1_source - F::ONE],
                        )
                        .unwrap();

                    let diff_h1_match_from = aligned_val_h1_source - pkp_source_node;
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

                    // --- H1 Alignment for pkp_target_node (ordered_edge[1]) ---
                    let mut aligned_val_h1_target = F::ZERO;
                    let mut next_aligned_val_h1_target = F::from(MAX_PERSON_ID);
                    let search_res_h1_target = distinct_hop1_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_target_node)));
                    match search_res_h1_target {
                        Ok(idx) => {
                            aligned_val_h1_target = distinct_hop1_to_ext_values[idx];
                            if idx + 1 < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_h1_target = distinct_hop1_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_h1_target = distinct_hop1_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop1_to_ext_values.len() {
                                next_aligned_val_h1_target = distinct_hop1_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h1_pkp_to_personid row {}", i),
                        self.config.aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(aligned_val_h1_target),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h1_pkp_to_personid row {}", i),
                        self.config.next_aligned_h1_pkp_to_personid,
                        i,
                        || Value::known(next_aligned_val_h1_target),
                    )?;
                    aligned_h1_pkp_to_personid_chip
                        .assign(&mut region, i, &[aligned_val_h1_target], &[pkp_target_node])
                        .unwrap();
                    next_aligned_h1_pkp_to_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_target_node],
                            &[next_aligned_val_h1_target - F::ONE],
                        )
                        .unwrap();

                    let diff_h1_pkp_to = aligned_val_h1_target - pkp_target_node;
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

                    // This assignment is tricky. The lookup needs distinct_hop1_to_ext to be the authoritative table.
                    // Assigning specific values here for each pkp row to distinct_hop1_to_ext might conflict
                    // with its role as a global, sorted, unique list.
                    // The original code does this, so replicating. It implies the lookup constraints
                    // are checking if (aligned_val_h1_source) is IN (distinct_hop1_to_ext values), not that this cell IS distinct_hop1_to_ext.
                    // This specific cell will be overwritten by the authoritative assignment later.
                    // This is only safe if the constraint system processes lookups against the final state of distinct_hop1_to_ext.
                    region.assign_advice(
                        || {
                            format!(
                                "placeholder_distinct_hop1_ext_for_pkp_source_align row {}",
                                i
                            )
                        },
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(aligned_val_h1_source),
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "placeholder_distinct_hop1_ext_for_pkp_target_align row {}",
                                i
                            )
                        },
                        self.config.distinct_hop1_to_ext,
                        i,
                        || Value::known(aligned_val_h1_target),
                    )?;

                    // Enable q_hop2_to selector
                    let enable_q_hop2_val_f = h1_match_flag_val
                        * (F::ONE - h1_pkp_to_flag_val)
                        * (F::ONE - source_pkp_to_check_val);
                    if enable_q_hop2_val_f == F::ONE {
                        self.config.q_hop2_to.enable(&mut region, i)?;
                    }

                    // --- Hop 3 Additions (PKP Loop Assignments) START ---
                    // --- H2 Alignment for pkp_source_node (ordered_edge[0]) ---
                    let mut aligned_val_h2_source = F::ZERO;
                    let mut next_aligned_val_h2_source = F::from(MAX_PERSON_ID);
                    let search_res_h2_src = distinct_hop2_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_source_node)));
                    match search_res_h2_src {
                        Ok(idx) => {
                            aligned_val_h2_source = distinct_hop2_to_ext_values[idx];
                            if idx + 1 < distinct_hop2_to_ext_values.len() {
                                next_aligned_val_h2_source = distinct_hop2_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_h2_source = distinct_hop2_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop2_to_ext_values.len() {
                                next_aligned_val_h2_source = distinct_hop2_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h2_pkp_personid row {}", i),
                        self.config.aligned_h2_pkp_personid,
                        i,
                        || Value::known(aligned_val_h2_source),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h2_pkp_personid row {}", i),
                        self.config.next_aligned_h2_pkp_personid,
                        i,
                        || Value::known(next_aligned_val_h2_source),
                    )?;
                    aligned_h2_pkp_personid_chip
                        .assign(&mut region, i, &[aligned_val_h2_source], &[pkp_source_node])
                        .unwrap();
                    next_aligned_h2_pkp_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_source_node],
                            &[next_aligned_val_h2_source - F::ONE],
                        )
                        .unwrap();

                    let diff_h2_match_from = aligned_val_h2_source - pkp_source_node;
                    h2_match_flag_chip
                        .assign(&mut region, i, Value::known(diff_h2_match_from))
                        .unwrap();
                    let h2_match_flag_val = if diff_h2_match_from == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h2_match_flag row {}", i),
                        self.config.h2_match_flag,
                        i,
                        || Value::known(h2_match_flag_val),
                    )?;

                    // --- H2 Alignment for pkp_target_node (ordered_edge[1]) ---
                    let mut aligned_val_h2_target = F::ZERO;
                    let mut next_aligned_val_h2_target = F::from(MAX_PERSON_ID);
                    let search_res_h2_target = distinct_hop2_to_ext_values
                        .binary_search_by(|p| f_to_u64(p).cmp(&f_to_u64(&pkp_target_node)));
                    match search_res_h2_target {
                        Ok(idx) => {
                            aligned_val_h2_target = distinct_hop2_to_ext_values[idx];
                            if idx + 1 < distinct_hop2_to_ext_values.len() {
                                next_aligned_val_h2_target = distinct_hop2_to_ext_values[idx + 1];
                            }
                        }
                        Err(idx) => {
                            if idx > 0 {
                                aligned_val_h2_target = distinct_hop2_to_ext_values[idx - 1];
                            }
                            if idx < distinct_hop2_to_ext_values.len() {
                                next_aligned_val_h2_target = distinct_hop2_to_ext_values[idx];
                            }
                        }
                    }
                    region.assign_advice(
                        || format!("aligned_h2_pkp_to_personid row {}", i),
                        self.config.aligned_h2_pkp_to_personid,
                        i,
                        || Value::known(aligned_val_h2_target),
                    )?;
                    region.assign_advice(
                        || format!("next_aligned_h2_pkp_to_personid row {}", i),
                        self.config.next_aligned_h2_pkp_to_personid,
                        i,
                        || Value::known(next_aligned_val_h2_target),
                    )?;
                    aligned_h2_pkp_to_personid_chip
                        .assign(&mut region, i, &[aligned_val_h2_target], &[pkp_target_node])
                        .unwrap();
                    next_aligned_h2_pkp_to_personid_chip
                        .assign(
                            &mut region,
                            i,
                            &[pkp_target_node],
                            &[next_aligned_val_h2_target - F::ONE],
                        )
                        .unwrap();

                    let diff_h2_pkp_to = aligned_val_h2_target - pkp_target_node;
                    h2_pkp_to_flag_chip
                        .assign(&mut region, i, Value::known(diff_h2_pkp_to))
                        .unwrap();
                    let h2_pkp_to_flag_val = if diff_h2_pkp_to == F::ZERO {
                        F::ONE
                    } else {
                        F::ZERO
                    };
                    region.assign_advice(
                        || format!("h2_pkp_to_flag row {}", i),
                        self.config.h2_pkp_to_flag,
                        i,
                        || Value::known(h2_pkp_to_flag_val),
                    )?;

                    // Placeholder assignment for distinct_hop2_to_ext (similar to hop1)
                    region.assign_advice(
                        || {
                            format!(
                                "placeholder_distinct_hop2_ext_for_pkp_source_align row {}",
                                i
                            )
                        },
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(aligned_val_h2_source),
                    )?;
                    region.assign_advice(
                        || {
                            format!(
                                "placeholder_distinct_hop2_ext_for_pkp_target_align row {}",
                                i
                            )
                        },
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(aligned_val_h2_target),
                    )?;

                    // Enable q_hop3_to selector
                    let enable_q_hop3_val_f = h2_match_flag_val
                        * (F::ONE - source_pkp_to_check_val)
                        * (F::ONE - h1_pkp_to_flag_val)
                        * (F::ONE - h2_pkp_to_flag_val);
                    if enable_q_hop3_val_f == F::ONE {
                        self.config.q_hop3_to.enable(&mut region, i)?;
                    }
                    // --- Hop 3 Additions (PKP Loop Assignments) END ---
                }

                // Assign distinct_hop1_to table (authoritative)
                for (i, &friend_id) in distinct_hop1_to_table.iter().enumerate() {
                    self.config.q_distinct_hop1_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("distinct_hop1_to row {}", i),
                        self.config.distinct_hop1_to,
                        i,
                        || Value::known(friend_id),
                    )?;
                    if i < distinct_hop1_to_table.len() - 1 {
                        self.config
                            .q_distinct_hop1_to_order
                            .enable(&mut region, i)?;
                        let next_friend_id = distinct_hop1_to_table[i + 1];
                        distinct_hop1_to_order_chip
                            .assign(&mut region, i, &[friend_id], &[next_friend_id])
                            .unwrap();
                        let diff_distinct = friend_id - next_friend_id;
                        distinct_hop1_to_zero_chip
                            .assign(&mut region, i, Value::known(diff_distinct))
                            .unwrap();
                        // distinct_hop1_to_check_val should be 0 for distinct sorted values. It's 1 if friend_id == next_friend_id
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
                let mut distinct_hop1_to_ext_offset = 0; // Keep track of offset if merging assignment regions
                for (i, &ext_id) in distinct_hop1_to_ext_values.iter().enumerate() {
                    let current_offset = i; // Use a local offset for this loop
                    self.config
                        .q_distinct_hop1_to_ext
                        .enable(&mut region, current_offset)?;
                    region.assign_advice(
                        || format!("authoritative_distinct_hop1_to_ext row {}", current_offset),
                        self.config.distinct_hop1_to_ext,
                        current_offset, // This is the authoritative assignment
                        || Value::known(ext_id),
                    )?;
                    if ext_id == F::ZERO || ext_id == F::from(MAX_PERSON_ID) {
                        self.config
                            .q_distinct_hop1_to_ext_boundary
                            .enable(&mut region, current_offset)?;
                    } else {
                        self.config
                            .q_distinct_hop1_to_ext_internal
                            .enable(&mut region, current_offset)?;
                    }
                    if current_offset < distinct_hop1_to_ext_values.len() - 1 {
                        self.config
                            .q_distinct_hop1_to_ext_order
                            .enable(&mut region, current_offset)?;
                        distinct_hop1_to_ext_order_chip
                            .assign(
                                &mut region,
                                current_offset,
                                &[ext_id],
                                &[distinct_hop1_to_ext_values[current_offset + 1]],
                            )
                            .unwrap();
                    }
                }
                distinct_hop1_to_ext_offset += distinct_hop1_to_ext_values.len();

                // Assign distinct_hop1_to_ext_pairs_lookup_table
                let mut pairs_table_offset = 0;
                for (i, &(pair_first, pair_second)) in
                    distinct_hop1_to_ext_pairs_table.iter().enumerate()
                {
                    let current_offset = i;
                    self.config
                        .q_distinct_hop1_to_ext_pairs_lookup
                        .enable(&mut region, current_offset)?;
                    region.assign_advice(
                        || format!("d_h1_ext_pairs_lookup_tab[0] row {}", current_offset),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[0],
                        current_offset,
                        || Value::known(pair_first),
                    )?;
                    region.assign_advice(
                        || format!("d_h1_ext_pairs_lookup_tab[1] row {}", current_offset),
                        self.config.distinct_hop1_to_ext_pairs_lookup_table[1],
                        current_offset,
                        || Value::known(pair_second),
                    )?;
                }
                pairs_table_offset += distinct_hop1_to_ext_pairs_table.len();

                // Assign distinct_hop2_to table (authoritative)
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

                // --- Hop 3 Additions (Table Assignments) START ---
                // Assign authoritative distinct_hop2_to_ext table
                // Manage offsets carefully if assigning to the same region after other tables.
                // For simplicity, assuming these can be assigned at offset 0 for their respective columns if region is fresh or columns are distinct.
                // If using the same region and advice columns are reused, offsets must be managed.
                // Here, assuming new columns or a new region conceptually.
                for (i, &ext_id) in distinct_hop2_to_ext_values.iter().enumerate() {
                    self.config.q_distinct_hop2_to_ext.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("authoritative_distinct_hop2_to_ext row {}", i),
                        self.config.distinct_hop2_to_ext,
                        i,
                        || Value::known(ext_id),
                    )?;
                    if ext_id == F::ZERO || ext_id == F::from(MAX_PERSON_ID) {
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
                            .assign(
                                &mut region,
                                i,
                                &[ext_id],
                                &[distinct_hop2_to_ext_values[i + 1]],
                            )
                            .unwrap();
                    }
                }

                // Assign distinct_hop2_to_ext_pairs_lookup_table
                for (i, &(pair_first, pair_second)) in
                    distinct_hop2_to_ext_pairs_table.iter().enumerate()
                {
                    self.config
                        .q_distinct_hop2_to_ext_pairs_lookup
                        .enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("d_h2_ext_pairs_lookup_tab[0] row {}", i),
                        self.config.distinct_hop2_to_ext_pairs_lookup_table[0],
                        i,
                        || Value::known(pair_first),
                    )?;
                    region.assign_advice(
                        || format!("d_h2_ext_pairs_lookup_tab[1] row {}", i),
                        self.config.distinct_hop2_to_ext_pairs_lookup_table[1],
                        i,
                        || Value::known(pair_second),
                    )?;
                }

                // Assign distinct_hop3_to table (authoritative)
                for (i, &h3_friend_id) in distinct_hop3_to_table.iter().enumerate() {
                    self.config.q_distinct_hop3_to.enable(&mut region, i)?;
                    region.assign_advice(
                        || format!("distinct_hop3_to row {}", i),
                        self.config.distinct_hop3_to,
                        i,
                        || Value::known(h3_friend_id),
                    )?;
                    if i < distinct_hop3_to_table.len() - 1 {
                        self.config
                            .q_distinct_hop3_to_order
                            .enable(&mut region, i)?;
                        let next_h3_friend_id = distinct_hop3_to_table[i + 1];
                        distinct_hop3_to_order_chip
                            .assign(&mut region, i, &[h3_friend_id], &[next_h3_friend_id])
                            .unwrap();
                        let diff_distinct_h3 = h3_friend_id - next_h3_friend_id;
                        distinct_hop3_to_zero_chip
                            .assign(&mut region, i, Value::known(diff_distinct_h3))
                            .unwrap();
                        let distinct_hop3_to_check_val = if diff_distinct_h3 == F::ZERO {
                            F::ONE
                        } else {
                            F::ZERO
                        };
                        region.assign_advice(
                            || format!("distinct_hop3_to_check row {}", i),
                            self.config.distinct_hop3_to_check,
                            i,
                            || Value::known(distinct_hop3_to_check_val),
                        )?;
                    }
                }
                // --- Hop 3 Additions (Table Assignments) END ---

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
    type FloorPlanner = SimpleFloorPlanner; // Consider PlafSimpleFloorPlanner if using Plaf & complex layout

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
            &mut layouter.namespace(|| "Assign full circuit"),
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
    // Assuming these utils are in a parent module or crate::utils
    // For this self-contained example, they would need to be defined here or in scope.
    // For brevity, I'll assume they exist as in the original snippet.
    // pub mod utils { /* ... your utility functions ... */ }
    // use crate::utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64};

    // Minimal stubs for utility functions for the test to compile
    mod utils {
        use halo2_proofs::halo2curves::bn256::Fr; // Or appropriate field
        pub fn read_csv(path: &str, delimiter: char) -> Result<Vec<Vec<String>>, csv::Error> {
            let mut rdr = csv::ReaderBuilder::new()
                .delimiter(delimiter as u8)
                .from_path(path)?;
            let mut records = Vec::new();
            for result in rdr.records() {
                records.push(result?.iter().map(String::from).collect());
            }
            Ok(records)
        }
        pub fn string_to_u64(s: &str) -> u64 {
            s.len() as u64
        } // Simplified stub
        pub fn parse_date(s: &str) -> u64 {
            s.len() as u64
        } // Simplified stub
        pub fn parse_datetime(s: &str) -> u64 {
            s.len() as u64
        } // Simplified stub
        pub fn ipv4_to_u64(s: &str) -> u64 {
            s.len() as u64
        } // Simplified stub
    }
    use utils::{ipv4_to_u64, parse_date, parse_datetime, read_csv, string_to_u64};

    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use std::time::Instant;

    #[test]
    fn test_is1_circuit_3hop() {
        // Renamed test function
        let k = 14; // Increased K, 3-hop is more complex. May need further increase.

        // NOTE: Provide actual paths to your CSV files
        let person_csv_path =
            "/home/wh/zkgraph/src/data/sf0.1/social_network/dynamic/person_0_0.csv";
        let pkp_csv_path =
            "/home/wh/zkgraph/src/data/sf0.1/social_network/dynamic/person_knows_person_0_0.csv";

        let person_data = read_csv(person_csv_path, '|').expect("无法加载 Person 数据");
        let relation_data = read_csv(pkp_csv_path, '|').expect("无法加载 Relation 数据");

        let mut person_table: Vec<Vec<Fr>> = Vec::new();
        for row in person_data.iter() {
            // Removed enumerate as index not used
            let person_row = vec![
                Fr::from(row[0].parse::<u64>().expect("无效的 Person ID")),
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
        for row in relation_data.iter() {
            // Removed enumerate
            let r_row = vec![
                Fr::from(row[0].parse::<u64>().expect("无效的 Person ID in PKP from")),
                Fr::from(row[1].parse::<u64>().expect("无效的 Person ID in PKP to")),
            ];
            person_knows_person.push(r_row);
        }

        println!("person_table.len: {:?}", person_table.len());
        println!("person_knows_person.len: {:?}", person_knows_person.len());

        // Test with a person ID known to be in your dataset
        let test_person_id_val: u64 = 21990232556585; // Example ID from original code
        let person_id_fr = Fr::from(test_person_id_val);

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_knows_person,
            person_id: person_id_fr,
            _marker: PhantomData,
        };

        // Public inputs, if any. Original had vec![Fr::from(1)], purpose unclear from snippet.
        // If it's related to the number of output friends, it might need adjustment or be made dynamic.
        // For now, keeping it as is.
        let public_input = vec![Fr::from(1)];
        let start = Instant::now();
        let prover =
            MockProver::run(k, &circuit, vec![public_input.clone()]).expect("MockProver 运行失败");
        println!("Prover 执行时间: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("验证成功!"),
            Err(e) => {
                // Print all errors
                for error in e.iter() {
                    println!("{:?}", error);
                }
                panic!("验证失败, siehe oben für Details.");
            }
        }
    }
}
