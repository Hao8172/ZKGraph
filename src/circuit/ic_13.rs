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

/*
MATCH
    (person1:Person {id: $person1Id}),
    (person2:Person {id: $person2Id}),
    path = shortestPath((person1)-[:KNOWS*]-(person2))
RETURN
    CASE path IS NULL
        WHEN true THEN -1
        ELSE length(path)
    END AS shortestPathLength
*/

#[derive(Clone, Debug)]
pub struct ic13CircuitConfig<F: Field + Ord + std::hash::Hash> {
    q_person: Selector,

    person: Vec<Column<Advice>>,
    person_id: Column<Advice>,
    person_check: Column<Advice>,
    // node
    person_dist: Column<Advice>,
    predecessor: Column<Advice>,
    predecessor_dist: Column<Advice>,
    person_zero: crate::chips::is_zero::IsZeroConfig<F>,

    person_knows_person: Vec<Column<Advice>>,

    pkp_norm_0: Column<Advice>, // min(pkp[0], pkp[1])
    pkp_norm_1: Column<Advice>, // max(pkp[0], pkp[1])
    pkp_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>,

    pc_norm_0: Column<Advice>, // min(predecessor, person[0])
    pc_norm_1: Column<Advice>, // max(predecessor, person[0])
    pc_norm_order_config: LtEqGenericConfig<F, NUM_BYTES>,

    // edge
    source_dist: Column<Advice>,
    target_dist: Column<Advice>,
    target_less: LtEqGenericConfig<F, NUM_BYTES>,
    q_edge: Selector,
    q_enable_pc_normalization: Selector,

    person_id2: Column<Advice>,
    person_id2_dist: Column<Advice>,
    q_id2: Selector,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct ic13Chip<F: Field + Ord + std::hash::Hash> {
    config: ic13CircuitConfig<F>,
}

impl<F: Field + Ord + std::hash::Hash> ic13Chip<F> {
    pub fn construct(config: ic13CircuitConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> ic13CircuitConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let mut person = Vec::new();
        for _ in 0..8 {
            person.push(meta.advice_column());
        }

        let person_id = meta.advice_column();
        let person_check = meta.advice_column();
        meta.enable_equality(person_check);

        let q_person = meta.complex_selector();

        let iz_person_advice = meta.advice_column();
        let person_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_person),
            |meta: &mut VirtualCells<'_, F>| {
                meta.query_advice(person[0], Rotation::cur())
                    - meta.query_advice(person_id, Rotation::cur())
            },
            iz_person_advice,
            person_check,
        );

        let person_dist = meta.advice_column();
        let predecessor = meta.advice_column();
        let predecessor_dist = meta.advice_column();

        let one = Expression::Constant(F::ONE);
        meta.lookup_any(format!("predecessor + predecessor_dist"), |meta| {
            let q = meta.query_selector(q_person);
            let a = meta.query_advice(predecessor, Rotation::cur());
            let b = meta.query_advice(predecessor_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.create_gate("person_check * dist == 0", |meta| {
            let q = meta.query_selector(q_person);
            let person_check = meta.query_advice(person_check, Rotation::cur());
            let dist = meta.query_advice(person_dist, Rotation::cur());
            vec![q.clone() * person_check * dist]
        });

        meta.create_gate("dist == predecessor_dist + 1", |meta| {
            let q = meta.query_selector(q_person);
            let is_source = meta.query_advice(person_check, Rotation::cur());
            let dist = meta.query_advice(person_dist, Rotation::cur());
            let f_dist = meta.query_advice(predecessor_dist, Rotation::cur());
            vec![
                q.clone()
                    * (Expression::Constant(F::ONE) - is_source)
                    * (dist.clone() - f_dist.clone() - Expression::Constant(F::ONE))
                    * (dist - Expression::Constant(F::from(100000u64))),
            ]
        });

        let mut person_knows_person = Vec::new();
        for _ in 0..2 {
            person_knows_person.push(meta.advice_column());
        }
        let pkp_norm_0 = meta.advice_column();
        let pkp_norm_1 = meta.advice_column();
        let pc_norm_0 = meta.advice_column();
        let pc_norm_1 = meta.advice_column();

        let q_enable_pc_normalization = meta.complex_selector();
        let q_edge = meta.complex_selector();

        let pkp_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_edge),
            |meta| vec![meta.query_advice(pkp_norm_1, Rotation::cur())], // M = max(pkp[0],pkp[1])
            |meta| vec![meta.query_advice(pkp_norm_0, Rotation::cur())], // m = min(pkp[0],pkp[1])
        );
        meta.create_gate("pkp_normalization", |meta| {
            let q = meta.query_selector(q_edge);
            let u = meta.query_advice(person_knows_person[0], Rotation::cur());
            let v = meta.query_advice(person_knows_person[1], Rotation::cur());
            let norm_u = meta.query_advice(pkp_norm_0, Rotation::cur());
            let norm_v = meta.query_advice(pkp_norm_1, Rotation::cur());

            let sum_check = (norm_u.clone() + norm_v.clone()) - (u.clone() + v.clone());
            let prod_check = (norm_u.clone() * norm_v.clone()) - (u * v);
            let order_check = pkp_norm_order_config.is_lt(meta, None);

            vec![
                q.clone() * sum_check,
                q.clone() * prod_check,
                q * order_check,
            ]
        });

        let pc_norm_order_config = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_enable_pc_normalization),
            |meta| vec![meta.query_advice(pc_norm_1, Rotation::cur())], // M = max(P,C)
            |meta| vec![meta.query_advice(pc_norm_0, Rotation::cur())], // m = min(P,C)
        );
        meta.create_gate("pc_normalization", |meta| {
            let q = meta.query_selector(q_enable_pc_normalization);
            let p = meta.query_advice(predecessor, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let norm_p = meta.query_advice(pc_norm_0, Rotation::cur());
            let norm_c = meta.query_advice(pc_norm_1, Rotation::cur());

            let sum_check = (norm_p.clone() + norm_c.clone()) - (p.clone() + c.clone());
            let prod_check = (norm_p.clone() * norm_c.clone()) - (p * c);
            let order_check = pc_norm_order_config.is_lt(meta, None);

            vec![
                q.clone() * sum_check,
                q.clone() * prod_check,
                q * order_check,
            ]
        });

        // 4. (norm_P, norm_C) --lookup--> (norm_U, norm_V)
        meta.lookup_any("normalized_edge_lookup", |meta| {
            let q_person_side = meta.query_selector(q_enable_pc_normalization); // Selector for (norm_P, norm_C)
            let q_pkp_side = meta.query_selector(q_edge); // Selector for (norm_U, norm_V)

            let p_norm0 = meta.query_advice(pc_norm_0, Rotation::cur());
            let p_norm1 = meta.query_advice(pc_norm_1, Rotation::cur());
            let pkp_norm0_lookup = meta.query_advice(pkp_norm_0, Rotation::cur());
            let pkp_norm1_lookup = meta.query_advice(pkp_norm_1, Rotation::cur());

            let one = Expression::Constant(F::ONE);
            // Lookup (1, p_norm0, p_norm1) in (1, pkp_norm0_lookup, pkp_norm1_lookup)
            vec![
                (
                    q_person_side.clone() * one.clone(),
                    q_pkp_side.clone() * one.clone(),
                ),
                (
                    q_person_side.clone() * p_norm0,
                    q_pkp_side.clone() * pkp_norm0_lookup,
                ),
                (q_person_side * p_norm1, q_pkp_side * pkp_norm1_lookup),
            ]
        });

        let source_dist = meta.advice_column();
        let target_dist = meta.advice_column();

        // 5. dist(target) <= dist(source) + 1
        let target_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_edge),
            |meta| vec![meta.query_advice(target_dist, Rotation::cur())],
            |meta| {
                vec![meta.query_advice(source_dist, Rotation::cur()) + Expression::Constant(F::ONE)]
            },
        );
        meta.create_gate("verify target_less", |meta| {
            let q = meta.query_selector(q_edge);
            vec![q.clone() * (target_less.is_lt(meta, None) - Expression::Constant(F::ONE))]
        });

        meta.lookup_any(format!("source dist"), |meta| {
            let q1 = meta.query_selector(q_edge);
            let q2 = meta.query_selector(q_person);
            let a = meta.query_advice(person_knows_person[0], Rotation::cur());
            let b = meta.query_advice(source_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.lookup_any(format!("target dist"), |meta| {
            let q1 = meta.query_selector(q_edge);
            let q2 = meta.query_selector(q_person);
            let a = meta.query_advice(person_knows_person[1], Rotation::cur());
            let b = meta.query_advice(target_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let person_id2 = meta.advice_column();
        let person_id2_dist = meta.advice_column();
        let q_id2 = meta.complex_selector();
        meta.lookup_any(format!("personid2 lookup"), |meta| {
            let q1 = meta.query_selector(q_id2);
            let q2 = meta.query_selector(q_person);
            let a = meta.query_advice(person_id2, Rotation::cur());
            let b = meta.query_advice(person_id2_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        ic13CircuitConfig {
            q_person,
            person,
            person_id,
            person_check,
            person_dist,
            predecessor,
            predecessor_dist,
            person_zero,
            person_knows_person,
            source_dist,
            target_dist,
            target_less,
            q_edge,
            instance,
            pkp_norm_0,
            pkp_norm_1,
            pkp_norm_order_config,
            pc_norm_0,
            pc_norm_1,
            pc_norm_order_config,
            q_enable_pc_normalization,
            person_id2,
            person_id2_dist,
            q_id2,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<F>>,
        person_knows_person: Vec<Vec<F>>,
        person_id1_val: F,
        person_id2_val: F,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        fn f_to_u64<F: Field>(f: &F) -> u64 {
            let repr_bytes = f.to_repr();
            let bytes_ref: &[u8] = repr_bytes.as_ref();
            if bytes_ref.len() < 8 {
                panic!("Field representation too small for u64 extraction");
            }
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&bytes_ref[0..8]);
            u64::from_le_bytes(u64_bytes)
        }

        let mut person_check_bits = vec![false; person_table.len()];
        for (i, row) in person_table.iter().enumerate() {
            if row[0] == person_id1_val {
                person_check_bits[i] = true;
            }
        }
        let chip_person_eq = IsZeroChip::construct(self.config.person_zero.clone());
        let target_less_chip = LtEqGenericChip::construct(self.config.target_less);
        target_less_chip.load(layouter).unwrap();
        let pkp_norm_order_chip =
            LtEqGenericChip::construct(self.config.pkp_norm_order_config.clone());
        let pc_norm_order_chip =
            LtEqGenericChip::construct(self.config.pc_norm_order_config.clone());
        pkp_norm_order_chip.load(layouter).unwrap();
        pc_norm_order_chip.load(layouter).unwrap();

        let dummy_distance_u64: u64 = 100000u64;

        let mut adj: HashMap<F, Vec<F>> = HashMap::new();
        for edge in &person_knows_person {
            adj.entry(edge[0]).or_default().push(edge[1]);
            adj.entry(edge[1]).or_default().push(edge[0]);
        }

        let mut distances: HashMap<F, u64> = HashMap::new();
        let mut predecessors: HashMap<F, F> = HashMap::new();
        let mut q: VecDeque<F> = VecDeque::new();

        for p_row in &person_table {
            distances.insert(p_row[0], dummy_distance_u64);
        }

        if distances.contains_key(&person_id1_val) {
            distances.insert(person_id1_val, 0);
            q.push_back(person_id1_val);
            predecessors.insert(person_id1_val, person_id1_val);
        } else {
            println!("person_id1_val not found in person_table");
        }

        // BFS
        while let Some(u_id) = q.pop_front() {
            let dist_u = distances[&u_id];

            if let Some(neighbors) = adj.get(&u_id) {
                for &v_id in neighbors {
                    if distances
                        .get(&v_id)
                        .map_or(false, |&d| d == dummy_distance_u64)
                    {
                        distances.insert(v_id, dist_u + 1);
                        predecessors.insert(v_id, u_id);
                        q.push_back(v_id);
                    }
                }
            }
        }

        // distances
        //     .iter()
        //     .filter(|(_, &v)| v == 1)
        //     .for_each(|(k, _)| println!("distance=1 Key: {}", f_to_u64(k)));

        let personid2_dist = distances.get(&person_id2_val).cloned().unwrap();
        // println!("personid2_dist:{}", personid2_dist);

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                region.assign_advice(
                    || format!("person_id2"),
                    self.config.person_id2,
                    0,
                    || Value::known(person_id2_val),
                )?;
                region.assign_advice(
                    || format!("person_id2"),
                    self.config.person_id2_dist,
                    0,
                    || Value::known(F::from(personid2_dist)),
                )?;
                self.config.q_id2.enable(&mut region, 0)?;

                for (i, row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;

                    for j in 0..8 {
                        region.assign_advice(
                            || format!("person col {} row {}", j, i),
                            self.config.person[j],
                            i,
                            || Value::known(row[j]),
                        )?;
                    }

                    region.assign_advice(
                        || "person_check",
                        self.config.person_check,
                        i,
                        || Value::known(F::from(person_check_bits[i] as u64)),
                    )?;

                    region.assign_advice(
                        || format!("person id {}", i),
                        self.config.person_id,
                        i,
                        || Value::known(person_id1_val),
                    )?;

                    let diff = row[0] - person_id1_val;
                    chip_person_eq
                        .assign(&mut region, i, Value::known(diff))
                        .unwrap();

                    let calculated_dist = distances
                        .get(&row[0])
                        .cloned()
                        .unwrap_or(dummy_distance_u64);
                    let person_dist_val = F::from(calculated_dist);

                    region.assign_advice(
                        || format!("person_dist for row {}", i),
                        self.config.person_dist,
                        i,
                        || Value::known(person_dist_val),
                    )?;

                    let (predecessor_val, predecessor_dist) = if row[0] == person_id1_val {
                        (row[0], F::ZERO)
                    } else if calculated_dist != dummy_distance_u64 {
                        self.config
                            .q_enable_pc_normalization
                            .enable(&mut region, i)?;
                        let pred_id = predecessors.get(&row[0]).cloned().unwrap();
                        (pred_id, F::from(calculated_dist - 1))
                    } else {
                        // dummy
                        (row[0], F::from(dummy_distance_u64))
                    };

                    region.assign_advice(
                        || format!("predecessor for row {}", i),
                        self.config.predecessor,
                        i,
                        || Value::known(predecessor_val),
                    )?;
                    region.assign_advice(
                        || format!("predecessor_dist for row {}", i),
                        self.config.predecessor_dist,
                        i,
                        || Value::known(predecessor_dist),
                    )?;

                    if row[0] != person_id1_val && calculated_dist != dummy_distance_u64 {
                        self.config
                            .q_enable_pc_normalization
                            .enable(&mut region, i)?; // Enable person side of lookup and PC normalization

                        let p_val = predecessor_val;
                        let c_val = row[0];
                        let norm_p = min(p_val, c_val);
                        let norm_c = max(p_val, c_val);
                        region.assign_advice(
                            || "pc_norm_0",
                            self.config.pc_norm_0,
                            i,
                            || Value::known(norm_p),
                        )?;
                        region.assign_advice(
                            || "pc_norm_1",
                            self.config.pc_norm_1,
                            i,
                            || Value::known(norm_c),
                        )?;
                        // Assign to pc_norm_order_chip: checks norm_c < norm_p is false
                        pc_norm_order_chip
                            .assign(&mut region, i, &[norm_c], &[norm_p])
                            .unwrap();
                    }
                }

                for (i, edge) in person_knows_person.iter().enumerate() {
                    self.config.q_edge.enable(&mut region, i)?;

                    let u_val = edge[0];
                    let v_val = edge[1];
                    let source_dist = distances.get(&u_val).cloned().unwrap();
                    let target_dist = distances.get(&v_val).cloned().unwrap();

                    region.assign_advice(
                        || format!("person_knows_person at {}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(u_val),
                    )?;

                    region.assign_advice(
                        || format!("person_knows_person at {}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(v_val),
                    )?;

                    let norm_u = min(u_val, v_val);
                    let norm_v = max(u_val, v_val);
                    region.assign_advice(
                        || "pkp_norm_0",
                        self.config.pkp_norm_0,
                        i,
                        || Value::known(norm_u),
                    )?;
                    region.assign_advice(
                        || "pkp_norm_1",
                        self.config.pkp_norm_1,
                        i,
                        || Value::known(norm_v),
                    )?;
                    // Assign to pkp_norm_order_chip: checks norm_v < norm_u is false
                    pkp_norm_order_chip
                        .assign(&mut region, i, &[norm_v], &[norm_u])
                        .unwrap();

                    region.assign_advice(
                        || format!("source_dist for edge at {}", i),
                        self.config.source_dist,
                        i,
                        || Value::known(F::from(source_dist)),
                    )?;
                    region.assign_advice(
                        || format!("target_dist for edge at {}", i),
                        self.config.target_dist,
                        i,
                        || Value::known(F::from(target_dist)),
                    )?;

                    target_less_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(target_dist)],
                            &[F::from(source_dist) + F::ONE],
                        )
                        .unwrap();
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
    pub person_id1: F,
    pub person_id2: F,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord + std::hash::Hash> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_knows_person: Default::default(),
            person_id1: Default::default(),
            person_id2: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord + std::hash::Hash> Circuit<F> for MyCircuit<F> {
    type Config = ic13CircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ic13Chip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::ErrorFront> {
        let chip = ic13Chip::construct(config.clone());

        chip.assign(
            &mut layouter.namespace(|| "Assign"),
            self.person.clone(),
            self.person_knows_person.clone(),
            self.person_id1,
            self.person_id2,
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
    fn test_ic13_circuit() {
        let k = 16;

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let relation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_knows_person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");

        let mut person_table: Vec<Vec<Fr>> = Vec::new();
        for (_, row) in person_data.iter().enumerate() {
            let person_row = vec![
                Fr::from(row[0].parse::<u64>().expect("invalid Person ID")),
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
                Fr::from(row[0].parse::<u64>().expect("invalid Person ID")),
                Fr::from(row[1].parse::<u64>().expect("invalid Person ID")),
            ];
            person_knows_person.push(r_row);
        }

        println!("person:{:?}", person_table.len());
        println!("person_knows_person.len:{:?}", person_knows_person.len());

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_knows_person,
            person_id1: Fr::from(32985348833679),
            person_id2: Fr::from(26388279067108),
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
