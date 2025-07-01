use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::data::csr::CsrValue;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

const NUM_BYTES: usize = 6;

/*
MATCH path = shortestPath((p)-[:KNOWS*1..3]->(friend))
*/

#[derive(Clone, Debug)]
pub struct Is1CircuitConfig<F: Field + Ord + std::hash::Hash> {
    q_person: Selector,
    q_pre_lookup: Selector,

    person: Vec<Column<Advice>>,
    person_id: Column<Advice>,
    person_check: Column<Advice>,
    // node
    person_dist: Column<Advice>,
    predecessor: Column<Advice>,
    predecessor_dist: Column<Advice>,
    person_zero: crate::chips::is_zero::IsZeroConfig<F>,

    person_knows_person: Vec<Column<Advice>>,
    // edge
    source_dist: Column<Advice>,
    target_dist: Column<Advice>,
    target_less: LtEqGenericConfig<F, NUM_BYTES>,
    q_target_less: Selector,
    q_edge: Selector,
    q_edge_exists: Vec<Selector>,

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
        let person_check = meta.advice_column();
        meta.enable_equality(person_check);

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
            person_check,
        );

        let person_dist = meta.advice_column();
        let predecessor = meta.advice_column();
        let predecessor_dist = meta.advice_column();

        let q_pre_lookup = meta.complex_selector();
        let one = Expression::Constant(F::ONE);
        meta.lookup_any(format!("predecessor + predecessor_dist"), |meta| {
            let q = meta.query_selector(q_pre_lookup);
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
                    * (dist - Expression::Constant(F::from(5u64))),
            ]
        });

        let mut person_knows_person = Vec::new();
        for _ in 0..2 {
            person_knows_person.push(meta.advice_column());
        }

        let mut q_edge_exists = Vec::new();
        for _ in 0..2 {
            q_edge_exists.push(meta.complex_selector());
        }
        meta.lookup_any(format!("predecessor + cur_node"), |meta| {
            let q1 = meta.query_selector(q_edge_exists[0]);
            let q2 = meta.query_selector(q_edge_exists[1]);
            let a = meta.query_advice(predecessor, Rotation::cur());
            let b = meta.query_advice(person[0], Rotation::cur());
            let c = meta.query_advice(person_knows_person[0], Rotation::cur());
            let d = meta.query_advice(person_knows_person[1], Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q1.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q2.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let source_dist = meta.advice_column();
        let target_dist = meta.advice_column();

        let q_target_less = meta.selector();
        let target_less = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_target_less),
            |meta| vec![meta.query_advice(target_dist, Rotation::cur())],
            |meta| {
                vec![meta.query_advice(source_dist, Rotation::cur()) + Expression::Constant(F::ONE)]
            },
        );
        meta.create_gate("verify target_less", |meta| {
            let q = meta.query_selector(q_target_less);
            vec![q.clone() * (target_less.is_lt(meta, None) - Expression::Constant(F::ONE))]
        });

        let q_edge = meta.complex_selector();
        meta.lookup_any(format!("source dist"), |meta| {
            let q = meta.query_selector(q_edge);
            let a = meta.query_advice(person_knows_person[0], Rotation::cur());
            let b = meta.query_advice(source_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        meta.lookup_any(format!("target dist"), |meta| {
            let q = meta.query_selector(q_edge);
            let a = meta.query_advice(person_knows_person[1], Rotation::cur());
            let b = meta.query_advice(target_dist, Rotation::cur());
            let c = meta.query_advice(person[0], Rotation::cur());
            let d = meta.query_advice(person_dist, Rotation::cur());
            let lhs = [one.clone(), a, b].map(|c| c * q.clone());
            let rhs = [one.clone(), c, d].map(|c| c * q.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        Is1CircuitConfig {
            q_person,
            q_pre_lookup,
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
            q_target_less,
            q_edge,
            q_edge_exists,
            instance,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<F>>,
        person_knows_person: Vec<Vec<F>>,
        person_id_val: F,
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
            if row[0] == person_id_val {
                person_check_bits[i] = true;
            }
        }
        let chip_person_eq = IsZeroChip::construct(self.config.person_zero.clone());
        let target_less_chip = LtEqGenericChip::construct(self.config.target_less);
        target_less_chip.load(layouter).unwrap();

        let max_hops = 4;
        let dummy_distance_u64: u64 = (max_hops + 1) as u64;

        let mut adj: HashMap<F, Vec<F>> = HashMap::new();
        for edge in &person_knows_person {
            adj.entry(edge[0]).or_default().push(edge[1]);
        }

        let mut distances: HashMap<F, u64> = HashMap::new();
        let mut predecessors: HashMap<F, F> = HashMap::new();
        let mut q: VecDeque<F> = VecDeque::new(); 

        for p_row in &person_table {
            distances.insert(p_row[0], dummy_distance_u64);
        }

        if distances.contains_key(&person_id_val) {
            distances.insert(person_id_val, 0); 
            q.push_back(person_id_val); 
            predecessors.insert(person_id_val, person_id_val);
        } else {
            println!("person_id_val not found in person_table");
        }

        // BFS
        while let Some(u_id) = q.pop_front() {
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

        layouter.assign_region(
            || "witness assignment",
            |mut region| {
                for (i, row) in person_table.iter().enumerate() {
                    self.config.q_person.enable(&mut region, i)?;
                    self.config.q_pre_lookup.enable(&mut region, i)?;

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
                        || Value::known(person_id_val),
                    )?;

                    let diff = row[0] - person_id_val;
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

                    let (predecessor_val, predecessor_dist) = if row[0] == person_id_val {
                        (row[0], F::ZERO)
                    } else if calculated_dist != dummy_distance_u64 {
                        self.config.q_edge_exists[0].enable(&mut region, i)?;
                        let pred_id = predecessors.get(&row[0]).cloned().unwrap();
                        (pred_id, F::from(calculated_dist - 1))
                    } else {
                        // dummy
                        (row[0], F::from(max_hops+1))
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
                }

                for (i, edge) in person_knows_person.iter().enumerate() {
                    self.config.q_edge_exists[1].enable(&mut region, i)?;
                    self.config.q_target_less.enable(&mut region, i)?;
                    self.config.q_edge.enable(&mut region, i)?;

                    let source_node_id = edge[0];
                    let target_node_id = edge[1];
                    let source_dist = distances.get(&source_node_id).cloned().unwrap();
                    let target_dist = distances.get(&target_node_id).cloned().unwrap();

                    region.assign_advice(
                        || format!("edge_source_node at {}", i),
                        self.config.person_knows_person[0],
                        i,
                        || Value::known(source_node_id),
                    )?;

                    region.assign_advice(
                        || format!("edge_target_node at {}", i),
                        self.config.person_knows_person[1],
                        i,
                        || Value::known(target_node_id),
                    )?;

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
    fn test_is1_circuit() {
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

        let test_person_id_val: u64 = 933;
        let person_id_fr = Fr::from(test_person_id_val);

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_knows_person,
            person_id: person_id_fr,
            _marker: PhantomData,
        };

        let public_input = vec![Fr::from(1)];
        let start = Instant::now();
        let prover = MockProver::run(k, &circuit, vec![public_input]).expect("MockProver fail");
        println!("Proving times: {:?}", start.elapsed());

        match prover.verify() {
            Ok(_) => println!("verification success!"),
            Err(e) => {
                panic!("verification failed{:?}", e);
            }
        }
    }
}
