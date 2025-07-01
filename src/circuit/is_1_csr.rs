use crate::chips::is_zero::IsZeroChip;
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::data::csr::CsrValue;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::halo2curves::ff_ext::quadratic;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use itertools::max;
use std::cmp;
use std::marker::PhantomData;

const NUM_BYTES: usize = 6;
pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}
/*
IS1. Profile of a person
:param personId: 10995116277794
MATCH (n:Person {id: $personId })-[:IS_LOCATED_IN]->(p:City)
RETURN
    n.firstName AS firstName,
    n.lastName AS lastName,
    n.birthday AS birthday,
    n.locationIP AS locationIP,
    n.browserUsed AS browserUsed,
    p.id AS cityId,
    n.gender AS gender,
    n.creationDate AS creationDate
*/

#[derive(Clone, Debug)]
pub struct Is1CircuitConfig<F: Field + Ord> {
    q_person: Selector,

    person: Vec<Column<Advice>>,
    person_id: Column<Advice>,
    person_check: Column<Advice>,

    index: Column<Advice>,

    csr_row: Column<Advice>,
    csr_column: Column<Advice>,

    q_row: Selector,

    q_shuffle_row_range: Selector,
    q_table_row_range: Selector,
    shuffle_start_offset: Column<Advice>,
    shuffle_end_offset: Column<Advice>,

    lte_start: LtEqGenericConfig<F, NUM_BYTES>,
    lte_end: LtEqGenericConfig<F, NUM_BYTES>,

    q_column: Selector,
    q_selected_column: Selector,
    q_not_selected_column: Selector,

    result: Vec<Column<Advice>>,
    q_result_person: Vec<Selector>,

    person_zero: crate::chips::is_zero::IsZeroConfig<F>,

    instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct Is1Chip<F: Field + Ord> {
    config: Is1CircuitConfig<F>,
}

impl<F: Field + Ord> Is1Chip<F> {
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

        let csr_row = meta.advice_column();

        let shuffle_start_offset = meta.advice_column();
        let shuffle_end_offset = meta.advice_column();

        let csr_column = meta.advice_column();

        meta.enable_equality(shuffle_start_offset);
        meta.enable_equality(shuffle_end_offset);
        meta.enable_equality(csr_column);

        let q_person = meta.selector();

        let index = meta.advice_column();

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

        let q_shuffle_row_range = meta.complex_selector();
        let q_table_row_range = meta.complex_selector();

        let one = Expression::Constant(F::ONE);

        meta.shuffle("shuffle row range", |meta| {
            let s_shuffle = meta.query_selector(q_shuffle_row_range);
            let s_table = meta.query_selector(q_table_row_range);

            let start = meta.query_advice(shuffle_start_offset, Rotation::cur());
            let end = meta.query_advice(shuffle_end_offset, Rotation::cur());

            let table_start = meta.query_advice(csr_row, Rotation::cur());
            let table_end = meta.query_advice(csr_row, Rotation::next());

            let lhs = [one.clone(), start, end].map(|c| c * s_shuffle.clone());
            let rhs = [one.clone(), table_start, table_end].map(|c| c * s_table.clone());

            lhs.into_iter().zip(rhs).collect()
        });

        let q_row = meta.selector();
        meta.create_gate("verify q_table_row_range", |meta| {
            let q_r = meta.query_selector(q_row);
            let q = meta.query_selector(q_table_row_range);
            let check = meta.query_advice(person_check, Rotation::cur());
            vec![q_r * (q.clone() - check)]
        });

        let q_selected_column = meta.complex_selector();
        let q_not_selected_column = meta.complex_selector();

        let mut result = Vec::new();
        for _ in 0..9 {
            result.push(meta.advice_column());
        }

        let mut q_result_person = Vec::new();
        for _ in 0..2 {
            q_result_person.push(meta.complex_selector());
        }

        // meta.lookup_any(format!("result_person_lookup"), |meta| {
        //     let q1 = meta.query_selector(q_result_person[0]);
        //     let q2 = meta.query_selector(q_result_person[1]);
        //     let r1 = meta.query_advice(result[0], Rotation::cur());
        //     let r2 = meta.query_advice(result[1], Rotation::cur());
        //     let r3 = meta.query_advice(result[2], Rotation::cur());
        //     let r4 = meta.query_advice(result[3], Rotation::cur());
        //     let r5 = meta.query_advice(result[4], Rotation::cur());
        //     let r6 = meta.query_advice(result[5], Rotation::cur());
        //     let r7 = meta.query_advice(result[6], Rotation::cur());
        //     let r8 = meta.query_advice(result[7], Rotation::cur());
        //     let p1 = meta.query_advice(person[0], Rotation::cur());
        //     let p2 = meta.query_advice(person[1], Rotation::cur());
        //     let p3 = meta.query_advice(person[2], Rotation::cur());
        //     let p4 = meta.query_advice(person[3], Rotation::cur());
        //     let p5 = meta.query_advice(person[4], Rotation::cur());
        //     let p6 = meta.query_advice(person[5], Rotation::cur());
        //     let p7 = meta.query_advice(person[6], Rotation::cur());
        //     let p8 = meta.query_advice(person[7], Rotation::cur());
        //     let lhs = [one.clone(), r1, r2, r3, r4, r5, r6, r7, r8].map(|c| c * q1.clone());
        //     let rhs = [one.clone(), p1, p2, p3, p4, p5, p6, p7, p8].map(|c| c * q2.clone());
        //     lhs.into_iter().zip(rhs).collect()
        // });

        meta.shuffle(format!("shuffle"), |meta| {
            let s_shuffle = meta.query_selector(q_result_person[0]);
            let q_selected_column = meta.query_selector(q_selected_column);
            let result = meta.query_advice(result[8], Rotation::cur());
            let iter = meta.query_advice(csr_column, Rotation::cur());
            let lhs = [one.clone(), result].map(|c| c * s_shuffle.clone());
            let rhs = [one.clone(), iter].map(|c| c * q_selected_column.clone());
            lhs.into_iter().zip(rhs).collect()
        });

        let q_column = meta.selector();
        let lte_start = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_column),
            |meta| vec![meta.query_advice(shuffle_start_offset, Rotation::cur())],
            |meta| vec![meta.query_advice(index, Rotation::cur())],
        );
        let lte_end = LtEqGenericChip::configure(
            meta,
            |meta| meta.query_selector(q_column),
            |meta| vec![meta.query_advice(shuffle_end_offset, Rotation::cur())],
            |meta| vec![meta.query_advice(index, Rotation::cur())],
        );

        meta.create_gate(
            "verify q_selected_column + q_not_selected_column = 1",
            |meta| {
                let q_c = meta.query_selector(q_column);
                let q1 = meta.query_selector(q_selected_column);
                let q2 = meta.query_selector(q_not_selected_column);
                vec![q_c * (q1 + q2 - one.clone())]
            },
        );

        // start <= index < end
        meta.create_gate("verify selected_column", |meta| {
            let q_c = meta.query_selector(q_selected_column);
            let lte_start = lte_start.is_lt(meta, None);
            let lte_end = lte_end.is_lt(meta, None);
            vec![
                q_c.clone() * (lte_start - one.clone()),
                q_c.clone() * (lte_end),
            ]
        });

        meta.create_gate("verify not_selected_column", |meta| {
            let q_c = meta.query_selector(q_not_selected_column);
            let lte_start = lte_start.is_lt(meta, None);
            let lte_end = lte_end.is_lt(meta, None);
            vec![q_c.clone() * lte_start * (lte_end - one.clone())]
        });

        Is1CircuitConfig {
            q_person,
            q_shuffle_row_range,
            q_table_row_range,
            q_selected_column,
            person,
            person_id,
            person_check,
            csr_row,
            shuffle_start_offset,
            shuffle_end_offset,
            csr_column,
            person_zero,
            instance,
            result,
            q_result_person,
            index,
            q_row,
            lte_start,
            lte_end,
            q_column,
            q_not_selected_column,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        person_table: Vec<Vec<F>>,
        person_to_place_csr: CsrValue<F>,
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

        let n_edges = person_to_place_csr.column.len();

        let mut person_idx = 0;
        let mut person_check_bits = vec![false; person_table.len()];
        for (i, row) in person_table.iter().enumerate() {
            if row[0] == person_id_val {
                person_idx = i;
                person_check_bits[i] = true;
            }
        }

        // get the start and end offsets of the places associated with this Person in the person_to_place_csr.column array
        let actual_start_offset = f_to_u64(&person_to_place_csr.row[person_idx]) as usize;
        let actual_end_offset = if person_idx + 1 < person_to_place_csr.row.len() {
            f_to_u64(&person_to_place_csr.row[person_idx + 1]) as usize
        } else {
            n_edges
        };
        let mut expected_places = Vec::new();
        for i in actual_start_offset..actual_end_offset {
            if i < n_edges {
                expected_places.push(person_to_place_csr.column[i]);
            }
        }

        let mut result_rows = Vec::new();
        let found_person = person_table
            .iter()
            .find(|row| row[0] == person_id_val)
            .cloned();

        if let Some(person_row) = found_person {
            for place_id in &expected_places {
                let mut result_row = person_row.clone();
                result_row.push(*place_id);
                result_rows.push(result_row);
            }
        }

        let mut actual_found_places = Vec::new();
        for i in actual_start_offset..actual_end_offset {
            if i < n_edges {
                actual_found_places.push(person_to_place_csr.column[i]);
            }
        }

        let chip_person_eq = IsZeroChip::construct(self.config.person_zero.clone());
        let lte_start_chip =
            LtEqGenericChip::<F, NUM_BYTES>::construct(self.config.lte_start.clone());
        let lte_end_chip = LtEqGenericChip::<F, NUM_BYTES>::construct(self.config.lte_end.clone());
        lte_start_chip.load(layouter).unwrap();
        lte_end_chip.load(layouter).unwrap();

        layouter.assign_region(
            || "Witness Assignment",
            |mut region| {
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

                    let cell_check = region.assign_advice(
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

                    if person_check_bits[i] {
                        self.config.q_table_row_range.enable(&mut region, i)?;
                    }

                    self.config.q_result_person[1].enable(&mut region, i)?;
                }

                for i in 0..person_to_place_csr.row.len() {
                    region.assign_advice(
                        || format!("csr_row {}", i),
                        self.config.csr_row,
                        i,
                        || Value::known(person_to_place_csr.row[i]),
                    )?;
                    if i != person_to_place_csr.row.len() - 1 {
                        self.config.q_row.enable(&mut region, i)?;
                    }
                }

                region.assign_advice(
                    || format!("shuffle_start"),
                    self.config.shuffle_start_offset,
                    0,
                    || Value::known(F::from(actual_start_offset as u64)),
                )?;
                region.assign_advice(
                    || format!("shuffle_end"),
                    self.config.shuffle_end_offset,
                    0,
                    || Value::known(F::from(actual_end_offset as u64)),
                )?;
                self.config.q_shuffle_row_range.enable(&mut region, 0)?;

                for i in 0..person_to_place_csr.column.len() {
                    region.assign_advice(
                        || format!("csr_column {}", i),
                        self.config.csr_column,
                        i,
                        || Value::known(person_to_place_csr.column[i]),
                    )?;

                    self.config.q_column.enable(&mut region, i)?;
                    if (actual_start_offset..actual_end_offset).contains(&i) {
                        self.config.q_selected_column.enable(&mut region, i)?;
                    } else {
                        self.config.q_not_selected_column.enable(&mut region, i)?;
                    }
                    region.assign_advice(
                        || format!("shuffle_start"),
                        self.config.shuffle_start_offset,
                        i,
                        || Value::known(F::from(actual_start_offset as u64)),
                    )?;
                    region.assign_advice(
                        || format!("shuffle_end"),
                        self.config.shuffle_end_offset,
                        i,
                        || Value::known(F::from(actual_end_offset as u64)),
                    )?;

                    lte_start_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(actual_start_offset as u64)],
                            &[F::from(i as u64)],
                        )
                        .unwrap();
                    lte_end_chip
                        .assign(
                            &mut region,
                            i,
                            &[F::from(actual_end_offset as u64)],
                            &[F::from(i as u64)],
                        )
                        .unwrap();
                }

                for (i, result_row) in result_rows.iter().enumerate() {
                    for (j, &value) in result_row.iter().enumerate() {
                        region.assign_advice(
                            || format!("result row {} col {}", i, j),
                            self.config.result[j],
                            i,
                            || Value::known(value),
                        )?;
                    }

                    self.config.q_result_person[0].enable(&mut region, i)?;
                }

                for i in 0..cmp::max(
                    person_to_place_csr.row.len(),
                    person_to_place_csr.column.len(),
                ) {
                    region.assign_advice(
                        || format!("index"),
                        self.config.index,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

pub struct MyCircuit<F: Field + Ord> {
    pub person: Vec<Vec<F>>,
    pub person_to_place: CsrValue<F>,
    pub person_id: F,
    pub _marker: PhantomData<F>,
}

impl<F: Copy + Default + Field + Ord> Default for MyCircuit<F> {
    fn default() -> Self {
        Self {
            person: Vec::new(),
            person_to_place: Default::default(),
            person_id: Default::default(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field + Ord> Circuit<F> for MyCircuit<F> {
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
            self.person_to_place.clone(),
            self.person_id,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::utils::{parse_date, parse_datetime, read_csv};
    use crate::data::csr::CsrValue;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use serde::de::Expected;
    use std::collections::HashMap;
    use std::time::Instant;

    #[test]
    fn test_is1_circuit() {
        let k = 16;

        let person_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let place_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/place_0_0.csv",
            '|',
        )
        .expect("Failed to read data");
        let relation_data = read_csv(
            "/home/wh/zkgraph/src/data/person_fact/60k/person_isLocatedIn_place_0_0.csv",
            '|',
        )
        .expect("Failed to read data");

        let mut person_id_to_index = HashMap::new();
        let mut person_table: Vec<Vec<Fr>> = Vec::new();
        for (i, row) in person_data.iter().enumerate() {
            let id = row[0].parse::<u64>().expect("invalid Person ID");
            person_id_to_index.insert(id, i);
            let person_row = vec![
                Fr::from(id),
                Fr::from(0),
                Fr::from(0),
                Fr::from(if row[3] == "male" { 1 } else { 0 }),
                Fr::from(parse_date(&row[4])),
                Fr::from(parse_datetime(&row[5])),
                Fr::from(0),
                Fr::from(0),
            ];
            person_table.push(person_row);
        }

        let mut place_id_to_index = HashMap::new();
        for (i, row) in place_data.iter().enumerate() {
            if row.is_empty() || row[0].is_empty() {
                continue;
            }
            let id = row[0].parse::<u64>().expect("invalid Place ID");
            place_id_to_index.insert(id, i);
        }

        let mut edges: Vec<(u64, u64)> = Vec::new();
        let mut person_to_places_map = HashMap::<u64, Vec<u64>>::new();
        for row in &relation_data {
            let person_id = row[0].parse::<u64>().expect("invalid Person ID");
            let place_id = row[1].parse::<u64>().expect("invalid Place ID");
            if let (Some(&p_idx), Some(&pl_idx)) = (
                person_id_to_index.get(&person_id),
                place_id_to_index.get(&place_id),
            ) {
                let place_idx_fr = pl_idx as u64;
                edges.push((p_idx as u64, pl_idx as u64));
                person_to_places_map
                    .entry(p_idx as u64)
                    .or_default()
                    .push(place_idx_fr);
            }
        }
        edges.sort_by_key(|&(p_idx, _)| p_idx);
        let person_to_place_csr = CsrValue::<Fr>::from_sorted_edges(&edges).expect("construct csr failed");

        println!(
            "person_to_place_csr.len:{:?}",
            person_to_place_csr.row.len()
        );
        println!("person:{:?}", person_table.len());

        let test_person_id_val: u64 = 30786325578904;
        let person_id_fr = Fr::from(test_person_id_val);
        let test_person_idx = person_id_to_index
            .get(&test_person_id_val)
            .expect("Person ID not found in the data");
        println!("Person ID: {}", test_person_id_val);
        println!("Person Index: {}", test_person_idx);

        let circuit = MyCircuit::<Fr> {
            person: person_table,
            person_to_place: person_to_place_csr,
            person_id: person_id_fr,
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
