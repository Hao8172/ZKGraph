use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, TableColumn, VirtualCells},
    poly::Rotation,
};
use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Expression};
use std::cmp::Ord;

pub trait Field: PrimeField {}
impl<F> Field for F where F: PrimeField {}

use super::{
    super::util::{expr_from_bytes, pow_of_two},
    bool_check,
};

pub trait LtEqGenericInstruction<F: Field + Ord> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: &[F],
        rhs: &[F],
    ) -> Result<(), Error>;

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug)]
pub struct LtEqGenericConfig<F: Field + Ord, const N_BYTES: usize> {
    pub lt: Column<Advice>,
    pub diff: [Column<Advice>; N_BYTES],
    pub u8: TableColumn,
    pub range: F,
}

impl<F: Field + Ord, const N_BYTES: usize> LtEqGenericConfig<F, N_BYTES> {
    pub fn is_lt(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }
}

#[derive(Clone, Debug)]
pub struct LtEqGenericChip<F: Field + Ord, const N_BYTES: usize> {
    config: LtEqGenericConfig<F, N_BYTES>,
}

impl<F: Field + Ord, const N_BYTES: usize> LtEqGenericChip<F, N_BYTES> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lhs: impl FnOnce(&mut VirtualCells<F>) -> Vec<Expression<F>>,
        rhs: impl FnOnce(&mut VirtualCells<F>) -> Vec<Expression<F>>,
    ) -> LtEqGenericConfig<F, N_BYTES> {
        let lt = meta.advice_column();
        let diff = [(); N_BYTES].map(|_| meta.advice_column());
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt generic gate", |meta| {
            let q_enable = q_enable(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let diff_bytes = diff
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<F>>>();
            let one_expression = Expression::Constant(F::from(1));

            let lhs_vals = lhs(meta);
            let rhs_vals = rhs(meta);
            let mut lhs_sum = Expression::Constant(F::ZERO);
            let mut rhs_sum = Expression::Constant(F::ZERO);

            for expr in &lhs_vals {
                lhs_sum = lhs_sum + expr.clone();
            }
            for expr in &rhs_vals {
                rhs_sum = rhs_sum + expr.clone();
            }
            let check_a = lhs_sum - (rhs_sum + one_expression) - expr_from_bytes(&diff_bytes)
                + (lt.clone() * range);

            let check_b = bool_check(lt);

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        let u8 = meta.lookup_table_column();

        diff[0..N_BYTES].iter().for_each(|column| {
            meta.lookup("range check for u8", |meta| {
                let u8_cell = meta.query_advice(*column, Rotation::cur());
                vec![(u8_cell, u8)]
            });
        });

        LtEqGenericConfig {
            lt,
            diff,
            range,
            u8,
        }
    }

    pub fn construct(config: LtEqGenericConfig<F, N_BYTES>) -> LtEqGenericChip<F, N_BYTES> {
        LtEqGenericChip { config }
    }
}

impl<F: Field + Ord, const N_BYTES: usize> LtEqGenericInstruction<F>
    for LtEqGenericChip<F, N_BYTES>
{
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: &[F],
        rhs: &[F],
    ) -> Result<(), Error> {
        let config = self.config();

        // let shift_amount = std::cmp::min(N_BYTES * 8, 63);
        // let con1 = lhs * F::from(1u64 << shift_amount) + rhs;
        // let con2 = lhs1 * F::from(1u64 << shift_amount) + rhs1;
        let mut lhs_sum = F::ZERO;
        let mut rhs_sum = F::ZERO;

        for expr in lhs {
            lhs_sum = lhs_sum + expr.clone();
        }
        for expr in rhs {
            rhs_sum = rhs_sum + expr.clone();
        }

        let lt = lhs_sum < (rhs_sum + F::ONE);

        // println!("Anything wrong here? {:?} {:?}", con1, con2);

        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || Value::known(F::from(lt as u64)),
        )?;

        let diff = (lhs_sum - (rhs_sum + F::ONE)) + (if lt { config.range } else { F::ZERO });
        let diff_bytes = diff.to_repr();
        let diff_bytes = diff_bytes.as_ref();
        for (idx, diff_column) in config.diff.iter().enumerate() {
            region.assign_advice(
                || format!("lt chip: diff byte {}", idx),
                *diff_column,
                offset,
                || Value::known(F::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }

    fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        const RANGE: usize = 256;

        layouter.assign_table(
            || "8-bit table",
            |mut table| {
                for i in 0..RANGE {
                    table.assign_cell(
                        || format!("row {i}"),
                        self.config.u8,
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

impl<F: Field + Ord, const N_BYTES: usize> Chip<F> for LtEqGenericChip<F, N_BYTES> {
    type Config = LtEqGenericConfig<F, N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
