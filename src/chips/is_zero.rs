use halo2_proofs::{
    circuit::*, halo2curves::ff::PrimeField, plonk::Expression, plonk::*, poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct IsZeroConfig<F: PrimeField> {
    pub is_zero: Column<Advice>,
    pub value_inv: Column<Advice>,
    pub is_zero_expr: Expression<F>,
}

impl<F: PrimeField> IsZeroConfig<F> {
    pub fn expr(&self) -> Expression<F> {
        self.is_zero_expr.clone()
    }

    pub fn is_zero(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        meta.query_advice(self.is_zero, rotation.unwrap_or_else(Rotation::cur))
    }
}

pub struct IsZeroChip<F: PrimeField> {
    config: IsZeroConfig<F>,
}

impl<F: PrimeField> IsZeroChip<F> {
    pub fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value_inv: Column<Advice>,
        is_zero: Column<Advice>,
    ) -> IsZeroConfig<F> {
        let mut is_zero_expr = Expression::Constant(F::ZERO);

        meta.create_gate("is_zero", |meta| {
            let value = value(meta);
            let q_enable = q_enable(meta);
            let value_inv = meta.query_advice(value_inv, Rotation::cur());
            let is_zero_value = meta.query_advice(is_zero, Rotation::cur());

            is_zero_expr = Expression::Constant(F::ONE) - value.clone() * value_inv.clone();

            let check_is_zero = is_zero_value - is_zero_expr.clone();

            vec![
                q_enable.clone() * value * is_zero_expr.clone(),
                q_enable * check_is_zero,
            ]
        });

        IsZeroConfig {
            is_zero,
            value_inv,
            is_zero_expr,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let value_inv = value.map(|value| value.invert().unwrap_or(F::ZERO));

        let is_zero_value = value.map(|value| if value == F::ZERO { F::ONE } else { F::ZERO });

        region.assign_advice(|| "is zero", self.config.is_zero, offset, || is_zero_value)?;

        region.assign_advice(|| "value inv", self.config.value_inv, offset, || value_inv)?;

        Ok(())
    }
}
