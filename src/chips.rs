pub mod is_zero;
pub mod lessthan_or_equal_generic;

use halo2_proofs::{halo2curves::ff::PrimeField, plonk::Expression};

pub fn bool_check<F: PrimeField>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

pub fn range_check<F: PrimeField>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        let i_as_field_element = F::from(i as u64); // Hypothetical method; replace with your field's equivalent
        acc * (Expression::Constant(i_as_field_element) - word.clone())
    })
}
