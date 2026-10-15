//! Exponential-sum representation of pharmacokinetic signals.
//!
//! Every dose response in this engine is a sum of terms `coeff * exp(-lambda * t)`.
//! One-compartment disposition is one term, two-compartment is two, a metabolite is
//! the convolution of a parent signal with `exp(-k_out * t)` -- which is again a sum
//! of exponentials. Superposition of many doses is concatenation of term lists.
//!
//! Time is in seconds throughout, amounts in mg.

/// A single term `coeff * exp(-lambda * t)`. `lambda == 0.0` is a constant term,
/// which arises during zero-order absorption.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpTerm {
    pub coeff: f64,
    pub lambda: f64,
}

/// Two rate constants closer than this are treated as equal, which would make the
/// convolution denominator `(k_out - lambda)` blow up. We nudge them apart instead of
/// introducing a `t * exp(-lambda t)` term type: the error is far below the accuracy
/// of the underlying PK parameters, which are population estimates to begin with.
const LAMBDA_EPS: f64 = 1e-9;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExpSum {
    pub terms: Vec<ExpTerm>,
}

impl ExpSum {
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    pub fn single(coeff: f64, lambda: f64) -> Self {
        Self { terms: vec![ExpTerm { coeff, lambda }] }
    }

    pub fn from_terms(terms: impl IntoIterator<Item = (f64, f64)>) -> Self {
        Self {
            terms: terms
                .into_iter()
                .map(|(coeff, lambda)| ExpTerm { coeff, lambda })
                .collect(),
        }
    }

    /// Evaluate at local time `t` (seconds since this signal's own origin).
    pub fn eval(&self, t: f64) -> f64 {
        self.terms
            .iter()
            .map(|term| term.coeff * (-term.lambda * t).exp())
            .sum()
    }

    /// The time derivative, which is again a sum of exponentials.
    ///
    /// d/dt [c * e^(-lambda t)] = -lambda * c * e^(-lambda t). So the representation is
    /// closed under differentiation: no numerical difference quotient, no step size to
    /// choose, no noise. The constant term a zero-order infusion carries has lambda 0
    /// and correctly differentiates to nothing.
    pub fn derivative(&self) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .map(|t| ExpTerm { coeff: -t.lambda * t.coeff, lambda: t.lambda })
                .collect(),
        }
    }

    pub fn scaled(&self, factor: f64) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .map(|t| ExpTerm { coeff: t.coeff * factor, lambda: t.lambda })
                .collect(),
        }
    }

    pub fn plus(mut self, other: &ExpSum) -> Self {
        self.terms.extend_from_slice(&other.terms);
        self
    }

    /// Pass this signal through a downstream compartment that eliminates with rate
    /// `k_out`, forming at rate `gain * self(t)`. Used for metabolites: cotinine from
    /// nicotine, cocaethylene from cocaine.
    ///
    /// `carry_in` is the amount already sitting in the downstream compartment at t=0,
    /// which lets a piecewise signal be filtered piece by piece without losing state
    /// across the boundaries.
    ///
    /// For an input term `c*exp(-lambda t)`:
    ///   integral of  gain*c*exp(-lambda s) * exp(-k_out (t-s))  ds  from 0 to t
    ///     = gain*c * (exp(-lambda t) - exp(-k_out t)) / (k_out - lambda)
    pub fn through_compartment(&self, gain: f64, k_out: f64, carry_in: f64) -> Self {
        let mut out = Vec::with_capacity(self.terms.len() * 2 + 1);
        if carry_in != 0.0 {
            out.push(ExpTerm { coeff: carry_in, lambda: k_out });
        }
        for term in &self.terms {
            let mut lambda = term.lambda;
            if (k_out - lambda).abs() < LAMBDA_EPS {
                lambda += LAMBDA_EPS;
            }
            let amplitude = gain * term.coeff / (k_out - lambda);
            out.push(ExpTerm { coeff: amplitude, lambda });
            out.push(ExpTerm { coeff: -amplitude, lambda: k_out });
        }
        Self { terms: out }
    }

    /// Re-origin this signal at time `shift`, i.e. return the sum `g` with
    /// `g(t) == self(t + shift)`. Used when a piecewise response hands off to the
    /// next piece.
    pub fn shifted(&self, shift: f64) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .map(|t| ExpTerm { coeff: t.coeff * (-t.lambda * shift).exp(), lambda: t.lambda })
                .collect(),
        }
    }

    /// Collapse terms that share a rate constant. Superposition of many doses grows the
    /// term list without bound; folding keeps evaluation cheap for long histories.
    pub fn compact(&mut self) {
        self.terms.sort_by(|a, b| a.lambda.total_cmp(&b.lambda));
        let mut folded: Vec<ExpTerm> = Vec::with_capacity(self.terms.len());
        for term in self.terms.drain(..) {
            match folded.last_mut() {
                Some(prev) if (prev.lambda - term.lambda).abs() < LAMBDA_EPS => {
                    prev.coeff += term.coeff;
                }
                _ => folded.push(term),
            }
        }
        folded.retain(|t| t.coeff != 0.0);
        self.terms = folded;
    }
}

/// Convert a half-life in seconds to a first-order rate constant (1/s).
pub fn rate_from_half_life(half_life_secs: f64) -> f64 {
    std::f64::consts::LN_2 / half_life_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: f64 = 3600.0;

    #[test]
    fn single_exponential_decays_by_half_each_half_life() {
        let k = rate_from_half_life(2.0 * HOUR);
        let sum = ExpSum::single(10.0, k);
        assert!((sum.eval(0.0) - 10.0).abs() < 1e-9);
        assert!((sum.eval(2.0 * HOUR) - 5.0).abs() < 1e-9);
        assert!((sum.eval(4.0 * HOUR) - 2.5).abs() < 1e-9);
    }

    #[test]
    fn metabolite_starts_at_zero_rises_then_falls() {
        // Parent: 1 mg bolus, 2 h half-life. Metabolite: 16 h half-life.
        let k_parent = rate_from_half_life(2.0 * HOUR);
        let k_meta = rate_from_half_life(16.0 * HOUR);
        let parent = ExpSum::single(1.0, k_parent);
        let meta = parent.through_compartment(0.8 * k_parent, k_meta, 0.0);

        assert!(meta.eval(0.0).abs() < 1e-12, "metabolite must start empty");
        let early = meta.eval(2.0 * HOUR);
        let peak = meta.eval(6.0 * HOUR);
        let late = meta.eval(40.0 * HOUR);
        assert!(early > 0.0 && peak > early, "should still be accumulating");
        assert!(late < peak, "should decline once the parent is gone");
    }

    #[test]
    fn metabolite_outlives_its_parent() {
        let k_parent = rate_from_half_life(2.0 * HOUR);
        let k_meta = rate_from_half_life(16.0 * HOUR);
        let parent = ExpSum::single(1.0, k_parent);
        let meta = parent.through_compartment(0.8 * k_parent, k_meta, 0.0);
        // At 24 h the parent is 12 half-lives gone; cotinine is only 1.5.
        assert!(parent.eval(24.0 * HOUR) < 1e-3);
        assert!(meta.eval(24.0 * HOUR) > 0.2);
    }

    #[test]
    fn near_equal_rates_stay_finite() {
        let k = rate_from_half_life(2.0 * HOUR);
        let parent = ExpSum::single(1.0, k);
        let meta = parent.through_compartment(0.5 * k, k, 0.0);
        for h in [0.0, 1.0, 5.0, 20.0] {
            assert!(meta.eval(h * HOUR).is_finite(), "blew up at {h} h");
        }
    }

    #[test]
    fn shifting_matches_direct_evaluation() {
        let sum = ExpSum::from_terms([(3.0, 1e-4), (-1.0, 5e-4)]);
        let shifted = sum.shifted(1234.0);
        assert!((shifted.eval(500.0) - sum.eval(1734.0)).abs() < 1e-12);
    }

    #[test]
    fn compacting_preserves_the_curve() {
        let k = rate_from_half_life(2.0 * HOUR);
        let mut sum = ExpSum::from_terms([(1.0, k), (2.0, k), (0.5, 0.0)]);
        let before = sum.eval(3.0 * HOUR);
        sum.compact();
        assert_eq!(sum.terms.len(), 2, "two distinct rate constants remain");
        assert!((sum.eval(3.0 * HOUR) - before).abs() < 1e-12);
    }
}
