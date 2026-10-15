//! Turning doses into concentration curves.
//!
//! A dose response is piecewise: absorption behaves differently while the drug is
//! still being delivered than afterwards. Within each piece it is an exponential sum,
//! so evaluation stays closed-form -- no numerical integration anywhere in this file.

use super::model::{Absorption, Disposition, Metabolite, Route, Subject, Substance};
use super::terms::{ExpSum, rate_from_half_life};

/// One administration, in seconds since an arbitrary epoch shared by the timeline.
#[derive(Clone, Copy, Debug)]
pub struct Dose {
    pub start_secs: f64,
    /// How long delivery lasted. Only meaningful for zero-order routes; `None` means
    /// the session is still open and the route's default is used.
    pub duration_secs: Option<f64>,
    /// Nominal amount as labelled on the product, before bioavailability.
    pub nominal_mg: f64,
}

/// A segment of a dose response, valid on `[start_secs, end_secs)`, evaluated at time
/// relative to `start_secs`.
#[derive(Clone, Debug)]
pub struct Piece {
    pub start_secs: f64,
    pub end_secs: Option<f64>,
    pub sum: ExpSum,
}

/// Amount of drug in the central compartment over time, in mg.
#[derive(Clone, Debug, Default)]
pub struct DoseResponse {
    pub pieces: Vec<Piece>,
}

impl DoseResponse {
    /// Rate of change of the amount at absolute time `t`, in mg/s.
    ///
    /// Piecewise like `eval`, and genuinely discontinuous at the piece boundary -- when
    /// a pouch comes out, delivery stops abruptly and so does the climb. Reporting a
    /// smoothed value there would hide the one moment the number is most informative.
    pub fn eval_rate(&self, t: f64) -> f64 {
        for piece in &self.pieces {
            let after_start = t >= piece.start_secs;
            let before_end = piece.end_secs.is_none_or(|end| t < end);
            if after_start && before_end {
                return piece.sum.derivative().eval(t - piece.start_secs);
            }
        }
        0.0
    }

    /// Amount in mg at absolute time `t`. Zero before the dose and outside all pieces.
    pub fn eval(&self, t: f64) -> f64 {
        for piece in &self.pieces {
            let after_start = t >= piece.start_secs;
            let before_end = piece.end_secs.is_none_or(|end| t < end);
            if after_start && before_end {
                return piece.sum.eval(t - piece.start_secs);
            }
        }
        0.0
    }
}

/// Decay of a unit amount already in circulation, as (fraction, rate) pairs.
fn disposition_terms(disposition: &Disposition, metabolism_factor: f64) -> Vec<(f64, f64)> {
    match disposition {
        Disposition::OneCompartment { half_life_secs } => {
            vec![(1.0, rate_from_half_life(*half_life_secs) * metabolism_factor)]
        }
        Disposition::TwoCompartment {
            alpha_fraction,
            alpha_half_life_secs,
            beta_half_life_secs,
        } => vec![
            (*alpha_fraction, rate_from_half_life(*alpha_half_life_secs) * metabolism_factor),
            (
                1.0 - *alpha_fraction,
                rate_from_half_life(*beta_half_life_secs) * metabolism_factor,
            ),
        ],
    }
}

/// The rate the terminal phase decays at -- used as the formation rate for metabolites.
fn terminal_rate(disposition: &Disposition, metabolism_factor: f64) -> f64 {
    disposition_terms(disposition, metabolism_factor)
        .into_iter()
        .map(|(_, lambda)| lambda)
        .fold(f64::INFINITY, f64::min)
}

/// Build the central-compartment amount curve for one dose.
pub fn dose_response(
    substance: &Substance,
    route: &Route,
    subject: &Subject,
    dose: Dose,
) -> DoseResponse {
    let absorbed_mg = dose.nominal_mg * route.bioavailability;
    let terms = disposition_terms(&substance.disposition, subject.metabolism_factor);
    let origin = dose.start_secs + route.lag_secs;

    match &route.absorption {
        // Everything lands at once: intravenous, or smoked where Tmax is seconds.
        Absorption::Bolus => {
            let sum = ExpSum::from_terms(
                terms.iter().map(|(frac, lambda)| (absorbed_mg * frac, *lambda)),
            );
            DoseResponse { pieces: vec![Piece { start_secs: origin, end_secs: None, sum }] }
        }

        // Uptake from a depot that itself decays: a pouch in the mouth, oral, intranasal.
        Absorption::FirstOrder { half_life_secs } => {
            let k_a = rate_from_half_life(*half_life_secs);
            let depot = ExpSum::single(absorbed_mg, k_a);

            // Per disposition phase, so that delivery can be cut off exactly: each
            // phase's contribution at the moment of removal becomes that phase's
            // starting amount afterwards. Summing first and splitting later would only
            // be exact for a one-compartment body.
            let per_phase: Vec<(f64, ExpSum)> = terms
                .iter()
                .map(|(frac, lambda)| {
                    (*lambda, depot.through_compartment(k_a, *lambda, 0.0).scaled(*frac))
                })
                .collect();

            let mut during = ExpSum::zero();
            for (_, phase) in &per_phase {
                during = during.plus(phase);
            }
            during.compact();

            match dose.duration_secs {
                // The depot is removed after `duration`: a pouch taken out of the
                // mouth stops delivering, and whatever it still holds is thrown away.
                // Without this the model would go on absorbing from a pouch in the bin.
                Some(duration) if duration > 0.0 => DoseResponse {
                    pieces: vec![
                        Piece {
                            start_secs: origin,
                            end_secs: Some(origin + duration),
                            sum: during,
                        },
                        Piece {
                            start_secs: origin + duration,
                            end_secs: None,
                            sum: ExpSum::from_terms(
                                per_phase
                                    .iter()
                                    .map(|(lambda, phase)| (phase.eval(duration), *lambda)),
                            ),
                        },
                    ],
                },
                // Depot stays until it is exhausted: swallowed, insufflated, injected.
                _ => DoseResponse {
                    pieces: vec![Piece { start_secs: origin, end_secs: None, sum: during }],
                },
            }
        }

        // Constant delivery for as long as the pouch is in. Two pieces: during, after.
        Absorption::ZeroOrder => {
            let duration = dose
                .duration_secs
                .or(route.default_duration_secs)
                .unwrap_or(1800.0)
                .max(1.0);
            let rate = absorbed_mg / duration;

            // While infusing: A(t) = sum_i f_i * (R/lambda_i) * (1 - exp(-lambda_i t)).
            // The constant part is a lambda == 0 term, which the representation carries
            // natively -- no special case needed.
            let mut during = ExpSum::zero();
            let mut plateau = Vec::with_capacity(terms.len());
            for (frac, lambda) in &terms {
                let amplitude = frac * rate / lambda;
                during = during.plus(&ExpSum::from_terms([
                    (amplitude, 0.0),
                    (-amplitude, *lambda),
                ]));
                // Amount contributed by this phase at the moment delivery stops.
                plateau.push((amplitude * (1.0 - (-lambda * duration).exp()), *lambda));
            }
            during.compact();

            DoseResponse {
                pieces: vec![
                    Piece {
                        start_secs: origin,
                        end_secs: Some(origin + duration),
                        sum: during,
                    },
                    Piece {
                        start_secs: origin + duration,
                        end_secs: None,
                        sum: ExpSum::from_terms(plateau),
                    },
                ],
            }
        }
    }
}

/// Pass a parent response through a metabolite compartment.
///
/// Formation is modelled as proportional to the parent amount at the parent's terminal
/// rate. For a one-compartment parent that is exact; for two-compartment it slightly
/// understates formation during the distribution phase, which is well inside the error
/// bars of the underlying parameters.
pub fn metabolite_response(
    parent: &DoseResponse,
    substance: &Substance,
    metabolite: &Metabolite,
    subject: &Subject,
) -> DoseResponse {
    let k_form = terminal_rate(&substance.disposition, subject.metabolism_factor);
    let k_out = rate_from_half_life(metabolite.half_life_secs) * subject.metabolism_factor;
    let gain = metabolite.molar_fraction * k_form;

    let mut pieces = Vec::with_capacity(parent.pieces.len());
    // The metabolite compartment carries state across piece boundaries: it does not
    // reset when the parent switches from absorbing to eliminating.
    let mut carry = 0.0;

    for piece in &parent.pieces {
        let mut sum = piece.sum.through_compartment(gain, k_out, carry);
        sum.compact();
        if let Some(end) = piece.end_secs {
            carry = sum.eval(end - piece.start_secs);
        }
        pieces.push(Piece { start_secs: piece.start_secs, end_secs: piece.end_secs, sum });
    }

    DoseResponse { pieces }
}

/// Convert an amount in mg to a plasma concentration in ng/mL.
///
/// mg / L is ug/mL, so the factor to ng/mL is 1000.
pub fn concentration_ng_ml(amount_mg: f64, volume_l: f64) -> f64 {
    (amount_mg / volume_l) * 1000.0
}

/// Superposition of many doses of the same substance.
///
/// Because the model is linear, the total is the plain sum of the individual responses.
/// That is what makes a long history cheap: no state to carry forward, no ordering
/// requirement, and a corrected parameter re-derives everything from scratch.
#[derive(Debug, Default)]
pub struct Curve {
    responses: Vec<DoseResponse>,
    volume_l: f64,
}

impl Curve {
    pub fn new(volume_l: f64) -> Self {
        Self { responses: Vec::new(), volume_l }
    }

    pub fn add(&mut self, response: DoseResponse) {
        self.responses.push(response);
    }

    pub fn amount_mg_at(&self, t: f64) -> f64 {
        let total: f64 = self.responses.iter().map(|r| r.eval(t)).sum();
        // Clamped because a negative amount is not a thing. Two ways to get one: an
        // empty sum, since -0.0 is f64's additive identity and Rust's `Sum` uses it; and
        // cancellation between the paired `+a e^-λt` and `-a e^-kt` terms a metabolite
        // is built from, which lands a hair below zero once the two have decayed.
        total.max(0.0)
    }

    pub fn concentration_at(&self, t: f64) -> f64 {
        concentration_ng_ml(self.amount_mg_at(t), self.volume_l)
    }

    /// How fast the amount is changing, in mg per second.
    ///
    /// Not clamped, unlike `amount_mg_at`: a falling level is the normal case and the
    /// sign is the entire information content here.
    pub fn amount_rate_at(&self, t: f64) -> f64 {
        self.responses.iter().map(|r| r.eval_rate(t)).sum()
    }

    /// Rate of change of concentration, in ng/mL per second.
    pub fn concentration_rate_at(&self, t: f64) -> f64 {
        concentration_ng_ml(self.amount_rate_at(t), self.volume_l)
    }

    /// Sample the curve at a fixed step. Used for plotting.
    pub fn sample(&self, from: f64, to: f64, step_secs: f64) -> Vec<(f64, f64)> {
        let mut out = Vec::new();
        let mut t = from;
        while t <= to {
            out.push((t, self.concentration_at(t)));
            t += step_secs;
        }
        out
    }

    /// Time of peak concentration and its value, found by sampling then refining.
    pub fn peak(&self, from: f64, to: f64) -> (f64, f64) {
        let coarse = ((to - from) / 200.0).max(1.0);
        let mut best = (from, self.concentration_at(from));
        let mut t = from;
        while t <= to {
            let c = self.concentration_at(t);
            if c > best.1 {
                best = (t, c);
            }
            t += coarse;
        }
        // Refine around the coarse winner.
        let mut t = (best.0 - coarse).max(from);
        let fine = coarse / 50.0;
        let stop = (best.0 + coarse).min(to);
        while t <= stop {
            let c = self.concentration_at(t);
            if c > best.1 {
                best = (t, c);
            }
            t += fine;
        }
        best
    }
}
