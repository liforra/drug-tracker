//! Substance, route and product definitions.
//!
//! A substance is nothing but a parameter set. Adding one is a data change, not a code
//! change -- that is the whole point of this module. Nicotine via a snus pouch and
//! cocaine via three different routes go through the same engine.

use serde::{Deserialize, Serialize};

/// How the drug leaves the body once it is in the bloodstream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Disposition {
    /// The body behaves as one well-mixed volume. Adequate for nicotine and caffeine.
    OneCompartment { half_life_secs: f64 },
    /// A fast distribution phase into peripheral tissue followed by slower elimination.
    /// Needed for anything where the felt effect drops much faster than the drug is
    /// actually cleared -- cocaine being the obvious example.
    ///
    /// `alpha_fraction` is the share of the dose that decays on the fast phase; the
    /// remainder decays on the slow one. These are the standard macro-constants.
    TwoCompartment {
        alpha_fraction: f64,
        alpha_half_life_secs: f64,
        beta_half_life_secs: f64,
    },
}

/// How the drug gets into the bloodstream in the first place.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Absorption {
    /// Effectively instantaneous: intravenous, or smoked/inhaled where Tmax is seconds.
    Bolus,
    /// Classic first-order uptake from a depot: oral, intranasal.
    FirstOrder { half_life_secs: f64 },
    /// Constant delivery rate for as long as the dose is being administered. The
    /// duration is not a parameter here -- it comes from the event, because how long
    /// you actually keep a pouch in is a fact about that pouch, not about the route.
    ZeroOrder,
}

/// A way of taking a substance. The same substance through two routes produces
/// completely different curves, so bioavailability and absorption live here, not on
/// the substance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Route {
    pub id: String,
    pub display_name: String,
    /// Fraction of the nominal dose that reaches systemic circulation.
    pub bioavailability: f64,
    pub absorption: Absorption,
    /// Dead time before anything is absorbed at all.
    pub lag_secs: f64,
    /// Used for zero-order routes when an event has no recorded end time yet.
    pub default_duration_secs: Option<f64>,
}

/// A downstream compound formed from the parent. Sometimes it is the interesting
/// signal in its own right: cotinine tracks nicotine load far more stably than
/// nicotine does, and benzoylecgonine is what a drug screen actually detects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Metabolite {
    pub id: String,
    pub display_name: String,
    /// Share of eliminated parent that becomes this compound.
    pub molar_fraction: f64,
    pub half_life_secs: f64,
    pub vd_l_per_kg: f64,
    /// Whether this metabolite contributes to the felt effect.
    pub active: bool,
}

/// Two substances combining into a third. Cocaine plus ethanol forms cocaethylene,
/// which is longer-lived and more cardiotoxic than either parent -- a case where the
/// model has something genuinely useful to say that neither substance alone would.
///
/// Declared here so the schema and stored data support it from day one. Formation
/// depends on the product of two concentrations, so it is not a linear filter and the
/// engine does not evaluate it yet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Interaction {
    pub id: String,
    pub display_name: String,
    /// Both substance ids must be present for the product to form.
    pub parent_ids: [String; 2],
    pub rate_gain: f64,
    pub product: Metabolite,
}

/// Parameters for the tolerance index. Two timescales, because two distinct things are
/// happening: receptors desensitise within a session and recover over hours, and
/// receptor density adapts over days to weeks.
///
/// These are not clinically calibrated and cannot be -- there is no tolerance assay.
/// The output is an index relative to the user's own baseline, meaningful as a trend
/// and meaningless as an absolute number.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ToleranceModel {
    pub acute_half_life_secs: f64,
    pub acute_gain: f64,
    pub chronic_half_life_secs: f64,
    pub chronic_gain: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Substance {
    pub id: String,
    pub display_name: String,
    pub disposition: Disposition,
    pub vd_l_per_kg: f64,
    pub routes: Vec<Route>,
    pub metabolites: Vec<Metabolite>,
    pub tolerance: ToleranceModel,
    /// Reference concentration in ng/mL used to normalise the effect scale. Purely a
    /// display convenience; it does not affect the kinetics.
    pub reference_concentration_ng_ml: f64,
}

impl Substance {
    pub fn route(&self, id: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.id == id)
    }
}

/// Per-user parameters. Kept separate from the substance because these are the values
/// a lab result would refine: body mass scales the volume of distribution, and
/// `metabolism_factor` scales every elimination rate to account for CYP2A6 activity
/// (the nicotine metabolite ratio) or equivalent.
///
/// Versioned in storage with a validity range, so body mass changing over the years
/// re-derives history correctly instead of retroactively rewriting it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Subject {
    pub body_mass_kg: f64,
    /// 1.0 = population average. >1 clears faster, <1 slower.
    pub metabolism_factor: f64,
}

impl Default for Subject {
    fn default() -> Self {
        Self { body_mass_kg: 75.0, metabolism_factor: 1.0 }
    }
}

impl Subject {
    /// Volume of distribution in litres for a given per-kilogram figure.
    pub fn volume_l(&self, vd_l_per_kg: f64) -> f64 {
        vd_l_per_kg * self.body_mass_kg
    }
}
