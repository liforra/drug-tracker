//! Built-in substance library.
//!
//! Every entry here is data, not code. Parameters are population averages from the
//! pharmacokinetic literature and carry real uncertainty -- half-lives in particular
//! vary several-fold between individuals. `Subject::metabolism_factor` is the hook for
//! narrowing that with a personal measurement.

use super::model::{
    Absorption, Disposition, Interaction, Metabolite, Route, Substance, ToleranceModel,
};

const MIN: f64 = 60.0;
const HOUR: f64 = 3600.0;
const DAY: f64 = 86400.0;

pub fn nicotine() -> Substance {
    Substance {
        id: "nicotine".into(),
        display_name: "Nikotin".into(),
        // t1/2 ranges roughly 1-4 h depending on CYP2A6 activity. This is the midpoint.
        disposition: Disposition::OneCompartment { half_life_secs: 2.0 * HOUR },
        vd_l_per_kg: 2.6,
        routes: vec![
            Route {
                id: "buccal_pouch".into(),
                display_name: "Snus / Pouch".into(),
                // Fraction of the labelled content that eventually reaches plasma if
                // the pouch is left in until it stops giving. Two losses stack: only
                // part of the content is ever extracted, and part of that is swallowed
                // rather than absorbed buccally.
                //
                // Calibrated against Azzopardi et al. 2026 (J Clin Pharmacol), who had
                // people use 11 mg and 20 mg pouches for 10, 20 and 30 minutes and then
                // weighed what was left in the pouch. Back-calculating clearance times
                // AUC from their 11 mg / 30 min arm gives roughly 3.9 mg systemic, and
                // that arm captures about four fifths of the eventual total.
                bioavailability: 0.45,
                // Release is markedly front-loaded rather than constant. The same study
                // found 28% of the content out in the first 10 minutes and only about
                // eight more points per 10 minutes after that, and says plainly that
                // extraction "is rapid during the first 10 min of use and slows
                // thereafter".
                //
                // A decaying depot reproduces that shape. This half-life reproduces
                // their measured 10/20/30-minute AUC ratios of 0.57 : 0.85 : 1.00 as
                // 0.51 : 0.82 : 1.00, and their Cmax of 21.6 ng/mL to within a few
                // percent.
                absorption: Absorption::FirstOrder { half_life_secs: 14.0 * MIN },
                lag_secs: 1.0 * MIN,
                // Not a hard limit: with first-order release nothing is ever strictly
                // empty. It is the point where the pouch is done in any practical
                // sense -- about 95% of what it will ever give is out.
                default_duration_secs: Some(60.0 * MIN),
            },
            Route {
                id: "smoked".into(),
                display_name: "Geraucht".into(),
                bioavailability: 0.20,
                absorption: Absorption::FirstOrder { half_life_secs: 1.0 * MIN },
                lag_secs: 0.0,
                default_duration_secs: None,
            },
        ],
        metabolites: vec![Metabolite {
            id: "cotinine".into(),
            display_name: "Cotinin".into(),
            molar_fraction: 0.75,
            // Long enough to smooth out the hourly sawtooth entirely, which is exactly
            // what makes it the better read on daily load.
            half_life_secs: 16.0 * HOUR,
            vd_l_per_kg: 0.8,
            active: false,
        }],
        tolerance: ToleranceModel {
            acute_half_life_secs: 1.0 * HOUR,
            acute_gain: 1.0,
            // Receptor upregulation normalises over weeks after cessation.
            chronic_half_life_secs: 7.0 * DAY,
            chronic_gain: 1.0,
        },
        reference_concentration_ng_ml: 15.0,
    }
}

pub fn caffeine() -> Substance {
    Substance {
        id: "caffeine".into(),
        display_name: "Koffein".into(),
        disposition: Disposition::OneCompartment { half_life_secs: 5.0 * HOUR },
        vd_l_per_kg: 0.6,
        routes: vec![Route {
            id: "oral".into(),
            display_name: "Oral".into(),
            bioavailability: 0.99,
            absorption: Absorption::FirstOrder { half_life_secs: 10.0 * MIN },
            lag_secs: 5.0 * MIN,
            default_duration_secs: None,
        }],
        metabolites: vec![Metabolite {
            id: "paraxanthine".into(),
            display_name: "Paraxanthin".into(),
            molar_fraction: 0.80,
            half_life_secs: 4.0 * HOUR,
            vd_l_per_kg: 0.6,
            active: true,
        }],
        tolerance: ToleranceModel {
            acute_half_life_secs: 4.0 * HOUR,
            acute_gain: 0.5,
            chronic_half_life_secs: 5.0 * DAY,
            chronic_gain: 0.8,
        },
        reference_concentration_ng_ml: 4000.0,
    }
}

/// Cocaine is the stress test for this engine, and the reason the model is not built
/// around a single half-life: the felt effect tracks the fast distribution phase while
/// clearance runs on the slow one, and the three routes produce curves with almost
/// nothing in common.
pub fn cocaine() -> Substance {
    Substance {
        id: "cocaine".into(),
        display_name: "Kokain".into(),
        disposition: Disposition::TwoCompartment {
            alpha_fraction: 0.5,
            alpha_half_life_secs: 15.0 * MIN,
            beta_half_life_secs: 60.0 * MIN,
        },
        vd_l_per_kg: 2.0,
        routes: vec![
            Route {
                id: "intranasal".into(),
                display_name: "Nasal".into(),
                bioavailability: 0.70,
                // Vasoconstriction slows its own uptake; Tmax lands around 30-60 min.
                absorption: Absorption::FirstOrder { half_life_secs: 20.0 * MIN },
                lag_secs: 2.0 * MIN,
                default_duration_secs: None,
            },
            Route {
                id: "smoked".into(),
                display_name: "Geraucht (Crack)".into(),
                bioavailability: 0.70,
                absorption: Absorption::Bolus,
                lag_secs: 10.0,
                default_duration_secs: None,
            },
            Route {
                id: "intravenous".into(),
                display_name: "Intravenös".into(),
                bioavailability: 1.0,
                absorption: Absorption::Bolus,
                lag_secs: 0.0,
                default_duration_secs: None,
            },
            Route {
                id: "oral".into(),
                display_name: "Oral".into(),
                bioavailability: 0.30,
                absorption: Absorption::FirstOrder { half_life_secs: 30.0 * MIN },
                lag_secs: 10.0 * MIN,
                default_duration_secs: None,
            },
        ],
        metabolites: vec![Metabolite {
            id: "benzoylecgonine".into(),
            display_name: "Benzoylecgonin".into(),
            molar_fraction: 0.45,
            half_life_secs: 6.0 * HOUR,
            vd_l_per_kg: 0.6,
            active: false,
        }],
        tolerance: ToleranceModel {
            // Acute tachyphylaxis within a session is pronounced and recovers fast --
            // a completely different shape from nicotine's slow receptor adaptation.
            acute_half_life_secs: 30.0 * MIN,
            acute_gain: 2.0,
            chronic_half_life_secs: 3.0 * DAY,
            chronic_gain: 1.5,
        },
        reference_concentration_ng_ml: 300.0,
    }
}

pub fn ethanol() -> Substance {
    Substance {
        id: "ethanol".into(),
        display_name: "Alkohol".into(),
        // Ethanol is really zero-order (Michaelis-Menten saturated) at typical doses.
        // A first-order approximation overstates the tail; flagged for a dedicated
        // elimination model before this entry is trusted quantitatively.
        disposition: Disposition::OneCompartment { half_life_secs: 1.0 * HOUR },
        vd_l_per_kg: 0.6,
        routes: vec![Route {
            id: "oral".into(),
            display_name: "Oral".into(),
            bioavailability: 0.90,
            absorption: Absorption::FirstOrder { half_life_secs: 15.0 * MIN },
            lag_secs: 5.0 * MIN,
            default_duration_secs: None,
        }],
        metabolites: vec![],
        tolerance: ToleranceModel {
            acute_half_life_secs: 2.0 * HOUR,
            acute_gain: 1.0,
            chronic_half_life_secs: 10.0 * DAY,
            chronic_gain: 1.0,
        },
        reference_concentration_ng_ml: 800_000.0,
    }
}

pub fn builtin() -> Vec<Substance> {
    vec![nicotine(), caffeine(), cocaine(), ethanol()]
}

/// Combinations that produce a third compound.
///
/// Cocaethylene is the motivating case: taken together, cocaine and ethanol form a
/// metabolite that outlives cocaine and carries more cardiac risk than either parent,
/// which is something neither substance's own curve would ever show. Formation depends
/// on the product of two concentrations, so it is not a linear filter -- the engine
/// stores and reports these but does not yet evaluate them.
pub fn interactions() -> Vec<Interaction> {
    vec![Interaction {
        id: "cocaethylene".into(),
        display_name: "Cocaethylen".into(),
        parent_ids: ["cocaine".into(), "ethanol".into()],
        rate_gain: 0.20,
        product: Metabolite {
            id: "cocaethylene".into(),
            display_name: "Cocaethylen".into(),
            molar_fraction: 1.0,
            half_life_secs: 2.5 * HOUR,
            vd_l_per_kg: 2.0,
            active: true,
        },
    }]
}

pub fn by_id(id: &str) -> Option<Substance> {
    builtin().into_iter().find(|s| s.id == id)
}
