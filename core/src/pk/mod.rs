//! Pharmacokinetic modelling.
//!
//! The engine is substance-agnostic: a substance is a parameter set, and adding one is
//! a data change. See [`model`] for the shape of those parameters, [`terms`] for the
//! representation everything is computed in, and [`engine`] for turning doses into
//! curves.
pub mod engine;
pub mod model;
pub mod substances;
pub mod terms;

pub use engine::{
    Curve, Dose, DoseResponse, concentration_ng_ml, dose_response, metabolite_response,
};
pub use model::{
    Absorption, Disposition, Interaction, Metabolite, Route, Subject, Substance, ToleranceModel,
};
pub use terms::{ExpSum, ExpTerm, rate_from_half_life};
