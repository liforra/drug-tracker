//! Turning the event log into curves, via the pharmacokinetic engine.
//!
//! This lives in the core rather than in a client because every client must agree on
//! what your nicotine level is. The same log has to produce the same number on the
//! phone and on the laptop; two implementations would be two answers.

use chrono::{DateTime, Duration, Utc};

use crate::log::{Session, State};
use crate::pk::{
    Absorption, Curve, Dose, Subject, dose_response, metabolite_response, rate_from_half_life,
    substances,
};

/// Seconds since the epoch, which is the engine's time base.
fn seconds(at: DateTime<Utc>) -> f64 {
    at.timestamp() as f64
}

pub struct Levels {
    pub nicotine: Curve,
    pub cotinine: Curve,
    /// Kept for the statistics view, which will want the body mass it was computed with.
    pub subject: Subject,
}

/// Build both curves from every session in the log, as of now.
pub fn build(state: &State) -> Levels {
    build_at(state, Utc::now())
}

/// Build both curves as of a stated time. Split out from `build` so tests are not at
/// the mercy of the clock.
///
/// Absorption is driven by *contact* time -- the intervals the pouch was actually in
/// the mouth -- not by wall-clock session length. A pouch that rested on the desk for
/// an hour delivered nothing during that hour. That the nicotine already in the blood
/// kept being eliminated needs no special handling: elimination is a property of the
/// body, not of the pouch.
pub fn build_at(state: &State, now: DateTime<Utc>) -> Levels {
    let subject = Subject {
        body_mass_kg: state.body_mass_kg.unwrap_or(75.0),
        metabolism_factor: state.metabolism_factor.unwrap_or(1.0),
    };

    let nicotine = substances::nicotine();
    let cotinine_params = &nicotine.metabolites[0];

    let mut parent = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    let mut metabolite = Curve::new(subject.volume_l(cotinine_params.vd_l_per_kg));

    for session in state.sessions.values() {
        let Some(product) = state.product(&session.product_id) else {
            continue;
        };
        if product.substance_id != nicotine.id {
            // Other substances get their own curves once they exist; silently folding
            // them into the nicotine one would be worse than leaving them out.
            continue;
        }
        let Some(route) = nicotine.route(&product.route_id) else {
            continue;
        };

        // How long the pouch goes on giving. A property of the pouch, not of how long
        // you happen to keep it in. Brands differ, so the product may state its own.
        let release_secs = product
            .default_duration_secs
            .or(route.default_duration_secs)
            .unwrap_or(3600.0)
            .max(1.0);
        // Contact time consumed so far in this session. Resting does not add to it.
        let mut used_contact_secs = 0.0_f64;

        // Contact intervals are the only times the pouch was delivering anything.
        // Each becomes its own short dose, and superposition makes that exact: the
        // model is linear, so the response to an interrupted delivery is the sum of the
        // responses to its parts. An interrupted pouch needs no new pharmacokinetics.
        for (from, to) in session.contact_intervals(now) {
            let len = (to - from).num_seconds().max(0) as f64;
            if len < 1.0 {
                continue;
            }

            let dose = match route.absorption {
                // A decaying depot: what is left in the pouch depends only on how long
                // it has spent in the mouth, never on how long it has sat on a desk.
                // Carrying that forward as a smaller starting amount is exact, because
                // a first-order depot has no state beyond its current size.
                Absorption::FirstOrder { half_life_secs } => {
                    let k = rate_from_half_life(half_life_secs);
                    let left = (-k * used_contact_secs).exp();
                    used_contact_secs += len;
                    Dose {
                        start_secs: seconds(from),
                        duration_secs: Some(len),
                        nominal_mg: product.nominal_mg * left,
                    }
                }

                // Constant delivery from a fixed budget: the pouch is spent once the
                // budget is used up, and a short session must deliver less rather than
                // the same amount faster.
                _ => {
                    let budget = release_secs - used_contact_secs;
                    if budget <= 0.0 {
                        break;
                    }
                    let len = len.min(budget);
                    used_contact_secs += len;
                    Dose {
                        start_secs: seconds(from),
                        duration_secs: Some(len),
                        nominal_mg: product.nominal_mg * (len / release_secs),
                    }
                }
            };

            let response = dose_response(&nicotine, route, &subject, dose);
            metabolite.add(metabolite_response(
                &response,
                &nicotine,
                cotinine_params,
                &subject,
            ));
            parent.add(response);
        }
    }

    Levels {
        nicotine: parent,
        cotinine: metabolite,
        subject,
    }
}

impl Levels {
    pub fn nicotine_at(&self, at: DateTime<Utc>) -> f64 {
        self.nicotine.concentration_at(seconds(at))
    }

    pub fn cotinine_at(&self, at: DateTime<Utc>) -> f64 {
        self.cotinine.concentration_at(seconds(at))
    }

    /// How fast the nicotine level is moving, in ng/mL per minute.
    ///
    /// This is the number that matches what a session feels like, and the level alone
    /// is not. Nicotinic receptors desensitise within minutes of steady exposure, so a
    /// rising concentration recruits receptors faster than desensitisation removes
    /// them, while a flat one -- however high -- mostly does not. Hence the familiar
    /// pattern of a rush early in a pouch and nothing at all later at a higher level.
    pub fn nicotine_rate_at(&self, at: DateTime<Utc>) -> f64 {
        self.nicotine.concentration_rate_at(seconds(at)) * 60.0
    }

    /// Sample both curves over a window, for plotting.
    pub fn samples(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        steps: usize,
    ) -> Vec<(DateTime<Utc>, f64, f64)> {
        let span = (to - from).num_seconds() as f64;
        let step = span / steps as f64;
        (0..=steps)
            .map(|i| {
                let at = from + Duration::seconds((step * i as f64) as i64);
                (at, self.nicotine_at(at), self.cotinine_at(at))
            })
            .collect()
    }
}

/// How much release the pouch has left, measured in contact time.
///
/// `Some(Duration::zero())` means spent: it will go on sitting in your lip without
/// delivering anything. `None` means the product's substance or route is unknown, so
/// there is no release profile to count against -- reporting a number there would be
/// inventing one.
///
/// Resting does not consume this budget, which is the honest model: what limits a pouch
/// is extraction by saliva, and on a desk there is nothing extracting it.
pub fn remaining_release(state: &State, session: &Session, now: DateTime<Utc>) -> Option<Duration> {
    let product = state.product(&session.product_id)?;
    let nicotine = substances::nicotine();
    if product.substance_id != nicotine.id {
        return None;
    }
    let route = nicotine.route(&product.route_id)?;
    let release_secs = product
        .default_duration_secs
        .or(route.default_duration_secs)? as i64;

    let used = session.contact_duration(now).num_seconds();
    Some(Duration::seconds((release_secs - used).max(0)))
}

/// A tolerance index relative to the user's own recent baseline.
///
/// Cotinine is the input rather than nicotine because chronic tolerance tracks sustained
/// exposure, not the hourly sawtooth. The result is scaled against the highest value in
/// the trailing window, so it says "heavier than usual for you" and deliberately does
/// not pretend to be a clinical quantity -- there is no tolerance assay to calibrate
/// against, and a number that looked absolute would be a lie.
pub fn tolerance_index(levels: &Levels, now: DateTime<Utc>) -> Option<f64> {
    let window_start = now - Duration::days(90);
    let current = levels.cotinine_at(now);

    let mut peak: f64 = 0.0;
    let mut at = window_start;
    while at <= now {
        peak = peak.max(levels.cotinine_at(at));
        at += Duration::hours(6);
    }

    // Below this there is not enough history for a ratio to mean anything.
    if peak < 1.0 {
        return None;
    }
    Some((current / peak * 100.0).clamp(0.0, 100.0))
}

/// Midnight local time, as UTC. Falls back to a rolling 24 hours if the local date is
/// ambiguous, which happens on a DST boundary.
fn start_of_day() -> DateTime<Utc> {
    chrono::Local::now()
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|naive| naive.and_local_timezone(chrono::Local).single())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() - Duration::hours(24))
}

/// Sessions that started today, in the local timezone.
pub fn today_count(state: &State) -> usize {
    let since = start_of_day();
    state
        .sessions
        .values()
        .filter(|s| s.started_at >= since)
        .count()
}

/// Total nominal milligrams consumed today.
///
/// Nominal, as printed on the tin -- not what was absorbed. The two differ, especially
/// for a pouch taken out early, but this number exists to be compared against the tin.
pub fn today_mg(state: &State) -> f64 {
    let since = start_of_day();
    state
        .sessions
        .values()
        .filter(|s| s.started_at >= since)
        .filter_map(|s| state.product(&s.product_id))
        .map(|p| p.nominal_mg)
        .sum::<f64>()
        // Same negative-zero trap as in the engine: an empty f64 sum is -0.0.
        .max(0.0)
}
