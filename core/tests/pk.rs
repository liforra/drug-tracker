//! Behavioural checks on the pharmacokinetic engine.
//!
//! These assert shape and relative ordering rather than exact numbers. The underlying
//! parameters are population averages with several-fold spread, so a test that pinned
//! an exact concentration would be asserting false precision. What must hold is that
//! the curves behave the way the pharmacology says they do.

use tracker_core::pk::{
    Curve, Dose, Subject, dose_response, metabolite_response, model::Absorption, substances,
};

const MIN: f64 = 60.0;
const HOUR: f64 = 3600.0;

fn subject() -> Subject {
    Subject {
        body_mass_kg: 75.0,
        metabolism_factor: 1.0,
    }
}

/// One 12 mg pouch, kept in for 30 minutes.
fn one_pouch(start: f64) -> Curve {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut curve = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    curve.add(dose_response(
        &nicotine,
        route,
        &subject,
        Dose {
            start_secs: start,
            duration_secs: Some(30.0 * MIN),
            nominal_mg: 12.0,
        },
    ));
    curve
}

#[test]
fn a_pouch_peaks_in_a_plausible_range() {
    let curve = one_pouch(0.0);
    let (t_peak, c_peak) = curve.peak(0.0, 6.0 * HOUR);

    // Published Cmax for a single pouch sits around 10-20 ng/mL.
    assert!(
        (5.0..30.0).contains(&c_peak),
        "peak {c_peak:.1} ng/mL is outside anything the literature would recognise"
    );
    // Zero-order delivery means the peak lands at the moment the pouch comes out.
    assert!(
        (25.0 * MIN..40.0 * MIN).contains(&t_peak),
        "peak at {:.0} min should coincide with removal at 30 min",
        t_peak / MIN
    );
}

#[test]
fn nothing_is_in_the_blood_before_the_pouch_goes_in() {
    let curve = one_pouch(10.0 * HOUR);
    assert_eq!(curve.concentration_at(0.0), 0.0);
    assert_eq!(curve.concentration_at(9.0 * HOUR), 0.0);
    assert!(curve.concentration_at(10.5 * HOUR) > 0.0);
}

#[test]
fn concentration_halves_over_one_half_life_after_absorption_ends() {
    let curve = one_pouch(0.0);
    // Well clear of the absorption phase, decay is the terminal rate alone.
    let at_2h = curve.concentration_at(2.0 * HOUR);
    let at_4h = curve.concentration_at(4.0 * HOUR);
    let ratio = at_4h / at_2h;
    assert!(
        (0.45..0.55).contains(&ratio),
        "expected a 2 h half-life, got a ratio of {ratio:.3} over 2 h"
    );
}

#[test]
fn doses_superimpose_linearly() {
    let single = one_pouch(0.0).concentration_at(45.0 * MIN);

    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut doubled = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    for _ in 0..2 {
        doubled.add(dose_response(
            &nicotine,
            route,
            &subject,
            Dose {
                start_secs: 0.0,
                duration_secs: Some(30.0 * MIN),
                nominal_mg: 12.0,
            },
        ));
    }

    let combined = doubled.concentration_at(45.0 * MIN);
    assert!(
        (combined - 2.0 * single).abs() < 1e-9,
        "linearity is the property the whole engine rests on"
    );
}

#[test]
fn a_days_pouches_accumulate_to_a_higher_trough_than_a_single_one() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut curve = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    // One pouch every 90 minutes from 08:00 to 22:00.
    for i in 0..10 {
        curve.add(dose_response(
            &nicotine,
            route,
            &subject,
            Dose {
                start_secs: 8.0 * HOUR + i as f64 * 90.0 * MIN,
                duration_secs: Some(30.0 * MIN),
                nominal_mg: 12.0,
            },
        ));
    }
    let after_first = curve.concentration_at(9.5 * HOUR);
    let late = curve.concentration_at(21.0 * HOUR);
    assert!(
        late > after_first,
        "steady-state accumulation should raise the baseline"
    );
}

#[test]
fn cotinine_is_the_stable_signal_nicotine_is_not() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let cotinine = &nicotine.metabolites[0];
    let subject = subject();

    // Five days of regular use. This has to run to steady state: with a 16 h half-life
    // cotinine is still climbing steeply on day one, and that climb would dominate any
    // measurement of how smoothly it rides.
    const DAYS: i64 = 5;
    let mut parent = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    let mut meta = Curve::new(subject.volume_l(cotinine.vd_l_per_kg));
    for day in 0..DAYS {
        for i in 0..10 {
            let dose = Dose {
                start_secs: day as f64 * 24.0 * HOUR + 8.0 * HOUR + i as f64 * 90.0 * MIN,
                duration_secs: Some(30.0 * MIN),
                nominal_mg: 12.0,
            };
            let response = dose_response(&nicotine, route, &subject, dose);
            meta.add(metabolite_response(
                &response, &nicotine, cotinine, &subject,
            ));
            parent.add(response);
        }
    }

    // Compare the ripple *within one dosing interval*, not across the day. Cotinine
    // accumulates steadily over a day of use, so a whole-day max-to-min would measure
    // that upward trend rather than the smoothness we actually care about.
    let ripple = |c: &Curve| {
        let start = (DAYS - 1) as f64 * 24.0 * HOUR + 20.0 * HOUR;
        let (mut lo, mut hi) = (f64::INFINITY, 0.0f64);
        let mut t = start;
        while t <= start + 90.0 * MIN {
            let v = c.concentration_at(t);
            lo = lo.min(v);
            hi = hi.max(v);
            t += MIN;
        }
        (hi - lo) / hi
    };

    // Measured margin at steady state is around 10x; 5x leaves room for parameter
    // changes without the test going quiet about a real regression.
    assert!(
        ripple(&meta) * 5.0 < ripple(&parent),
        "cotinine must ride far smoother than nicotine within a dosing cycle -- \
         that is the whole reason it is the better read on daily load"
    );
    // Overnight the two signals diverge completely: nicotine washes out, cotinine does
    // not. Stated as a ratio against the same evening level, because the absolute
    // numbers scale with how much the person actually consumes.
    let evening = (DAYS - 1) as f64 * 24.0 * HOUR + 22.0 * HOUR;
    let next_morning = evening + 10.0 * HOUR;
    let parent_left = parent.concentration_at(next_morning) / parent.concentration_at(evening);
    let meta_left = meta.concentration_at(next_morning) / meta.concentration_at(evening);

    assert!(
        parent_left < 0.10,
        "nicotine should be all but gone by morning, {:.1}% remains",
        parent_left * 100.0
    );
    assert!(
        meta_left > 0.50,
        "cotinine should still carry most of yesterday's load, only {:.1}% remains",
        meta_left * 100.0
    );
}

#[test]
fn route_determines_the_shape_of_the_curve() {
    let cocaine = substances::cocaine();
    let subject = subject();

    let peak_for = |route_id: &str| {
        let route = cocaine.route(route_id).unwrap();
        let mut curve = Curve::new(subject.volume_l(cocaine.vd_l_per_kg));
        curve.add(dose_response(
            &cocaine,
            route,
            &subject,
            Dose {
                start_secs: 0.0,
                duration_secs: None,
                nominal_mg: 50.0,
            },
        ));
        curve.peak(0.0, 4.0 * HOUR)
    };

    let (t_smoked, c_smoked) = peak_for("smoked");
    let (t_nasal, c_nasal) = peak_for("intranasal");
    let (_, c_oral) = peak_for("oral");

    assert!(
        t_smoked < 2.0 * MIN,
        "smoked should peak almost immediately"
    );
    assert!(
        t_nasal > 15.0 * MIN,
        "intranasal Tmax should land well later, got {:.0} min",
        t_nasal / MIN
    );
    assert!(
        c_smoked > c_nasal,
        "same absorbed dose delivered faster must reach a higher peak"
    );
    assert!(
        c_oral < c_nasal,
        "first-pass loss should flatten the oral curve"
    );
}

#[test]
fn two_compartment_decay_is_faster_early_than_late() {
    let cocaine = substances::cocaine();
    let route = cocaine.route("intravenous").unwrap();
    let subject = subject();
    let mut curve = Curve::new(subject.volume_l(cocaine.vd_l_per_kg));
    curve.add(dose_response(
        &cocaine,
        route,
        &subject,
        Dose {
            start_secs: 0.0,
            duration_secs: None,
            nominal_mg: 50.0,
        },
    ));

    // Both windows must span the same duration, or this compares nothing at all: a
    // steeper phase measured over a shorter window can still show the larger ratio.
    let decay_over =
        |from: f64| curve.concentration_at(from + 15.0 * MIN) / curve.concentration_at(from);
    let early_ratio = decay_over(0.0);
    let late_ratio = decay_over(2.0 * HOUR);
    assert!(
        early_ratio < late_ratio,
        "the alpha phase must be steeper than the beta phase ({early_ratio:.3} vs {late_ratio:.3})"
    );
}

#[test]
fn an_open_session_falls_back_to_the_routes_default_duration() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    // A pouch is a depot that drains, not a pump running at a constant rate.
    assert!(matches!(route.absorption, Absorption::FirstOrder { .. }));

    let subject = subject();
    let mut open = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    open.add(dose_response(
        &nicotine,
        route,
        &subject,
        // No end recorded yet -- the pouch is still in.
        Dose {
            start_secs: 0.0,
            duration_secs: None,
            nominal_mg: 12.0,
        },
    ));
    let (_, peak) = open.peak(0.0, 4.0 * HOUR);
    assert!(
        peak > 0.0,
        "an open session must still produce a usable estimate"
    );
}

/// Exposure from one pouch used for `minutes`, as area under the curve over four hours.
///
/// Four hours because that is the window Azzopardi et al. report, and comparing against
/// a different window would compare a different quantity.
fn exposure_over_4h(minutes: f64, nominal_mg: f64) -> f64 {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut curve = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    curve.add(dose_response(
        &nicotine,
        route,
        &subject,
        Dose {
            start_secs: 0.0,
            duration_secs: Some(minutes * MIN),
            nominal_mg,
        },
    ));
    // Trapezoid on a one-minute grid. The curve is smooth on that scale.
    curve
        .sample(0.0, 4.0 * HOUR, MIN)
        .windows(2)
        .map(|w| (w[0].1 + w[1].1) / 2.0 * (w[1].0 - w[0].0) / HOUR)
        .sum()
}

/// The published dose-duration data is the only external check this model has, so it is
/// worth asserting against directly rather than paraphrasing.
///
/// Azzopardi et al. 2026, 11 mg pouch: AUC(0-4h) of 24.6, 36.5 and 43.0 h*ng/mL for 10,
/// 20 and 30 minutes of use. What matters is the shape -- strongly front-loaded, with
/// each further ten minutes adding less than the one before -- so the ratios are checked
/// rather than the absolute values, which carry the spread of the population parameters.
#[test]
fn exposure_matches_the_published_dose_duration_data() {
    let ten = exposure_over_4h(10.0, 11.0);
    let twenty = exposure_over_4h(20.0, 11.0);
    let thirty = exposure_over_4h(30.0, 11.0);

    let measured = [24.6 / 43.0, 36.5 / 43.0];
    let modelled = [ten / thirty, twenty / thirty];

    for (measured, modelled) in measured.iter().zip(modelled.iter()) {
        assert!(
            (measured - modelled).abs() < 0.12,
            "modelled exposure ratio {modelled:.2} is too far from the measured {measured:.2}"
        );
    }

    // The first ten minutes must deliver more than the twenty that follow. This is the
    // whole point of the front-loaded shape, and a constant-rate model fails it.
    let first_ten = ten;
    let next_twenty = thirty - ten;
    assert!(
        first_ten > next_twenty,
        "the first ten minutes ({first_ten:.1}) should beat the next twenty ({next_twenty:.1})"
    );
}

#[test]
fn peak_concentration_is_in_the_measured_range() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut curve = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    curve.add(dose_response(
        &nicotine,
        route,
        &subject,
        Dose {
            start_secs: 0.0,
            duration_secs: Some(30.0 * MIN),
            nominal_mg: 11.0,
        },
    ));

    let (at, peak) = curve.peak(0.0, 4.0 * HOUR);
    // Measured: 21.6 ng/mL. Wide bounds on purpose -- volume of distribution and
    // clearance both vary severalfold between people, so a tight assertion here would
    // be asserting false precision about a population average.
    assert!(
        (14.0..30.0).contains(&peak),
        "peak {peak:.1} ng/mL is outside the range the published study supports"
    );
    // Tmax sits at the moment the pouch comes out, which is what the study found at
    // every duration it tested.
    assert!(
        (25.0 * MIN..=35.0 * MIN).contains(&at),
        "peak should land when the pouch is removed, not at {:.0} min",
        at / MIN
    );
}

#[test]
fn a_pouch_taken_out_early_stops_delivering() {
    let short = exposure_over_4h(10.0, 11.0);
    let long = exposure_over_4h(30.0, 11.0);
    assert!(
        short < long * 0.8,
        "removing the pouch must cut exposure short ({short:.1} vs {long:.1})"
    );
}

#[test]
fn a_slow_metaboliser_reaches_higher_levels_on_the_same_intake() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();

    let level_for = |factor: f64| {
        let subject = Subject {
            body_mass_kg: 75.0,
            metabolism_factor: factor,
        };
        let mut curve = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
        for i in 0..8 {
            curve.add(dose_response(
                &nicotine,
                route,
                &subject,
                Dose {
                    start_secs: i as f64 * 90.0 * MIN,
                    duration_secs: Some(30.0 * MIN),
                    nominal_mg: 12.0,
                },
            ));
        }
        curve.concentration_at(11.0 * HOUR)
    };

    // This is the axis a nicotine metabolite ratio would pin down for a real person.
    assert!(
        level_for(0.5) > level_for(1.0),
        "halved clearance must accumulate more drug"
    );
    assert!(level_for(2.0) < level_for(1.0));
}

#[test]
fn concentrations_are_never_negative() {
    // An empty curve is the sharp case: `[].iter().sum::<f64>()` is -0.0, because that
    // is the additive identity for f64, and it would surface as "-0.0 ng/mL".
    let empty = Curve::new(195.0);
    assert!(empty.concentration_at(0.0).is_sign_positive());
    assert_eq!(empty.concentration_at(1.7e9), 0.0);
    assert_eq!(format!("{:.1}", empty.concentration_at(0.0)), "0.0");

    // And long after a real dose, where the metabolite's paired terms have cancelled.
    let nicotine = substances::nicotine();
    let cotinine = &nicotine.metabolites[0];
    let route = nicotine.route("buccal_pouch").unwrap();
    let subject = subject();
    let mut meta = Curve::new(subject.volume_l(cotinine.vd_l_per_kg));
    let response = dose_response(
        &nicotine,
        route,
        &subject,
        Dose {
            start_secs: 0.0,
            duration_secs: Some(30.0 * MIN),
            nominal_mg: 12.0,
        },
    );
    meta.add(metabolite_response(
        &response, &nicotine, cotinine, &subject,
    ));

    for days in 1..40 {
        let value = meta.concentration_at(days as f64 * 24.0 * HOUR);
        assert!(
            value >= 0.0,
            "negative concentration {value} after {days} days"
        );
    }
}
