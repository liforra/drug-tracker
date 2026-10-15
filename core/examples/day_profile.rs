//! Print a day's worth of curves so the numbers can be eyeballed against reality.
//! Run with: cargo run -p tracker-core --example day_profile

use tracker_core::pk::{Curve, Dose, Subject, dose_response, metabolite_response, substances};

const MIN: f64 = 60.0;
const HOUR: f64 = 3600.0;

fn main() {
    let nicotine = substances::nicotine();
    let route = nicotine.route("buccal_pouch").unwrap();
    let cotinine = &nicotine.metabolites[0];
    let subject = Subject { body_mass_kg: 75.0, metabolism_factor: 1.0 };

    let mut parent = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    let mut meta = Curve::new(subject.volume_l(cotinine.vd_l_per_kg));

    // 10 pouches of 12 mg, one every 90 minutes starting at 08:00, seven days running.
    for day in 0..7 {
        for i in 0..10 {
            let dose = Dose {
                start_secs: day as f64 * 24.0 * HOUR + 8.0 * HOUR + i as f64 * 90.0 * MIN,
                duration_secs: Some(30.0 * MIN),
                nominal_mg: 12.0,
            };
            let response = dose_response(&nicotine, route, &subject, dose);
            meta.add(metabolite_response(&response, &nicotine, cotinine, &subject));
            parent.add(response);
        }
    }

    // Measured on its own curve: the shared one already has the 09:30 pouch overlapping.
    let mut isolated = Curve::new(subject.volume_l(nicotine.vd_l_per_kg));
    isolated.add(dose_response(
        &nicotine,
        route,
        &subject,
        Dose { start_secs: 0.0, duration_secs: Some(30.0 * MIN), nominal_mg: 12.0 },
    ));
    let (t, c) = isolated.peak(0.0, 4.0 * HOUR);
    println!("Single 12 mg pouch in isolation:");
    println!("  peak {:.1} ng/mL at {:.0} min after insertion", c, t / MIN);

    println!("\nDay 7, hourly (steady state):");
    println!("  {:>6}  {:>10}  {:>10}", "time", "nicotine", "cotinine");
    for h in 6..=23 {
        let t = 6.0 * 24.0 * HOUR + h as f64 * HOUR;
        println!(
            "  {:>4}:00  {:>8.1}    {:>8.1}",
            h,
            parent.concentration_at(t),
            meta.concentration_at(t)
        );
    }

    // Ripple within one dosing interval, late on day 7.
    let window_start = 6.0 * 24.0 * HOUR + 20.0 * HOUR;
    let ripple = |c: &Curve| {
        let (mut lo, mut hi) = (f64::INFINITY, 0.0f64);
        let mut t = window_start;
        while t <= window_start + 90.0 * MIN {
            let v = c.concentration_at(t);
            lo = lo.min(v);
            hi = hi.max(v);
            t += MIN;
        }
        (hi - lo) / hi * 100.0
    };
    println!("\nRipple within one 90 min dosing cycle:");
    println!("  nicotine {:.1}%   cotinine {:.1}%", ripple(&parent), ripple(&meta));
}
