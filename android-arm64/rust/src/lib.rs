//! JNI surface.
//!
//! The only file in the crate that knows about Java. Everything below it in
//! [`bridge`] is plain Rust taking and returning JSON, which keeps the parts worth
//! testing testable on the host where there is no JVM.

pub mod bridge;

use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::{jdouble, jstring},
};

/// Read a Java string, or return an empty Rust one.
///
/// A failure here means the JVM handed us something impossible, and there is no useful
/// recovery; the callee will reject an empty argument with a normal error result.
fn text(env: &mut JNIEnv, value: &JString) -> String {
    env.get_string(value).map(|s| s.into()).unwrap_or_default()
}

/// Hand a Rust string back. If allocation fails there is nothing left to do but return
/// null, which the Kotlin side treats as a hard error.
fn reply(env: &mut JNIEnv, value: String) -> jstring {
    match env.new_string(value) {
        Ok(java) => java.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_initLogging(
    _env: JNIEnv,
    _class: JClass,
) {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("snus-native"),
    );
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_generateIdentity(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::generate_identity())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_enroll(
    mut env: JNIEnv,
    _class: JClass,
    request: JString,
) -> jstring {
    let request = text(&mut env, &request);
    reply(&mut env, bridge::enroll(&request))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_open(
    mut env: JNIEnv,
    _class: JClass,
    request: JString,
) -> jstring {
    let request = text(&mut env, &request);
    reply(&mut env, bridge::open(&request))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_snapshot(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::snapshot())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_startSession(
    mut env: JNIEnv,
    _class: JClass,
    product_id: JString,
) -> jstring {
    let product_id = text(&mut env, &product_id);
    reply(&mut env, bridge::start_session(&product_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_endSession(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jstring {
    let session_id = text(&mut env, &session_id);
    reply(&mut env, bridge::end_session(&session_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_pauseSession(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jstring {
    let session_id = text(&mut env, &session_id);
    reply(&mut env, bridge::pause_session(&session_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_resumeSession(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jstring {
    let session_id = text(&mut env, &session_id);
    reply(&mut env, bridge::resume_session(&session_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_discardSession(
    mut env: JNIEnv,
    _class: JClass,
    session_id: JString,
) -> jstring {
    let session_id = text(&mut env, &session_id);
    reply(&mut env, bridge::discard_session(&session_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_retireProduct(
    mut env: JNIEnv,
    _class: JClass,
    product_id: JString,
) -> jstring {
    let product_id = text(&mut env, &product_id);
    reply(&mut env, bridge::retire_product(&product_id))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_setProductDuration(
    mut env: JNIEnv,
    _class: JClass,
    product_id: JString,
    minutes: f64,
) -> jstring {
    let product_id = text(&mut env, &product_id);
    reply(&mut env, bridge::set_product_duration(&product_id, minutes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_updateSubject(
    mut env: JNIEnv,
    _class: JClass,
    body_mass_kg: f64,
    metabolism_factor: f64,
) -> jstring {
    // Zero stands for "leave this alone": the JNI boundary has no null for a primitive
    // double, and no real body mass or metabolism factor is zero.
    reply(
        &mut env,
        bridge::update_subject(
            Some(body_mass_kg).filter(|v| *v > 0.0),
            Some(metabolism_factor).filter(|v| *v > 0.0),
        ),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_samples(
    mut env: JNIEnv,
    _class: JClass,
    from_secs: i64,
    to_secs: i64,
    steps: i32,
) -> jstring {
    reply(
        &mut env,
        bridge::samples(from_secs, to_secs, steps.max(2) as usize),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_addProduct(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
    nominal_mg: jdouble,
    accent: JString,
) -> jstring {
    let name = text(&mut env, &name);
    let accent = text(&mut env, &accent);
    let accent = (!accent.is_empty()).then_some(accent);
    reply(&mut env, bridge::add_product(&name, nominal_mg, accent))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_sync(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::sync())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_leaseShare(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::lease_share())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_approveDevices(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::approve_devices())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_createInvite(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::create_invite())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_bootstrapAccount(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::bootstrap_account())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_de_liforra_snustracker_NativeBridge_close(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    reply(&mut env, bridge::close())
}
