//! Loads the library named by `CRONET_LIBRARY` and starts an engine through
//! the raw bindings. Skipped when the variable is unset.

#![cfg(feature = "dynamic")]

use std::ffi::CStr;

use cronet_sys::*;

#[test]
fn engine_starts_and_reports_its_version() {
    let Some(path) = std::env::var_os("CRONET_LIBRARY") else {
        eprintln!("CRONET_LIBRARY is not set; skipping");
        return;
    };
    load(path).expect("libcronet loads");
    assert!(is_loaded());

    // SAFETY: each object is created, used and destroyed in order, on one thread.
    unsafe {
        let params = Cronet_EngineParams_Create();
        Cronet_EngineParams_user_agent_set(params, c"cronet-sys test".as_ptr());
        let engine = Cronet_Engine_Create();
        assert_eq!(Cronet_Engine_StartWithParams(engine, params), Cronet_RESULT_SUCCESS);
        Cronet_EngineParams_Destroy(params);

        let version = CStr::from_ptr(Cronet_Engine_GetVersionString(engine)).to_str().unwrap();
        assert!(version.starts_with("150."), "{version}");
        assert!(!Cronet_Engine_GetStreamEngine(engine).is_null());

        assert_eq!(Cronet_Engine_Shutdown(engine), Cronet_RESULT_SUCCESS);
        Cronet_Engine_Destroy(engine);
    }
}
