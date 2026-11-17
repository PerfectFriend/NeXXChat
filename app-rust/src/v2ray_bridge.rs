//! Мост к Xray-ядру через libv2ray (Этап 4.3, outbound через ядро).
//!
//! Приложение — чистый Rust NativeActivity (hasCode=false), Java-слоя нет,
//! поэтому libgojni.so (из app/libs/libv2ray.aar) грузим через dlopen и зовём
//! gomobile JNI-экспорты напрямую: initCoreEnv → newCoreController → startLoop.
//!
//! На хосте (не Android) — заглушка с Err, чтобы юнит-тесты гонялись везде.
//! В рантайме на устройстве проверяется вручную (нет эмулятора в этом окружении).

use std::sync::Mutex;

#[cfg(target_os = "android")]
pub fn set_vm(vm_raw: *mut std::ffi::c_void) {
    imp::set_vm(vm_raw);
}

#[cfg(target_os = "android")]
pub fn set_asset_manager(am_raw: *mut std::ffi::c_void) {
    imp::set_asset_manager(am_raw);
}

/// Распаковывает geoip.dat/geosite.dat из APK assets в dest (Xray читает их с диска).
#[cfg(target_os = "android")]
pub fn extract_assets(dest: &str) -> Result<(), String> {
    imp::extract_assets(dest)
}

#[cfg(not(target_os = "android"))]
pub fn extract_assets(_dest: &str) -> Result<(), String> {
    Err("только Android".into())
}

/// Xray-конфиг для локального SOCKS5 + outbound из user_config (SS/VLESS/...).
/// Обёртка над control::build_xray_merged_config — тестируется на хосте.
pub fn socks_config(local_port: u16, outbound_json: &str) -> Result<String, String> {
    let v = nexxrust::control::build_xray_merged_config(outbound_json, local_port, "socks");
    let cfg = v.get("config").and_then(|c| c.as_str()).ok_or("merged config без поля config")?;
    let root: serde_json::Value = serde_json::from_str(cfg).map_err(|e| e.to_string())?;
    if !root.get("inbounds").and_then(|i| i.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
        return Err("merged config без inbounds".into());
    }
    Ok(cfg.to_string())
}

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use jni::JNIEnv;
    use std::ffi::{c_void, CString};

    /// JavaVM/AssetManager — raw pointers, потокобезопасность обеспечиваем сами
    /// (доступ только под мьютексом из одного потока UI).
    struct SendSync<T>(T);
    unsafe impl<T> Send for SendSync<T> {}
    unsafe impl<T> Sync for SendSync<T> {}

    // храним raw-указатели (JavaVM/AssetManager не Clone), конструируем на месте
    static VM: SendSync<Mutex<Option<usize>>> = SendSync(Mutex::new(None));
    static ASSETS: SendSync<Mutex<Option<usize>>> = SendSync(Mutex::new(None));
    static CTRL: SendSync<Mutex<Option<(*mut c_void, usize, usize)>>> = SendSync(Mutex::new(None));

    pub fn set_vm(ptr: *mut c_void) {
        *VM.0.lock().unwrap() = Some(ptr as usize);
    }
    pub fn set_asset_manager(ptr: *mut c_void) {
        *ASSETS.0.lock().unwrap() = Some(ptr as usize);
    }

    pub fn extract_assets(dest: &str) -> Result<(), String> {
        use std::io::Read;
        let raw = ASSETS.0.lock().unwrap().ok_or("AssetManager не установлен")?;
        let ptr = raw as *mut android_activity::ndk_sys::AAssetManager;
        if ptr.is_null() {
            return Err("null AAssetManager".into());
        }
        let am = unsafe {
            android_activity::ndk::asset::AssetManager::from_ptr(
                std::ptr::NonNull::new_unchecked(ptr),
            )
        };
        std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
        for name in ["geoip.dat", "geosite.dat", "geoip-only-cn-private.dat"] {
            let cname = CString::new(name).unwrap();
            let mut asset = am.open(&cname).ok_or_else(|| format!("asset {name} не найден в APK"))?;
            let buf = asset.buffer().map_err(|e| e.to_string())?;
            std::fs::write(format!("{dest}/{name}"), buf).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    unsafe fn load_fn(handle: *mut c_void, name: &str) -> Result<usize, String> {
        let c = CString::new(name).unwrap();
        let p = libc::dlsym(handle, c.as_ptr());
        if p.is_null() {
            Err(format!("dlsym {name}: не найден"))
        } else {
            Ok(p as usize)
        }
    }

    type FInit = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
    type FNew = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
    type FLoop = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, jni::sys::jint);
    type FStop = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);

    /// initCoreEnv(assetPath, deviceID) + newCoreController(null) + startLoop(config, -1).
    pub fn start(asset_path: &str, device_id: &str, config_json: &str) -> Result<(), String> {
        unsafe {
            let handle = libc::dlopen(CString::new("libgojni.so").unwrap().as_ptr(), libc::RTLD_NOW);
            if handle.is_null() {
                return Err("dlopen libgojni.so: не найден (нет в jniLibs?)".into());
            }
            let vm_raw = VM.0.lock().unwrap().ok_or("JavaVM не установлен")?;
            let vm = unsafe { jni::JavaVM::from_raw(vm_raw as *mut jni::sys::JavaVM) }.map_err(|e| format!("JavaVM::from_raw: {e}"))?;
            let mut env = vm.get_env().map_err(|e| format!("get_env: {e}"))?;
            let env_ptr = &mut env as *mut JNIEnv as *mut c_void;
            let null_cls = std::ptr::null_mut::<c_void>();

            let init: FInit = std::mem::transmute(load_fn(handle, "Java_libv2ray_Libv2ray_initCoreEnv")?);
            let new_ctrl: FNew = std::mem::transmute(load_fn(handle, "Java_libv2ray_Libv2ray_newCoreController")?);
            let start_loop: FLoop = std::mem::transmute(load_fn(handle, "Java_libv2ray_CoreController_startLoop")?);
            let stop_loop = load_fn(handle, "Java_libv2ray_CoreController_stopLoop")?;

            let asset = env.new_string(asset_path).map_err(|e| e.to_string())?;
            let dev = env.new_string(device_id).map_err(|e| e.to_string())?;
            init(env_ptr, null_cls, asset.as_raw() as *mut c_void, dev.as_raw() as *mut c_void);

            // callback handler = null: gomobile не дёргает его, пока ядро не шлёт статусы
            let ctrl = new_ctrl(env_ptr, null_cls, std::ptr::null_mut());
            if ctrl.is_null() {
                return Err("newCoreController вернул null".into());
            }
            let cfg = env.new_string(config_json).map_err(|e| e.to_string())?;
            start_loop(env_ptr, null_cls, ctrl, cfg.as_raw() as *mut c_void, -1);
            *CTRL.0.lock().unwrap() = Some((handle, ctrl as usize, stop_loop));
            Ok(())
        }
    }

    pub fn stop() {
        unsafe {
            if let Some((handle, ctrl, stop_fn)) = CTRL.0.lock().unwrap().take() {
                if let Some(vm_raw) = *VM.0.lock().unwrap() {
                    if let Ok(vm) = unsafe { jni::JavaVM::from_raw(vm_raw as *mut jni::sys::JavaVM) } {
                        if let Ok(mut env) = vm.get_env() {
                            let f: FStop = std::mem::transmute(stop_fn);
                            f(&mut env as *mut JNIEnv as *mut c_void, std::ptr::null_mut(), ctrl as *mut c_void);
                        }
                    }
                }
                libc::dlclose(handle);
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    pub fn start(_asset_path: &str, _device_id: &str, _config_json: &str) -> Result<(), String> {
        Err("Xray-ядро доступно только на Android (libgojni.so)".into())
    }
    pub fn stop() {}
}

pub fn start(asset_path: &str, device_id: &str, config_json: &str) -> Result<(), String> {
    imp::start(asset_path, device_id, config_json)
}

pub fn stop() {
    imp::stop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_config_has_inbound_and_outbound() {
        let outbound = serde_json::json!({
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": "1.2.3.4", "port": 8388, "method": "chacha20-ietf-poly1305", "password": "x"}]},
            "tag": "proxy"
        });
        let cfg = socks_config(21080, &outbound.to_string()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert!(v["inbounds"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
        assert_eq!(v["outbounds"][0]["protocol"], "shadowsocks");
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn host_stub_returns_err() {
        assert!(start("/tmp", "dev", "{}").is_err());
    }
}
