//! nexxrust — Rust-ядро форка NeXX (миграция с Kotlin, фазы 1-3 плана).
//! JNI-мост в Android: все функции — extern "C" с префиксом Java_com_nexx_rustcore_RustCore_

pub mod bip39;
pub mod keytree;
pub mod control;
pub mod proxy_runtime;
pub mod tor_transport;
pub mod crypto;
mod jni_api;
pub mod proxy_parse;

pub mod protocols;
mod jni_smp;

#[cfg(test)]
mod control_tests;

pub use jni_api::*;
