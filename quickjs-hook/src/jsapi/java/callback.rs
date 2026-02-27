//! Java hook callback and registry
//!
//! Contains: JavaHookData, JAVA_HOOK_REGISTRY, CURRENT_HOOK_* globals,
//! helper functions, dispatch_call!, js_call_original, java_hook_callback.

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::jni_core::*;

// ============================================================================
// Hook registry
// ============================================================================

pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Original method state (saved for unhook restore)
    pub(super) original_access_flags: u32,
    pub(super) original_data: u64,
    pub(super) original_entry_point: u64,
    // ArtMethod clone for callOriginal (heap-allocated, 8-byte aligned)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // Original jmethodID (before decode) — for JNI calls via clone
    pub(super) method_id_raw: u64,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    pub(super) class_name: String,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

// Callback state globals — set before JS_Call in java_hook_callback, read by js_call_original.
// Protected by JS_ENGINE lock (single-threaded JS execution). Use atomics to avoid UB from
// static mut in multi-threaded context.
pub(super) static CURRENT_HOOK_CTX_PTR: AtomicUsize = AtomicUsize::new(0);
pub(super) static CURRENT_HOOK_ART_METHOD: AtomicU64 = AtomicU64::new(0);

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

pub(super) fn init_java_registry() {
    let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}

/// Count the number of parameters in a JNI method signature.
/// "(II)V" → 2, "(Ljava/lang/String;I)V" → 2, "()V" → 0
pub(super) fn count_jni_params(sig: &str) -> usize {
    let bytes = sig.as_bytes();
    let mut count = 0;
    let mut i = 0;
    // skip to '('
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        count += 1;
    }
    count
}

/// Parse a JNI method signature into individual parameter type descriptors.
/// "(ILjava/lang/String;[B)V" → ["I", "Ljava/lang/String;", "[B"]
pub(super) fn parse_jni_param_types(sig: &str) -> Vec<String> {
    let bytes = sig.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    // skip to '('
    while i < bytes.len() && bytes[i] != b'(' {
        i += 1;
    }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        let start = i;
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        result.push(String::from_utf8_lossy(&bytes[start..i]).to_string());
    }
    result
}

// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

/// JS CFunction: ctx.callOriginal()
/// Invokes the cloned ArtMethod via JNI CallNonvirtual*MethodA / CallStatic*MethodA.
/// Returns the method's return value as a JS value.
///
/// Must be called from within a java_hook_callback (reads CURRENT_HOOK_* globals).
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let art_method_addr = CURRENT_HOOK_ART_METHOD.load(Ordering::Relaxed);
    let ctx_ptr = CURRENT_HOOK_CTX_PTR.load(Ordering::Relaxed) as *mut hook_ffi::HookContext;
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data for clone info
    let (clone_addr, class_global_ref, return_type, param_count, is_static) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (data.clone_addr, data.class_global_ref, data.return_type, data.param_count, data.is_static)
    }; // lock released

    if clone_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal: no ArtMethod clone available\0".as_ptr() as *const _,
        );
    }

    let hook_ctx = &*ctx_ptr;

    // JNIEnv* is in x0 of the HookContext (set by ART's JNI trampoline)
    let env: JniEnv = hook_ctx.x[0] as JniEnv;
    if env.is_null() {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal: JNIEnv* is null\0".as_ptr() as *const _,
        );
    }

    // Build jvalue args from HookContext registers x2-x7 + stack spill
    // jvalue is a union of 8 bytes (same size on ARM64)
    // ARM64 JNI: x0=JNIEnv, x1=this/class, x2-x7=args 0-5, stack for args 6+
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    for i in 0..param_count {
        let val = if i < 6 {
            hook_ctx.x[2 + i]
        } else {
            // Args 6+ are on the stack at SP+0, SP+8, SP+16, ...
            let sp = hook_ctx.sp as usize;
            *((sp + (i - 6) * 8) as *const u64)
        };
        jargs.push(val);
    }
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    // Use clone_addr as jmethodID — it's heap-allocated with 8-byte alignment (bit 0 = 0),
    // so ART treats it as a raw ArtMethod* pointer (not encoded).
    let clone_mid = clone_addr as *mut std::ffi::c_void;
    let cls = class_global_ref as *mut std::ffi::c_void;
    let this_obj = hook_ctx.x[1] as *mut std::ffi::c_void;

    // Clear any pending exception before calling original
    jni_check_exc(env);

    match return_type {
        b'V' => {
            dispatch_call!(env, JNI_CALL_STATIC_VOID_METHOD_A, JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                           cls, this_obj, clone_mid, jargs_ptr, is_static, ());
            if jni_check_exc(env) {
                if is_static {
                    output_message("[callOriginal] JNI exception in static void call");
                } else {
                    output_message("[callOriginal] JNI exception in nonvirtual void call");
                }
            }
            ffi::qjs_undefined()
        }
        b'Z' => {
            let ret: u8 = dispatch_call!(env, JNI_CALL_STATIC_BOOLEAN_METHOD_A, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                                         cls, this_obj, clone_mid, jargs_ptr, is_static, u8);
            jni_check_exc(env);
            JSValue::bool(ret != 0).raw()
        }
        b'I' | b'B' | b'C' | b'S' => {
            let ret: i32 = dispatch_call!(env, JNI_CALL_STATIC_INT_METHOD_A, JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                                          cls, this_obj, clone_mid, jargs_ptr, is_static, i32);
            jni_check_exc(env);
            JSValue::int(ret).raw()
        }
        b'J' => {
            let ret: i64 = dispatch_call!(env, JNI_CALL_STATIC_LONG_METHOD_A, JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                                          cls, this_obj, clone_mid, jargs_ptr, is_static, i64);
            jni_check_exc(env);
            ffi::JS_NewBigUint64(ctx, ret as u64)
        }
        b'F' => {
            let ret: f32 = dispatch_call!(env, JNI_CALL_STATIC_FLOAT_METHOD_A, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                                          cls, this_obj, clone_mid, jargs_ptr, is_static, f32);
            jni_check_exc(env);
            JSValue::float(ret as f64).raw()
        }
        b'D' => {
            let ret: f64 = dispatch_call!(env, JNI_CALL_STATIC_DOUBLE_METHOD_A, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                                          cls, this_obj, clone_mid, jargs_ptr, is_static, f64);
            jni_check_exc(env);
            JSValue::float(ret).raw()
        }
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(env, JNI_CALL_STATIC_OBJECT_METHOD_A, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                                                            cls, this_obj, clone_mid, jargs_ptr, is_static, *mut std::ffi::c_void);
            jni_check_exc(env);
            if ret.is_null() {
                ffi::qjs_null()
            } else {
                let js_val = ffi::JS_NewBigUint64(ctx, ret as u64);
                // 释放 JNI local ref，避免 local ref table 泄漏
                let delete_local_ref: DeleteLocalRefFn =
                    jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
                delete_local_ref(env, ret);
                js_val
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // KNOWN LIMITATION: ARM64 ABI passes floats in d0-d7 (FP registers), not x registers.
            // HookContext currently only saves x0-x30. The `raw` value comes from an x register,
            // which may not contain the float argument. This will produce incorrect values.
            // TODO: Extend HookContext to save d0-d7 and read float args from FP registers.
            let f = f32::from_bits(raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // KNOWN LIMITATION: Same as F — double args are in d registers, not x registers.
            // TODO: Extend HookContext to save d0-d7 and read double args from FP registers.
            let d = f64::from_bits(raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }

            // String → read as JS string
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn =
                    jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn =
                    jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars)
                        .to_string_lossy()
                        .to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                // GetStringUTFChars failed — fall through to wrapped object
                jni_check_exc(env);
            }

            // Other object → wrap as {__jptr, __jclass} for Proxy field access
            let wrapper = ffi::JS_NewObject(ctx);
            let wrapper_val = JSValue(wrapper);

            let ptr_val = ffi::JS_NewBigUint64(ctx, raw);
            wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

            // Extract class name from signature: "Ljava/lang/Foo;" → "java.lang.Foo"
            let type_name = if sig.starts_with('L') && sig.ends_with(';') {
                sig[1..sig.len() - 1].replace('/', ".")
            } else {
                // Array or unknown — use raw signature
                sig.replace('/', ".")
            };
            let cls_val = JSValue::string(ctx, &type_name);
            wrapper_val.set_property(ctx, "__jclass", cls_val);

            wrapper
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock (same pattern as hook_api.rs)
    let (ctx_usize, callback_bytes, is_static, param_count, return_type, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.is_static,
         hook_data.param_count, hook_data.return_type,
         hook_data.param_types.clone())
    }; // lock released

    // Serialize JS access via JS_ENGINE mutex.
    // Use try_lock() to prevent same-thread deadlock: if JS thread executes JS → JNI → hooked
    // method, JS thread already holds JS_ENGINE → blocking lock() would deadlock.
    // Same pattern as hook_api/callback.rs.
    let _js_guard = match crate::JS_ENGINE.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::WouldBlock) => {
            // JS 线程已持有锁（重入调用）或另一线程正在执行回调，跳过以避免死锁
            output_message(&format!(
                "[java hook] callback skipped (JS engine busy), art_method={:#x}",
                art_method_addr
            ));
            return;
        }
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
    };

    let ctx = ctx_usize as *mut ffi::JSContext;
    let callback: ffi::JSValue =
        std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);

    // CRITICAL: Update QuickJS stack top for cross-thread safety
    ffi::qjs_update_stack_top(ctx);

    // Set callback state globals for js_call_original
    CURRENT_HOOK_CTX_PTR.store(ctx_ptr as usize, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(art_method_addr, Ordering::Relaxed);

    // Build context object
    let js_ctx = ffi::JS_NewObject(ctx);
    let hook_ctx = &*ctx_ptr;

    // JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    // Add thisObj for instance methods (x1 = jobject this)
    // NOTE: thisObj 和 object 类型参数使用 ART 传入的原始 local ref（x 寄存器中的 jobject）。
    // 这些 local ref 在 hook callback 返回前有效。JS callback 中不应异步存储这些值。
    // 如需跨 callback 持久化，需在 JS 侧调用 Java 方法创建 global ref。
    if !is_static {
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[1]);
        JSValue(js_ctx).set_property(ctx, "thisObj", JSValue(val));
    }

    // Add args[] — x2-x7 contain first 6 Java arguments, stack for args 6+.
    // JNIEnv* from x0 for reading String/Object args.
    {
        let env: JniEnv = hook_ctx.x[0] as JniEnv;
        let arr = ffi::JS_NewArray(ctx);
        for i in 0..param_count {
            let raw = if i < 6 {
                hook_ctx.x[2 + i] // x2-x7
            } else {
                // Args 6+ are on the stack at SP+0, SP+8, SP+16, ...
                let sp = hook_ctx.sp as usize;
                *((sp + (i - 6) * 8) as *const u64)
            };
            let val = marshal_jni_arg_to_js(ctx, env, raw, param_types.get(i).map(|s| s.as_str()));
            ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
        }
        JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
    }

    // Add env (JNIEnv* — useful for advanced JNI calls from JS)
    {
        let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[0]);
        JSValue(js_ctx).set_property(ctx, "env", JSValue(val));
    }

    // Add callOriginal() CFunction to the context object
    {
        let cname = CString::new("callOriginal").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx, Some(js_call_original), cname.as_ptr(), 0);
        JSValue(js_ctx).set_property(ctx, "callOriginal", JSValue(func_val));
    }

    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback, global, 1, &js_ctx as *const _ as *mut _);

    // Check for exception
    if ffi::qjs_is_exception(result) != 0 {
        let exc = ffi::JS_GetException(ctx);
        let exc_val = JSValue(exc);
        let msg_prop = exc_val.get_property(ctx, "message");
        let msg = if let Some(s) = msg_prop.to_string(ctx) {
            msg_prop.free(ctx);
            s
        } else {
            msg_prop.free(ctx);
            exc_val.to_string(ctx).unwrap_or_else(|| "[unknown exception]".to_string())
        };
        output_message(&format!("[java hook error] {}", msg));
        exc_val.free(ctx);
    } else if return_type != b'V' {
        // Propagate JS return value to HookContext.x[0] for non-void methods.
        // The thunk restores x0 from HookContext, so ART sees this as the return value.
        let result_val = JSValue(result);
        let ret_u64 = match return_type {
            b'F' => {
                // Float: convert JS number to f32 IEEE 754 bits in low 32 bits
                if let Some(f) = result_val.to_float() {
                    (f as f32).to_bits() as u64
                } else {
                    0u64
                }
            }
            b'D' => {
                // Double: convert JS number to f64 IEEE 754 bits
                if let Some(f) = result_val.to_float() {
                    f.to_bits()
                } else {
                    0u64
                }
            }
            _ => {
                // Integer/object types: use u64/i64 conversion
                if let Some(v) = result_val.to_u64(ctx) {
                    v
                } else if let Some(v) = result_val.to_i64(ctx) {
                    v as u64
                } else {
                    // undefined/null → 0 (NULL for objects, 0 for primitives)
                    0u64
                }
            }
        };
        (*ctx_ptr).x[0] = ret_u64;
    }

    // Clear callback state globals
    CURRENT_HOOK_CTX_PTR.store(0, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(0, Ordering::Relaxed);

    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
}
