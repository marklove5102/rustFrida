//! hook() and unhook() API implementation

mod callback;
mod functions;
mod registry;

use crate::context::JSContext;
use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

use functions::{js_call_native, js_hook, js_unhook};
use registry::HOOK_REGISTRY;

/// Register hook API
pub fn register_hook_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        // Register hook(ptr, callback, stealth?)
        let cname = CString::new("hook").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_hook), cname.as_ptr(), 3);
        global.set_property(ctx.as_ptr(), "hook", JSValue(func_val));

        // Register unhook()
        let cname = CString::new("unhook").unwrap();
        let func_val = ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_unhook), cname.as_ptr(), 1);
        global.set_property(ctx.as_ptr(), "unhook", JSValue(func_val));

        // Register callNative(ptr, ...args) - call native function with 0-6 args
        let cname = CString::new("callNative").unwrap();
        let func_val =
            ffi::qjs_new_cfunction(ctx.as_ptr(), Some(js_call_native), cname.as_ptr(), 1);
        global.set_property(ctx.as_ptr(), "callNative", JSValue(func_val));
    }

    global.free(ctx.as_ptr());
}

/// Cleanup all hooks (call before dropping context)
///
/// 两阶段清理：先移除所有 hook（阻止新回调进入），再释放 JS callback。
/// 如果在同一循环中 remove + free，正在其他 hooked thread 执行的回调
/// 可能在 hook_remove 和 free 之间用已释放的 JSValue 调用 JS_Call。
pub fn cleanup_hooks() {
    let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        // 第一阶段：移除所有 hook，阻止新回调触发
        for addr in registry.keys() {
            unsafe {
                ffi::hook::hook_remove(*addr as *mut std::ffi::c_void);
            }
        }
        // 第二阶段：所有 hook 已移除，安全释放 callback
        for (_addr, data) in registry {
            unsafe {
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue =
                    std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
}
