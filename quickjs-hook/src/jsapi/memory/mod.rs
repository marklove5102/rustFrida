//! Memory API implementation

mod helpers;
mod read;
mod write;

use crate::context::JSContext;
use crate::jsapi::util::add_cfunction_to_object;

use read::*;
use write::*;

/// Register Memory API
pub fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = memory.raw();
        add_cfunction_to_object(ctx_ptr, obj, "readU8", memory_read_u8, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU16", memory_read_u16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU32", memory_read_u32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU64", memory_read_u64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readPointer", memory_read_pointer, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readCString", memory_read_cstring, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUtf8String", memory_read_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readByteArray", memory_read_byte_array, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU8", memory_write_u8, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU16", memory_write_u16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU32", memory_write_u32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU64", memory_write_u64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writePointer", memory_write_pointer, 2);
    }

    // Set Memory on global object
    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}
