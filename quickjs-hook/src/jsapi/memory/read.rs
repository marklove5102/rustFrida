//! Memory read operations

use crate::ffi;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;
use super::helpers::get_addr_from_arg;

/// Memory.readU8(ptr)
pub(super) unsafe extern "C" fn memory_read_u8(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"readU8() requires 1 argument\0".as_ptr() as *const _);
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read(addr as *const u8);
    JSValue::int(val as i32).raw()
}

/// Memory.readU16(ptr)
pub(super) unsafe extern "C" fn memory_read_u16(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU16() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 2) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u16);
    JSValue::int(val as i32).raw()
}

/// Memory.readU32(ptr)
pub(super) unsafe extern "C" fn memory_read_u32(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU32() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u32);
    // Use BigInt for values that might overflow i32
    ffi::JS_NewBigUint64(ctx, val as u64)
}

/// Memory.readU64(ptr)
pub(super) unsafe extern "C" fn memory_read_u64(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readU64() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 8) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u64);
    ffi::JS_NewBigUint64(ctx, val)
}

/// Memory.readPointer(ptr)
pub(super) unsafe extern "C" fn memory_read_pointer(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readPointer() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 8) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    let val = std::ptr::read_unaligned(addr as *const u64);
    create_native_pointer(ctx, val).raw()
}

/// Memory.readCString(ptr)
pub(super) unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readCString() requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    if !is_addr_accessible(addr, 1) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Bounded scan: find '\0' within MAX_CSTRING_LEN bytes to avoid SEGV on unterminated buffers.
    // Only call is_addr_accessible at page boundaries (every 4096 bytes) for performance.
    const MAX_CSTRING_LEN: usize = 4096;
    const PAGE_SIZE: u64 = 4096;
    let mut len = 0usize;
    // Track next page boundary that needs checking
    let mut next_page_check = (addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
    while len < MAX_CSTRING_LEN {
        let byte_addr = addr + len as u64;
        // Check accessibility when we cross into a new page
        if byte_addr >= next_page_check {
            if !is_addr_accessible(byte_addr, 1) {
                break;
            }
            next_page_check = (byte_addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
        }
        if *(byte_addr as *const u8) == 0 {
            break;
        }
        len += 1;
    }
    if len >= MAX_CSTRING_LEN {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"readCString: string exceeds maximum length (4096)\0".as_ptr() as *const _,
        );
    }
    let slice = std::slice::from_raw_parts(addr as *const u8, len);
    let s = String::from_utf8_lossy(slice);
    JSValue::string(ctx, &s).raw()
}

/// Memory.readUtf8String(ptr)
pub(super) unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // Same as readCString for now
    memory_read_cstring(ctx, _this, argc, argv)
}

/// Memory.readByteArray(ptr, length)
pub(super) unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"readByteArray() requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(a) => a,
        None => return ffi::JS_ThrowTypeError(ctx, b"Invalid pointer\0".as_ptr() as *const _),
    };

    let length_raw = match JSValue(*argv.add(1)).to_i64(ctx) {
        Some(v) => v,
        None => return ffi::JS_ThrowTypeError(ctx, b"readByteArray: length must be a number\0".as_ptr() as *const _),
    };
    if length_raw <= 0 {
        return ffi::JS_ThrowRangeError(ctx, b"readByteArray: length must be positive\0".as_ptr() as *const _);
    }
    const MAX_READ_SIZE: i64 = 1024 * 1024 * 1024; // 1GB
    if length_raw > MAX_READ_SIZE {
        return ffi::JS_ThrowRangeError(ctx, b"readByteArray: length exceeds maximum (1GB)\0".as_ptr() as *const _);
    }
    let length = length_raw as usize;

    if !is_addr_accessible(addr, length) {
        return ffi::JS_ThrowRangeError(ctx, b"Invalid memory address\0".as_ptr() as *const _);
    }
    // Create ArrayBuffer
    let slice = std::slice::from_raw_parts(addr as *const u8, length);
    let arr = ffi::JS_NewArrayBufferCopy(ctx, slice.as_ptr(), length);
    arr
}
