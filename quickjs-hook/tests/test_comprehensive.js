// test_comprehensive.js — Comprehensive integration test
// Usage: ./rustfrida --pid <pid> -l test_comprehensive.js
// Requires: injection into an Android app process with libc and ART runtime

(function() {
    "use strict";

    var passed = 0;
    var failed = 0;
    var total = 0;

    function assert(name, condition, detail) {
        total++;
        if (condition) {
            passed++;
            console.log("[TEST] " + name + ": PASS");
        } else {
            failed++;
            console.log("[TEST] " + name + ": FAIL (" + (detail || "assertion failed") + ")");
        }
    }

    function assertEq(name, actual, expected) {
        total++;
        var actualStr = "" + actual;
        var expectedStr = "" + expected;
        if (actualStr === expectedStr) {
            passed++;
            console.log("[TEST] " + name + ": PASS");
        } else {
            failed++;
            console.log("[TEST] " + name + ": FAIL (expected " + expectedStr + ", got " + actualStr + ")");
        }
    }

    function assertThrows(name, fn) {
        total++;
        try {
            fn();
            failed++;
            console.log("[TEST] " + name + ": FAIL (expected exception, but none thrown)");
        } catch (e) {
            passed++;
            console.log("[TEST] " + name + ": PASS (threw: " + e.message + ")");
        }
    }

    function assertNoThrow(name, fn) {
        total++;
        try {
            fn();
            passed++;
            console.log("[TEST] " + name + ": PASS");
        } catch (e) {
            failed++;
            console.log("[TEST] " + name + ": FAIL (unexpected exception: " + e.message + ")");
        }
    }

    console.log("=== Comprehensive Integration Tests ===");
    console.log("");

    // ====================================================================
    // Section 1: API Availability
    // ====================================================================
    console.log("--- Section 1: API Availability ---");

    assert("ptr is a function", typeof ptr === "function");
    assert("hook is a function", typeof hook === "function");
    assert("unhook is a function", typeof unhook === "function");
    assert("callNative is a function", typeof callNative === "function");
    assert("console.log is a function", typeof console.log === "function");
    assert("console.warn is a function", typeof console.warn === "function");
    assert("console.error is a function", typeof console.error === "function");
    assert("console.info is a function", typeof console.info === "function");
    assert("console.debug is a function", typeof console.debug === "function");
    assert("Memory is an object", typeof Memory === "object");
    assert("Memory.readU8 is a function", typeof Memory.readU8 === "function");
    assert("Memory.readU16 is a function", typeof Memory.readU16 === "function");
    assert("Memory.readU32 is a function", typeof Memory.readU32 === "function");
    assert("Memory.readU64 is a function", typeof Memory.readU64 === "function");
    assert("Memory.readPointer is a function", typeof Memory.readPointer === "function");
    assert("Memory.readCString is a function", typeof Memory.readCString === "function");
    assert("Memory.readUtf8String is a function", typeof Memory.readUtf8String === "function");
    assert("Memory.readByteArray is a function", typeof Memory.readByteArray === "function");
    assert("Memory.writeU8 is a function", typeof Memory.writeU8 === "function");
    assert("Memory.writeU16 is a function", typeof Memory.writeU16 === "function");
    assert("Memory.writeU32 is a function", typeof Memory.writeU32 === "function");
    assert("Memory.writeU64 is a function", typeof Memory.writeU64 === "function");
    assert("Memory.writePointer is a function", typeof Memory.writePointer === "function");
    assert("Java is an object", typeof Java === "object");
    assert("Java.use is a function", typeof Java.use === "function");

    // ====================================================================
    // Section 2: Console output variants
    // ====================================================================
    console.log("");
    console.log("--- Section 2: Console Output ---");

    assertNoThrow("console.log with string", function() {
        console.log("test message");
    });
    assertNoThrow("console.log with number", function() {
        console.log(42);
    });
    assertNoThrow("console.log with multiple args", function() {
        console.log("hello", "world", 123);
    });
    assertNoThrow("console.warn", function() {
        console.warn("warning message");
    });
    assertNoThrow("console.error", function() {
        console.error("error message");
    });
    assertNoThrow("console.info", function() {
        console.info("info message");
    });
    assertNoThrow("console.debug", function() {
        console.debug("debug message");
    });
    assertNoThrow("console.log with ptr", function() {
        console.log("pointer:", ptr("0xDEAD").toString());
    });
    assertNoThrow("console.log with BigInt", function() {
        console.log("bigint:", 12345678901234567890n);
    });
    assertNoThrow("console.log with null/undefined", function() {
        console.log("null:", null, "undefined:", undefined);
    });

    // ====================================================================
    // Section 3: Cross-API interaction: ptr + Memory
    // ====================================================================
    console.log("");
    console.log("--- Section 3: ptr + Memory Interaction ---");

    // ptr arithmetic then Memory read should correctly propagate errors
    var addr = ptr("0x1000").add(0x500);
    assertEq("ptr arithmetic result", addr.toString(), "0x1500");

    // Try reading from an address constructed via arithmetic
    // This should throw because 0x1500 is in the first 64KB (unmapped)
    assertThrows("Memory.readU8 on low arithmetic result", function() {
        Memory.readU8(ptr(0x1500));
    });

    // Verify NativePointer can be passed to Memory.read* directly
    var npAddr = ptr("0xDEAD0000");
    assertThrows("Memory.readU8(NativePointer) for unmapped addr throws", function() {
        Memory.readU8(npAddr);
    });

    // ====================================================================
    // Section 4: Cross-API interaction: Java + ptr
    // ====================================================================
    console.log("");
    console.log("--- Section 4: Java + ptr Interaction ---");

    // Java.use returns a proxy that can be used with hook
    var Activity = Java.use("android.app.Activity");
    assert("Java.use result is usable proxy", typeof Activity === "object");

    // Verify .impl property exists on method wrappers
    var wrapper = Activity.onResume;
    assert("Method wrapper .impl is accessible", wrapper.impl === null);

    // ====================================================================
    // Section 5: Error resilience
    // ====================================================================
    console.log("");
    console.log("--- Section 5: Error Resilience ---");

    // Verify that errors in one API don't break others
    assertThrows("Intentional error 1", function() { Memory.readU8(ptr(0)); });
    assertNoThrow("ptr still works after error", function() { ptr(42).toString(); });

    assertThrows("Intentional error 2", function() { hook(ptr(0), function(){}); });
    assertNoThrow("Memory API still works after hook error", function() {
        assertThrows("nested: readU8(null)", function() { Memory.readU8(ptr(0)); });
    });

    assertThrows("Intentional error 3", function() { callNative(ptr(0)); });
    assertNoThrow("Java.use still works after callNative error", function() {
        Java.use("android.app.Activity");
    });

    // ====================================================================
    // Section 6: Java hook stress test — rapid hook/unhook
    // ====================================================================
    console.log("");
    console.log("--- Section 6: Java Hook Stress Test ---");

    var stressTarget = Java.use("java.lang.Object");
    var stressCycles = 10;
    var stressErrors = 0;

    for (var i = 0; i < stressCycles; i++) {
        try {
            stressTarget.hashCode.impl = function(ctx) {
                return ctx.callOriginal();
            };
            stressTarget.hashCode.impl = null;
        } catch (e) {
            stressErrors++;
            if (stressErrors <= 3) {
                console.log("[TEST] Stress cycle " + i + " error: " + e.message);
            }
        }
    }
    assertEq("Java hook stress " + stressCycles + " cycles, errors", stressErrors, 0);

    // ====================================================================
    // Section 7: NativePointer stress test — rapid allocation
    // ====================================================================
    console.log("");
    console.log("--- Section 7: NativePointer Allocation Stress ---");

    var ptrCount = 1000;
    var ptrErrors = 0;
    for (var j = 0; j < ptrCount; j++) {
        try {
            var p = ptr(j * 0x1000);
            if (p.toString() !== "0x" + (j * 0x1000).toString(16)) {
                ptrErrors++;
            }
        } catch (e) {
            ptrErrors++;
        }
    }
    assertEq("NativePointer " + ptrCount + " allocations, errors", ptrErrors, 0);

    // ====================================================================
    // Section 8: ptr arithmetic stress
    // ====================================================================
    console.log("");
    console.log("--- Section 8: ptr Arithmetic Stress ---");

    var arithBase = ptr(0);
    var arithErrors = 0;
    for (var k = 0; k < 100; k++) {
        try {
            arithBase = arithBase.add(0x100);
        } catch (e) {
            arithErrors++;
        }
    }
    assertEq("100 chained add operations", arithBase.toString(), "0x" + (100 * 0x100).toString(16));
    assertEq("Arithmetic stress errors", arithErrors, 0);

    // ====================================================================
    // Section 9: Mixed Java hook patterns
    // ====================================================================
    console.log("");
    console.log("--- Section 9: Mixed Java Hook Patterns ---");

    // Hook multiple methods simultaneously
    var hookCount = 0;
    var unhookErrors = 0;
    var methods = [
        { cls: "java.lang.Object", method: "hashCode" },
        { cls: "java.lang.Object", method: "toString" },
    ];

    for (var m = 0; m < methods.length; m++) {
        try {
            var target = Java.use(methods[m].cls);
            target[methods[m].method].impl = function(ctx) {
                return ctx.callOriginal();
            };
            hookCount++;
        } catch (e) {
            console.log("[TEST] Hook " + methods[m].cls + "." + methods[m].method + " failed: " + e.message);
        }
    }
    assertEq("Multiple simultaneous hooks installed", hookCount, methods.length);

    // Unhook all
    for (var n = 0; n < methods.length; n++) {
        try {
            var target2 = Java.use(methods[n].cls);
            target2[methods[n].method].impl = null;
        } catch (e) {
            unhookErrors++;
            console.log("[TEST] Unhook " + methods[n].cls + "." + methods[n].method + " failed: " + e.message);
        }
    }
    assertEq("All simultaneous hooks removed, errors", unhookErrors, 0);

    // ====================================================================
    // Section 10: Edge cases and type coercion
    // ====================================================================
    console.log("");
    console.log("--- Section 10: Edge Cases ---");

    // ptr with various numeric types
    assertEq("ptr(0.0)", ptr(0.0).toString(), "0x0");
    assertEq("ptr(1.0)", ptr(1.0).toString(), "0x1");

    // BigInt construction
    assertEq("ptr(0n)", ptr(0n).toString(), "0x0");
    assertEq("ptr(1n)", ptr(1n).toString(), "0x1");
    assertEq("ptr(0xFFn)", ptr(0xFFn).toString(), "0xff");

    // Empty hex string edge cases
    assertThrows("ptr('') throws", function() {
        ptr("");
    });

    assertThrows("ptr('0x') throws", function() {
        ptr("0x");
    });

    // NativePointer method on wrong object type
    // (toString is on the prototype, calling on wrong this should throw)

    // Verify GC doesn't collect NativePointers in active use
    var ptrs = [];
    for (var g = 0; g < 100; g++) {
        ptrs.push(ptr(g * 8));
    }
    // Force some GC pressure by creating many objects
    for (var gc = 0; gc < 1000; gc++) {
        var tmp = { a: gc, b: ptr(gc) };
    }
    // Verify original pointers are still valid
    var gcErrors = 0;
    for (var gv = 0; gv < 100; gv++) {
        if (ptrs[gv].toString() !== "0x" + (gv * 8).toString(16)) {
            gcErrors++;
        }
    }
    assertEq("NativePointer survives GC pressure", gcErrors, 0);

    // === Summary ===
    console.log("");
    console.log("=== FINAL SUMMARY ===");
    console.log("[SUMMARY] " + passed + "/" + total + " tests passed");
    if (failed > 0) {
        console.log("[SUMMARY] " + failed + " tests FAILED");
    } else {
        console.log("[SUMMARY] All tests passed!");
    }
})();
