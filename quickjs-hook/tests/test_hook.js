// test_hook.js — hook/unhook/callNative API comprehensive test
// Usage: ./rustfrida --pid <pid> -l test_hook.js
// Requires: injection into any process with libc loaded

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

    console.log("=== Hook API Tests ===");
    console.log("");

    // === Section 1: hook() argument validation ===
    console.log("--- Section 1: hook() Argument Validation ---");

    assertThrows("hook() no args throws", function() {
        hook();
    });

    assertThrows("hook(ptr(0)) one arg throws", function() {
        hook(ptr(0));
    });

    assertThrows("hook(ptr(0), 'not a function') throws", function() {
        hook(ptr(0), "not a function");
    });

    assertThrows("hook(ptr(0), 123) non-function throws", function() {
        hook(ptr(0), 123);
    });

    // Hook at null address should fail (hook_attach fails on invalid address)
    assertThrows("hook(ptr(0), fn) null address throws", function() {
        hook(ptr(0), function(ctx) {});
    });

    // Hook at unmapped address should fail
    assertThrows("hook(ptr(0xDEAD), fn) unmapped address throws", function() {
        hook(ptr("0xDEAD"), function(ctx) {});
    });

    // === Section 2: unhook() argument validation ===
    console.log("");
    console.log("--- Section 2: unhook() Argument Validation ---");

    assertThrows("unhook() no args throws", function() {
        unhook();
    });

    // Unhooking an address that was never hooked should fail
    assertThrows("unhook(ptr(0x1234)) never-hooked throws", function() {
        unhook(ptr("0x1234"));
    });

    // === Section 3: callNative() argument validation ===
    console.log("");
    console.log("--- Section 3: callNative() Argument Validation ---");

    assertThrows("callNative() no args throws", function() {
        callNative();
    });

    // callNative with null/low address should throw (< 0x10000 check)
    assertThrows("callNative(ptr(0)) null address throws", function() {
        callNative(ptr(0));
    });

    assertThrows("callNative(ptr(1)) very low address throws", function() {
        callNative(ptr(1));
    });

    assertThrows("callNative(ptr(0xFFFF)) below 64K threshold throws", function() {
        callNative(ptr("0xFFFF"));
    });

    // callNative with unmapped address should throw
    assertThrows("callNative(unmapped addr) throws", function() {
        callNative(ptr("0xDEAD000000000000"));
    });

    // === Section 4: callNative() on libc getpid ===
    // getpid() always returns the current PID (> 0), takes no args, safe to call.
    // We need to find getpid's address. Since callNative validates via dladdr(),
    // we need a real function pointer.
    //
    // Strategy: hook getpid to discover its address, then use callNative.
    // But we need the address to hook... circular dependency.
    //
    // Alternative: the test runner can pass addresses via environment or we test
    // the pattern with comments showing expected usage.

    console.log("");
    console.log("--- Section 4: callNative() Functional Test ---");
    console.log("[INFO] callNative functional tests require known function addresses.");
    console.log("[INFO] Typical usage:");
    console.log("[INFO]   var pid = callNative(getpid_addr);");
    console.log("[INFO]   console.log('PID: ' + pid);");
    console.log("[INFO]   assert(pid > 0);");

    // === Section 5: hook/unhook lifecycle ===
    // Test the hook/unhook pattern on a real function.
    // This requires a known function address. The test demonstrates the pattern.

    console.log("");
    console.log("--- Section 5: hook/unhook Lifecycle Pattern ---");
    console.log("[INFO] Hook lifecycle tests require a known function address.");
    console.log("[INFO] Example pattern:");
    console.log("[INFO]   // Hook getpid");
    console.log("[INFO]   hook(getpid_addr, function(ctx) {");
    console.log("[INFO]     console.log('getpid called! x0=' + ctx.x0);");
    console.log("[INFO]     console.log('sp=' + ctx.sp + ' pc=' + ctx.pc);");
    console.log("[INFO]     // Modify return value: ctx.x0 = 12345n;");
    console.log("[INFO]   });");
    console.log("[INFO]   // Verify hook fires");
    console.log("[INFO]   callNative(getpid_addr);");
    console.log("[INFO]   // Remove hook");
    console.log("[INFO]   unhook(getpid_addr);");

    // === Section 6: HookContext structure validation ===
    console.log("");
    console.log("--- Section 6: HookContext Structure ---");
    console.log("[INFO] HookContext properties available in callback:");
    console.log("[INFO]   ctx.x0 - ctx.x30  (BigUint64 — ARM64 general registers)");
    console.log("[INFO]   ctx.sp             (BigUint64 — stack pointer)");
    console.log("[INFO]   ctx.pc             (BigUint64 — program counter)");
    console.log("[INFO] Register modification: set ctx.x0 = newValue (BigUint64)");
    console.log("[INFO] Common patterns:");
    console.log("[INFO]   ctx.x0 — first arg or return value");
    console.log("[INFO]   ctx.x1 — second arg");
    console.log("[INFO]   ctx.x30 — link register (return address)");

    // === Section 7: stealth mode parameter ===
    console.log("");
    console.log("--- Section 7: Stealth Mode Parameter ---");
    console.log("[INFO] hook(addr, callback, true) enables stealth/wxshadow mode");
    console.log("[INFO] Stealth mode uses WX shadow mapping for traceless hooking");

    // Verify stealth parameter is accepted (doesn't crash on parse)
    // We can't test with a real address here, but verify the API accepts 3 args
    assertThrows("hook(ptr(0), fn, true) stealth on null still throws (invalid addr)", function() {
        hook(ptr(0), function(ctx) {}, true);
    });

    assertThrows("hook(ptr(0), fn, false) non-stealth on null still throws", function() {
        hook(ptr(0), function(ctx) {}, false);
    });

    // === Summary ===
    console.log("");
    console.log("[SUMMARY] " + passed + "/" + total + " tests passed");
    if (failed > 0) {
        console.log("[SUMMARY] " + failed + " tests FAILED");
    }
})();
