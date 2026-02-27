// test_ptr.js — NativePointer (ptr()) API comprehensive test
// Usage: ./rustfrida --pid <pid> -l test_ptr.js

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

    console.log("=== NativePointer (ptr) API Tests ===");
    console.log("");

    // === Section 1: ptr() Construction ===
    console.log("--- Section 1: ptr() Construction ---");

    // From integer 0
    var p0 = ptr(0);
    assert("ptr(0) is not null", p0 !== null && p0 !== undefined);
    assertEq("ptr(0).toString()", p0.toString(), "0x0");

    // From positive integer
    var p1 = ptr(255);
    assertEq("ptr(255).toString()", p1.toString(), "0xff");

    var p2 = ptr(4096);
    assertEq("ptr(4096).toString()", p2.toString(), "0x1000");

    // From large integer (within f64 safe range)
    var p3 = ptr(0x7FFFFFFF);
    assertEq("ptr(0x7FFFFFFF).toString()", p3.toString(), "0x7fffffff");

    // From hex string
    var p4 = ptr("0x12345678");
    assertEq("ptr('0x12345678').toString()", p4.toString(), "0x12345678");

    // Hex string without 0x prefix
    var p5 = ptr("ABCDEF");
    assertEq("ptr('ABCDEF').toString()", p5.toString(), "0xabcdef");

    // Hex string with 0X (uppercase prefix)
    var p6 = ptr("0XDEAD");
    assertEq("ptr('0XDEAD').toString()", p6.toString(), "0xdead");

    // Full 64-bit address
    var p7 = ptr("0x7FFFFFFFFFFF");
    assertEq("ptr('0x7FFFFFFFFFFF').toString()", p7.toString(), "0x7fffffffffff");

    // From BigInt (ARM64 addresses often exceed f64 safe integer range)
    var p8 = ptr(0x100000000n);
    assertEq("ptr(BigInt 0x100000000).toString()", p8.toString(), "0x100000000");

    var p9 = ptr(BigInt("0x7000000000"));
    assertEq("ptr(BigInt '0x7000000000').toString()", p9.toString(), "0x7000000000");

    // ptr(0) edge case
    var pZero = ptr(0);
    assertEq("ptr(0) is zero", pZero.toString(), "0x0");

    // ptr from another NativePointer (identity/copy)
    var pCopy = ptr(p4);
    assertEq("ptr(NativePointer) copies address", pCopy.toString(), "0x12345678");

    // === Section 2: ptr() Error Handling ===
    console.log("");
    console.log("--- Section 2: ptr() Error Handling ---");

    assertThrows("ptr() no args throws", function() {
        ptr();
    });

    assertThrows("ptr('not hex') throws", function() {
        ptr("ZZZZ");
    });

    assertThrows("ptr('hello world') throws", function() {
        ptr("hello world");
    });

    // === Section 3: NativePointer.add() ===
    console.log("");
    console.log("--- Section 3: NativePointer.add() ---");

    var base = ptr("0x1000");

    // add integer
    assertEq("ptr(0x1000).add(0x100)", base.add(0x100).toString(), "0x1100");

    // add zero
    assertEq("ptr(0x1000).add(0)", base.add(0).toString(), "0x1000");

    // add 1
    assertEq("ptr(0x1000).add(1)", base.add(1).toString(), "0x1001");

    // add large value
    assertEq("ptr(0x1000).add(0xFFF)", base.add(0xFFF).toString(), "0x1fff");

    // add BigInt
    assertEq("ptr(0x1000).add(BigInt)", base.add(0x200n).toString(), "0x1200");

    // add hex string
    assertEq("ptr(0x1000).add('0x300')", base.add("0x300").toString(), "0x1300");

    // add NativePointer
    var offset_ptr = ptr(0x50);
    assertEq("ptr(0x1000).add(ptr(0x50))", base.add(offset_ptr).toString(), "0x1050");

    // add that wraps around (very large address)
    var highAddr = ptr("0xFFFFFFFFFFFF0000");
    assertEq("high addr + 0x10000 wraps to 0", highAddr.add(0x10000).toString(), "0x0");

    // add error: no argument
    assertThrows("ptr.add() no args throws", function() {
        base.add();
    });

    // add error: string without 0x prefix (non-hex) should throw
    assertThrows("ptr.add('abc') plain string throws", function() {
        base.add("abc");
    });

    // === Section 4: NativePointer.sub() ===
    console.log("");
    console.log("--- Section 4: NativePointer.sub() ---");

    var subBase = ptr("0x2000");

    // sub integer
    assertEq("ptr(0x2000).sub(0x100)", subBase.sub(0x100).toString(), "0x1f00");

    // sub zero
    assertEq("ptr(0x2000).sub(0)", subBase.sub(0).toString(), "0x2000");

    // sub 1
    assertEq("ptr(0x2000).sub(1)", subBase.sub(1).toString(), "0x1fff");

    // sub BigInt
    assertEq("ptr(0x2000).sub(BigInt)", subBase.sub(0x500n).toString(), "0x1b00");

    // sub hex string
    assertEq("ptr(0x2000).sub('0x100')", subBase.sub("0x100").toString(), "0x1f00");

    // sub NativePointer
    var subOffset = ptr(0x800);
    assertEq("ptr(0x2000).sub(ptr(0x800))", subBase.sub(subOffset).toString(), "0x1800");

    // sub underflow (wraps around)
    var lowAddr = ptr("0x10");
    // 0x10 - 0x20 wraps to 0xFFFFFFFFFFFFFFFF0
    var wrapped = lowAddr.sub(0x20);
    assert("ptr(0x10).sub(0x20) wraps (underflow)", wrapped.toString() !== "0x10");

    // sub error: no argument
    assertThrows("ptr.sub() no args throws", function() {
        subBase.sub();
    });

    // === Section 5: NativePointer.toString() ===
    console.log("");
    console.log("--- Section 5: NativePointer.toString() ---");

    assertEq("ptr(0).toString() is '0x0'", ptr(0).toString(), "0x0");
    assertEq("ptr(1).toString() is '0x1'", ptr(1).toString(), "0x1");
    assertEq("ptr(16).toString() is '0x10'", ptr(16).toString(), "0x10");
    assertEq("ptr(255).toString() is '0xff'", ptr(255).toString(), "0xff");
    assertEq("ptr(0xCAFE).toString()", ptr(0xCAFE).toString(), "0xcafe");

    // Full 48-bit address (typical ARM64 user-space VA)
    assertEq("48-bit address toString", ptr("0x7F12AB340000").toString(), "0x7f12ab340000");

    // === Section 6: NativePointer.toNumber() / toInt() ===
    console.log("");
    console.log("--- Section 6: NativePointer.toNumber() / toInt() ---");

    // toNumber returns BigUint64
    var tn0 = ptr(0).toNumber();
    assertEq("ptr(0).toNumber()", tn0, 0n);

    var tn1 = ptr(42).toNumber();
    assertEq("ptr(42).toNumber()", tn1, 42n);

    // toInt is alias of toNumber
    var ti0 = ptr(100).toInt();
    assertEq("ptr(100).toInt()", ti0, 100n);

    // Large address
    var tnLarge = ptr("0x7F0000000000").toNumber();
    assertEq("ptr(0x7F0000000000).toNumber()", tnLarge, 0x7F0000000000n);

    // === Section 7: Chained Operations ===
    console.log("");
    console.log("--- Section 7: Chained Operations ---");

    // add then sub
    var chain1 = ptr("0x1000").add(0x500).sub(0x200);
    assertEq("ptr(0x1000).add(0x500).sub(0x200)", chain1.toString(), "0x1300");

    // Multiple adds
    var chain2 = ptr(0).add(0x100).add(0x200).add(0x300);
    assertEq("ptr(0).add(0x100).add(0x200).add(0x300)", chain2.toString(), "0x600");

    // add then toString then new ptr
    var str1 = ptr("0xABCD").add(0x1000).toString();
    assertEq("chained add then toString", str1, "0xbbcd");

    // === Section 8: Boundary Values ===
    console.log("");
    console.log("--- Section 8: Boundary Values ---");

    // Max ARM64 user-space VA (48-bit)
    var maxVA = ptr("0xFFFFFFFFFFFF");
    assertEq("max 48-bit VA", maxVA.toString(), "0xffffffffffff");

    // Full 64-bit max
    var max64 = ptr("0xFFFFFFFFFFFFFFFF");
    assertEq("max 64-bit", max64.toString(), "0xffffffffffffffff");

    // Page-aligned addresses
    assertEq("page-aligned 4K", ptr("0x1000").toString(), "0x1000");
    assertEq("page-aligned 2M", ptr("0x200000").toString(), "0x200000");
    assertEq("page-aligned 1G", ptr("0x40000000").toString(), "0x40000000");

    // Single byte values
    for (var i = 0; i < 16; i++) {
        var expected = "0x" + i.toString(16);
        assertEq("ptr(" + i + ").toString()", ptr(i).toString(), expected);
    }

    // === Summary ===
    console.log("");
    console.log("[SUMMARY] " + passed + "/" + total + " tests passed");
    if (failed > 0) {
        console.log("[SUMMARY] " + failed + " tests FAILED");
    }
})();
