// test_java.js — Java hooking API comprehensive test
// Usage: ./rustfrida --pid <pid> -l test_java.js
// Requires: injection into an Android app process (not native-only)
// Best target: any Activity-based app (e.g., Settings, Calculator)

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

    console.log("=== Java Hooking API Tests ===");
    console.log("");

    // === Section 1: Java.use() basics ===
    console.log("--- Section 1: Java.use() Basics ---");

    assert("Java object exists", typeof Java === "object");
    assert("Java.use is a function", typeof Java.use === "function");

    // Java.use returns a Proxy
    var Activity;
    assertNoThrow("Java.use('android.app.Activity') succeeds", function() {
        Activity = Java.use("android.app.Activity");
    });
    assert("Java.use returns an object", typeof Activity === "object");

    // Access method wrapper
    var onResumeWrapper;
    assertNoThrow("Activity.onResume is accessible", function() {
        onResumeWrapper = Activity.onResume;
    });
    assert("Method wrapper is an object", typeof onResumeWrapper === "object");

    // Method wrapper has .overload()
    assert("Method wrapper has overload()", typeof onResumeWrapper.overload === "function");

    // Method wrapper has .impl property
    var descriptor = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(onResumeWrapper), "impl"
    );
    assert("Method wrapper has impl getter", descriptor && typeof descriptor.get === "function");
    assert("Method wrapper has impl setter", descriptor && typeof descriptor.set === "function");

    // === Section 2: Java.use() for system classes ===
    console.log("");
    console.log("--- Section 2: System Class Hooking ---");

    // Hook android.util.Log.d (static method, 2 String params, returns int)
    // Signature: (Ljava/lang/String;Ljava/lang/String;)I
    var Log = Java.use("android.util.Log");
    var hookFired = false;

    assertNoThrow("Hook Log.d with overload", function() {
        Log.d.overload("(Ljava/lang/String;Ljava/lang/String;)I").impl = function(ctx) {
            hookFired = true;
            console.log("[TEST] Log.d hook fired!");
            if (ctx.args) {
                console.log("[TEST] Log.d args: tag=" + ctx.args[0] + ", msg=" + ctx.args[1]);
            }
            // Call original to let the log through
            return ctx.callOriginal();
        };
    });

    // Unhook
    assertNoThrow("Unhook Log.d", function() {
        Log.d.overload("(Ljava/lang/String;Ljava/lang/String;)I").impl = null;
    });

    // === Section 3: Hook/unhook lifecycle ===
    console.log("");
    console.log("--- Section 3: Hook/Unhook Lifecycle ---");

    // Hook a method
    var StringBuilder = Java.use("java.lang.StringBuilder");

    assertNoThrow("Hook StringBuilder.toString", function() {
        StringBuilder.toString.impl = function(ctx) {
            console.log("[TEST] StringBuilder.toString hook fired");
            return ctx.callOriginal();
        };
    });

    // Double-hook should throw (already hooked)
    assertThrows("Double-hook StringBuilder.toString throws", function() {
        StringBuilder.toString.impl = function(ctx) {
            return ctx.callOriginal();
        };
    });

    // Unhook should succeed
    assertNoThrow("Unhook StringBuilder.toString", function() {
        StringBuilder.toString.impl = null;
    });

    // Unhook again should throw (not hooked)
    assertThrows("Double-unhook StringBuilder.toString throws", function() {
        StringBuilder.toString.impl = null;
    });

    // Re-hook after unhook should succeed
    assertNoThrow("Re-hook StringBuilder.toString after unhook", function() {
        StringBuilder.toString.impl = function(ctx) {
            return ctx.callOriginal();
        };
    });

    // Clean up
    assertNoThrow("Final unhook StringBuilder.toString", function() {
        StringBuilder.toString.impl = null;
    });

    // === Section 4: Constructor ($init) hooking ===
    console.log("");
    console.log("--- Section 4: Constructor ($init) Hook ---");

    // Hook Integer constructor: Integer(int)
    // Signature: (I)V
    var Integer = Java.use("java.lang.Integer");
    assertNoThrow("Hook Integer.$init (constructor)", function() {
        Integer.$init.overload("(I)V").impl = function(ctx) {
            console.log("[TEST] Integer.<init>(int) hook fired, arg=" + ctx.args[0]);
            return ctx.callOriginal();
        };
    });

    assertNoThrow("Unhook Integer.$init", function() {
        Integer.$init.overload("(I)V").impl = null;
    });

    // === Section 5: Method overload resolution ===
    console.log("");
    console.log("--- Section 5: Method Overload Resolution ---");

    // String.valueOf has many overloads — should require .overload()
    var StringClass = Java.use("java.lang.String");

    assertThrows("String.valueOf without overload throws (ambiguous)", function() {
        StringClass.valueOf.impl = function(ctx) { return ctx.callOriginal(); };
    });

    // With explicit overload
    assertNoThrow("String.valueOf.overload('(I)...') works", function() {
        StringClass.valueOf.overload("static:(I)Ljava/lang/String;").impl = function(ctx) {
            console.log("[TEST] String.valueOf(int) hook fired, arg=" + ctx.args[0]);
            return ctx.callOriginal();
        };
    });

    assertNoThrow("Unhook String.valueOf(int)", function() {
        StringClass.valueOf.overload("static:(I)Ljava/lang/String;").impl = null;
    });

    // === Section 6: Hook callback context ===
    console.log("");
    console.log("--- Section 6: Hook Callback Context ---");

    // Verify context properties when hooking an instance method
    var contextChecked = false;
    var Object_ = Java.use("java.lang.Object");

    assertNoThrow("Hook Object.hashCode to inspect context", function() {
        Object_.hashCode.impl = function(ctx) {
            if (!contextChecked) {
                contextChecked = true;
                console.log("[TEST] Context properties:");
                console.log("[TEST]   thisObj: " + (ctx.thisObj !== undefined ? "present" : "missing"));
                console.log("[TEST]   args: " + (ctx.args !== undefined ? "present (length=" + ctx.args.length + ")" : "missing"));
                console.log("[TEST]   env: " + (ctx.env !== undefined ? "present" : "missing"));
                console.log("[TEST]   callOriginal: " + (typeof ctx.callOriginal === "function" ? "function" : typeof ctx.callOriginal));
            }
            return ctx.callOriginal();
        };
    });

    assertNoThrow("Unhook Object.hashCode", function() {
        Object_.hashCode.impl = null;
    });

    // === Section 7: Field access via thisObj proxy ===
    console.log("");
    console.log("--- Section 7: Field Access via thisObj ---");
    console.log("[INFO] Field access uses dot notation on ctx.thisObj");
    console.log("[INFO] Example: ctx.thisObj.mTitle reads mTitle field via JNI reflection");
    console.log("[INFO] Supported types: boolean, byte, char, short, int, long, float, double, String, Object");
    console.log("[INFO] Object fields are recursively wrapped as Proxy objects");

    // === Section 8: Error handling ===
    console.log("");
    console.log("--- Section 8: Error Handling ---");

    // Non-existent class
    var FakeClass = Java.use("com.nonexistent.FakeClass12345");
    assertThrows("Hook method on non-existent class throws", function() {
        FakeClass.fakeMethod.impl = function(ctx) {};
    });

    // Non-existent method on real class
    assertThrows("Hook non-existent method throws", function() {
        var Act = Java.use("android.app.Activity");
        Act.thisMethodDoesNotExist12345.impl = function(ctx) {};
    });

    // Wrong overload signature
    assertThrows("Hook with wrong signature throws", function() {
        var Act = Java.use("android.app.Activity");
        Act.onCreate.overload("(ZZZZ)V").impl = function(ctx) {};
    });

    // === Section 9: Static method hooking ===
    console.log("");
    console.log("--- Section 9: Static Method Hooking ---");

    // System.currentTimeMillis() — static, no params, returns long
    var System = Java.use("java.lang.System");
    assertNoThrow("Hook System.currentTimeMillis", function() {
        System.currentTimeMillis.impl = function(ctx) {
            console.log("[TEST] System.currentTimeMillis hook fired");
            var result = ctx.callOriginal();
            console.log("[TEST] Original returned: " + result);
            return result;
        };
    });

    assertNoThrow("Unhook System.currentTimeMillis", function() {
        System.currentTimeMillis.impl = null;
    });

    // === Section 10: Rapid hook/unhook cycles ===
    console.log("");
    console.log("--- Section 10: Rapid Hook/Unhook Cycles ---");

    var cycleErrors = 0;
    var cycleCount = 5;
    for (var i = 0; i < cycleCount; i++) {
        try {
            Object_.hashCode.impl = function(ctx) { return ctx.callOriginal(); };
            Object_.hashCode.impl = null;
        } catch (e) {
            cycleErrors++;
            console.log("[TEST] Cycle " + i + " error: " + e.message);
        }
    }
    assertEq("Rapid hook/unhook " + cycleCount + " cycles, errors", cycleErrors, 0);

    // === Summary ===
    console.log("");
    console.log("[SUMMARY] " + passed + "/" + total + " tests passed");
    if (failed > 0) {
        console.log("[SUMMARY] " + failed + " tests FAILED");
    }
})();
