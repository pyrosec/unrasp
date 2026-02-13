package is.pyrosec.unrasp;

import android.content.Context;
import android.content.Intent;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class UnraspModule implements IXposedHookLoadPackage {

    private static final String TAG = "UnRASP";
    private static final String TALSEC_ACTION = "TALSEC_INFO";
    private static final boolean BLOCK_INIT = false; // Nuclear option — set true if needed

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        XposedBridge.log(TAG + ": Loaded in " + lpparam.packageName);

        // Layer 1: Intent interception
        // Hook Intent.getStringExtra() — when the action is TALSEC_INFO, return empty
        // string so the switch in ThreatListener.onReceive() matches no threat case.
        XposedHelpers.findAndHookMethod(
            Intent.class,
            "getStringExtra",
            String.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    Intent intent = (Intent) param.thisObject;
                    String action = intent.getAction();
                    if (TALSEC_ACTION.equals(action)) {
                        XposedBridge.log(TAG + ": Intercepted TALSEC_INFO getStringExtra, returning empty");
                        param.setResult("");
                    }
                }
            }
        );

        // Layer 2: ThreatListener.onReceive() no-op
        // Direct hook on freeRASP's BroadcastReceiver as a backup.
        try {
            Class<?> threatListener = XposedHelpers.findClass(
                "com.aheaditec.talsec_security.security.api.ThreatListener",
                lpparam.classLoader
            );
            XposedHelpers.findAndHookMethod(
                threatListener,
                "onReceive",
                Context.class,
                Intent.class,
                XC_MethodReplacement.returnConstant(null)
            );
            XposedBridge.log(TAG + ": Hooked ThreatListener.onReceive()");
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": ThreatListener class not found (may be obfuscated): " + t.getMessage());
        }

        // Layer 3: Kill prevention
        // Prevent freeRASP's onInvalidCallback() and killOnBypass from killing the app.

        // Hook Process.killProcess() — only block self-kill (not kills of other processes)
        XposedHelpers.findAndHookMethod(
            android.os.Process.class,
            "killProcess",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    int pid = (int) param.args[0];
                    if (pid == android.os.Process.myPid()) {
                        XposedBridge.log(TAG + ": Blocked Process.killProcess(self)");
                        param.setResult(null);
                    }
                }
            }
        );

        // Hook System.exit() — block unconditionally within this app
        XposedHelpers.findAndHookMethod(
            System.class,
            "exit",
            int.class,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    XposedBridge.log(TAG + ": Blocked System.exit(" + param.args[0] + ")");
                    param.setResult(null);
                }
            }
        );

        // Layer 4: Block initialization (optional, disabled by default)
        if (BLOCK_INIT) {
            try {
                Class<?> talsec = XposedHelpers.findClass(
                    "com.aheaditec.talsec_security.security.api.Talsec",
                    lpparam.classLoader
                );
                Class<?> talsecConfig = XposedHelpers.findClass(
                    "com.aheaditec.talsec_security.security.api.TalsecConfig",
                    lpparam.classLoader
                );
                XposedHelpers.findAndHookMethod(
                    talsec,
                    "start",
                    Context.class,
                    talsecConfig,
                    XC_MethodReplacement.returnConstant(null)
                );
                XposedBridge.log(TAG + ": Hooked Talsec.start() — initialization blocked");
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": Talsec class not found: " + t.getMessage());
            }
        }

        XposedBridge.log(TAG + ": All hooks installed for " + lpparam.packageName);
    }
}
