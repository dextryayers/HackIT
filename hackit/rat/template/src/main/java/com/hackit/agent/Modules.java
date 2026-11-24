package com.hackit.agent;

import android.content.Context;

import java.util.List;

/** Spec gate: the build only runs the modules its spec named. */
final class Modules {
    static boolean on(Context ctx, String module) {
        List<String> list = Config.get(ctx).modules;
        for (String name : list) {
            if (module.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    static String spec(Context ctx) {
        return Config.get(ctx).spec;
    }

    private Modules() {
    }
}
