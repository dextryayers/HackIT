package com.hackit.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Alarm tick: re-arm, then nudge the beacon back to life. */
public class AlarmReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Scheduler.arm(context);
        BeaconService.poke(context);
    }
}
