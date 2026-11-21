package com.hackit.agent;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/** Bounded shell exec: 30 s wall clock, 512 KB captured, stderr merged. */
final class Shell {
    private static final int TIMEOUT_MS = 30000;
    private static final int OUTPUT_CAP = 512 * 1024;

    static String run(String command) {
        Process process = null;
        try {
            List<String> argv = new ArrayList<String>();
            argv.add("/system/bin/sh");
            argv.add("-c");
            argv.add(command);
            ProcessBuilder builder = new ProcessBuilder(argv);
            builder.redirectErrorStream(true);
            process = builder.start();
            OutputStream stdin = process.getOutputStream();
            stdin.write('\n');
            stdin.flush();
            stdin.close();

            final InputStream stream = process.getInputStream();
            final ByteArrayOutputStream captured = new ByteArrayOutputStream(8192);
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    byte[] buffer = new byte[8192];
                    try {
                        int read;
                        while ((read = stream.read(buffer)) > 0) {
                            synchronized (captured) {
                                int room = OUTPUT_CAP - captured.size();
                                if (room > 0) {
                                    captured.write(buffer, 0, Math.min(read, room));
                                }
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }, "shell-reader");
            reader.setDaemon(true);
            reader.start();

            // Process.waitFor(long, TimeUnit) is API 26; a watchdog covers 21-25.
            final Process target = process;
            final boolean[] timedOut = {false};
            Thread watchdog = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(TIMEOUT_MS);
                        timedOut[0] = true;
                        target.destroy();
                    } catch (InterruptedException ignored) {
                    }
                }
            }, "shell-watchdog");
            watchdog.setDaemon(true);
            watchdog.start();

            int code;
            try {
                code = process.waitFor();
            } finally {
                watchdog.interrupt();
            }
            try {
                reader.join(2000L);
            } catch (InterruptedException exc) {
                Thread.currentThread().interrupt();
            }
            synchronized (captured) {
                String text = captured.toString("UTF-8");
                if (timedOut[0]) {
                    return "$ " + command + "\n" + text + "\n[timeout]";
                }
                return "$ " + command + "\n" + text + "\n[exit " + code + "]";
            }
        } catch (Throwable exc) {
            Log.e("shell: " + exc);
            return "shell error: " + exc;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private Shell() {
    }
}
