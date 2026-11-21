package com.hackit.agent;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Bounded shell exec: 30 s wall clock, 512 KB captured, stderr merged. */
final class Shell {
    private static final int TIMEOUT_S = 30;
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
            final Object done = new Object();
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
                    } finally {
                        synchronized (done) {
                            done.notifyAll();
                        }
                    }
                }
            }, "shell-reader");
            reader.start();

            boolean finished = process.waitFor(TIMEOUT_S, TimeUnit.SECONDS);
            if (!finished) {
                process.destroy();
                synchronized (captured) {
                    captured.write("\n[timeout]".getBytes());
                }
            }
            try {
                reader.join(2000L);
            } catch (InterruptedException exc) {
                Thread.currentThread().interrupt();
            }
            synchronized (captured) {
                String text = captured.toString("UTF-8");
                if (!finished) {
                    return text;
                }
                int code = process.exitValue();
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
