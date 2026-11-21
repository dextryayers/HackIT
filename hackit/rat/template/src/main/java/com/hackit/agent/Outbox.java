package com.hackit.agent;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.ConcurrentLinkedQueue;

/** Bounded queues for results and events; oldest wins when the link is down. */
final class Outbox {
    private static final int EVENT_CAP = 2000;
    private static final int RESULT_CAP = 256;
    private static final ConcurrentLinkedQueue<JSONObject> EVENTS = new ConcurrentLinkedQueue<JSONObject>();
    private static final ConcurrentLinkedQueue<JSONObject> RESULTS = new ConcurrentLinkedQueue<JSONObject>();

    static void event(String kind, Object data) {
        JSONObject item = new JSONObject();
        try {
            item.put("kind", kind);
            item.put("data", data);
        } catch (Exception ignored) {
            return;
        }
        EVENTS.add(item);
        while (EVENTS.size() > EVENT_CAP) {
            EVENTS.poll();
        }
    }

    static void result(int id, int code, Object out) {
        JSONObject item = new JSONObject();
        try {
            item.put("id", id);
            item.put("code", code);
            item.put("out", out == null ? "" : out);
        } catch (Exception ignored) {
            return;
        }
        RESULTS.add(item);
        while (RESULTS.size() > RESULT_CAP) {
            RESULTS.poll();
        }
    }

    static JSONArray drainEvents(int limit) {
        JSONArray array = new JSONArray();
        JSONObject item;
        while (array.length() < limit && (item = EVENTS.poll()) != null) {
            array.put(item);
        }
        return array;
    }

    static JSONArray drainResults(int limit) {
        JSONArray array = new JSONArray();
        JSONObject item;
        while (array.length() < limit && (item = RESULTS.poll()) != null) {
            array.put(item);
        }
        return array;
    }
}
