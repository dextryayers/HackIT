package com.hackit.agent;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.Build;

/** Periodic job keeps the process warm on ROMs that defer alarms. */
public class BeaconJob extends JobService {
    @Override
    public boolean onStartJob(JobParameters params) {
        if (Build.VERSION.SDK_INT >= 21) {
            BeaconService.start(this);
        }
        jobFinished(params, false);
        return false;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true;
    }
}
