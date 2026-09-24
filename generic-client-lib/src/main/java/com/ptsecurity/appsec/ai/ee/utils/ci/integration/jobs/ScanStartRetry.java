package com.ptsecurity.appsec.ai.ee.utils.ci.integration.jobs;

import com.ptsecurity.appsec.ai.ee.utils.ci.integration.Resources;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.AictlResult;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

@RequiredArgsConstructor
public class ScanStartRetry {
    public interface Attempt<T> {
        T run() throws GenericException;
    }

    public interface Sleeper {
        void sleep(int seconds) throws InterruptedException;
    }

    private final boolean enabled;

    private final int retryTime;

    private final int interval;

    @NonNull
    private final Consumer<String> log;

    @NonNull
    private final LongSupplier clock;

    @NonNull
    private final Sleeper sleeper;

    public ScanStartRetry(final boolean enabled, final int retryTime, @NonNull final Consumer<String> log) {
        this(enabled, retryTime, GenericAstJob.RETRY_INTERVAL_SECONDS, log,
                System::currentTimeMillis, TimeUnit.SECONDS::sleep);
    }

    public static final int MAX_RETRY_TIME_LENGTH = String.valueOf(Integer.MAX_VALUE).length() - 1;

    public static final int MAX_RETRY_TIME_SECONDS = (int) Math.pow(10, MAX_RETRY_TIME_LENGTH) - 1;

    public static Integer parseRetryTime(final String value) {
        try {
            int retryTime = Integer.parseInt(StringUtils.trimToEmpty(value));
            return validRetryTime(retryTime) ? retryTime : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static boolean validRetryTime(final int retryTime) {
        return retryTime >= GenericAstJob.RETRY_INTERVAL_SECONDS && retryTime <= MAX_RETRY_TIME_SECONDS;
    }

    @NonNull
    public static String invalidRetryTimeMessage() {
        return Resources.i18n_ast_settings_retryTime_message_invalid(String.valueOf(GenericAstJob.RETRY_INTERVAL_SECONDS));
    }

    public <T> T run(@NonNull final Attempt<T> attempt) throws GenericException {
        long deadline = clock.getAsLong() + TimeUnit.SECONDS.toMillis(retryTime);
        GenericException failure;
        do {
            try {
                return attempt.run();
            } catch (GenericException e) {
                failure = e;
            }
        } while (retryAfter(failure, deadline));

        throw failure;
    }

    private boolean retryAfter(@NonNull final GenericException failure, final long deadline) throws GenericException {
        if (!enabled || !retryable(failure)) {
            return false;
        }

        if (clock.getAsLong() >= deadline) {
            log.accept(String.format("Scan start did not succeed within %d seconds", retryTime));
            return false;
        }

        log.accept(String.format("Scan start attempt failed: %s", failure.getDetailedMessage()));
        pause();
        return true;
    }

    private void pause() throws GenericException {
        try {
            sleeper.sleep(interval);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw GenericException.raise("Scan start retry interrupted", e);
        }
    }

    static boolean retryable(@NonNull final Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof AictlException) {
                return AictlResult.ExitCode.VALIDATION != ((AictlException) cause).getKind();
            }
        }

        return false;
    }
}
