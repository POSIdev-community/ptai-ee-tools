package com.ptsecurity.appsec.ai.ee.utils.ci.integration;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ResourceBundle;

public class LogConfigurator {
    private static ResourceBundle bundle;
    public static File logFile = null;
    private static final String logFileName = "ptsecurity-ai.log";

    static {
        try {
            bundle = ResourceBundle.getBundle("generic-client-lib");
        } catch (Exception e) {
            bundle = null;
        }
    }

    public static void redirectLogsToFile() {
        try {
            if (!isRedirectLogs()) {
                return;
            }

            final LoggerContext context = (LoggerContext) LogManager.getContext(false);
            final Configuration config = context.getConfiguration();

            String tempDir = getSystemTempPath();

            Path tempPath = Paths.get(tempDir);
            if (!Files.exists(tempPath)) {
                Files.createDirectories(tempPath);
            }

            logFile = createLogFile(tempDir);

            Appender appender = FileAppender.newBuilder()
                    .setName(logFileName)
                    .withFileName(logFile.getAbsolutePath())
                    .setLayout(createLayout(config))
                    .build();

            appender.start();

            configureLogger(config, appender);

            context.updateLoggers();
            System.out.println("Logging configured to: " + logFile.getAbsolutePath());

        } catch (Exception e) {
            System.err.println("Failed to configure logging: ");
            e.printStackTrace();
        }
    }

    public static boolean isDeleteTempLogsFile() {
        return getBooleanProperty("deleteTempLogsFile");
    }

    private static File createLogFile(String basePath) {
        try {
            Path path = Paths.get(basePath, logFileName);

            Files.createDirectories(path.getParent());
            Files.createFile(path);

            if (!Files.isRegularFile(path)) {
                throw new IOException("Path is a directory: " + path);
            }

            return path.toFile();

        } catch (Exception e) {
            System.err.println("Error creating log file in " + basePath + ": " + e.getMessage());
            return null;
        }
    }

    private static PatternLayout createLayout(Configuration config) {
        return PatternLayout.newBuilder()
                .withPattern("%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n")
                .withConfiguration(config)
                .build();
    }

    private static void configureLogger(Configuration config, Appender appender) {
        final String loggerName = "com.ptsecurity.appsec.ai.ee.utils.ci.integration";

        config.addAppender(appender);
        LoggerConfig loggerConfig = config.getLoggerConfig(loggerName);

        if (!loggerConfig.getName().equals(loggerName)) {
            loggerConfig = new LoggerConfig(loggerName, Level.DEBUG, false);
            config.addLogger(loggerName, loggerConfig);
        }

        loggerConfig.addAppender(appender, Level.DEBUG, null);
        loggerConfig.setLevel(Level.DEBUG);
    }

    private static String getSystemTempPath() {
        return System.getProperty("java.io.tmpdir");
    }

    private static boolean isRedirectLogs() {
        return getBooleanProperty("redirectLogsToFile");
    }

    private static boolean getBooleanProperty(String property) {
        if (bundle == null) {
            return false;
        }

        try {
            return Boolean.parseBoolean(
                    bundle.getString(property)
            );
        } catch (Exception e) {
            return false;
        }
    }
}
