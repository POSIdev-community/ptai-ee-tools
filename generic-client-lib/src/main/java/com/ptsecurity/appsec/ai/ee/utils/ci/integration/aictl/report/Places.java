package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.ptsecurity.appsec.ai.ee.scan.result.issue.types.BaseSourceIssue;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class Places {
    private static final Pattern COORDINATES = Pattern.compile("(\\d+):(\\d+):(\\d+):(\\d+)\\s*$");

    private static final Pattern PATTERN_COORDINATES = Pattern.compile("\\[(\\d+),(\\d+)\\.\\.(\\d+)\\)\\s*$");

    private static final Pattern FILE_AND_LINE = Pattern.compile("^(.*?)\\s*:\\s*(\\d+)\\s*$");

    @NonNull
    public static String file(final String sourceFile) {
        if (sourceFile == null) {
            return "";
        }

        Matcher matcher = FILE_AND_LINE.matcher(sourceFile.trim());
        return matcher.matches() ? matcher.group(1).trim() : sourceFile.trim();
    }

    public static BaseSourceIssue.Place place(
            final String sourceFile,
            final String parentItem,
            final int numberLine,
            final String snippet) {
        String file = file(sourceFile);
        if (file.isEmpty()) {
            return null;
        }

        int beginLine = numberLine;
        int beginColumn = 0;
        int endLine = numberLine;
        int endColumn = 0;

        if (parentItem != null) {
            Matcher matcher = COORDINATES.matcher(parentItem);
            Matcher pattern = PATTERN_COORDINATES.matcher(parentItem);
            if (matcher.find()) {
                beginLine = Integer.parseInt(matcher.group(1));
                beginColumn = Integer.parseInt(matcher.group(2));
                endLine = Integer.parseInt(matcher.group(3));
                endColumn = Integer.parseInt(matcher.group(4));
            } else if (pattern.find()) {
                beginLine = Integer.parseInt(pattern.group(1));
                beginColumn = Integer.parseInt(pattern.group(2));
                endLine = beginLine;
                endColumn = Integer.parseInt(pattern.group(3));
            }
        }

        return BaseSourceIssue.Place.builder()
                .file(file)
                .beginLine(beginLine)
                .beginColumn(beginColumn)
                .endLine(endLine)
                .endColumn(endColumn)
                .value(snippet == null ? "" : snippet)
                .build();
    }

    public static BaseSourceIssue.Place place(
            final String sourceFile,
            final int beginLine,
            final int beginColumn,
            final int endLine,
            final int endColumn,
            final String snippet) {
        String file = file(sourceFile);
        if (file.isEmpty()) {
            return null;
        }

        return BaseSourceIssue.Place.builder()
                .file(file)
                .beginLine(beginLine)
                .beginColumn(beginColumn)
                .endLine(0 == endLine ? beginLine : endLine)
                .endColumn(endColumn)
                .value(snippet == null ? "" : snippet)
                .build();
    }

    public static BaseSourceIssue.Place entryPoint(final String entry) {
        if (entry == null || entry.trim().isEmpty()) {
            return null;
        }

        String file = file(entry);
        if (file.isEmpty()) {
            return null;
        }

        int line = 0;
        Matcher matcher = FILE_AND_LINE.matcher(entry.trim());
        if (matcher.matches()) line = Integer.parseInt(matcher.group(2));

        return BaseSourceIssue.Place.builder()
                .file(file)
                .beginLine(line)
                .beginColumn(0)
                .endLine(line)
                .endColumn(0)
                .value("")
                .build();
    }
}
