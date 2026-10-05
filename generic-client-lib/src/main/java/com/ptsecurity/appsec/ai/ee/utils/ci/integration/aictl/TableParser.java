package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import lombok.NonNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class TableParser {
    @NonNull
    public static List<String[]> rows(final String output) {
        if (output == null || output.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<String[]> result = new ArrayList<>();
        String[] lines = output.split("\\R");
        for (String line : lines) {
            if (line.trim().isEmpty()) continue;
            String[] cells = line.split("\t");
            for (int j = 0; j < cells.length; j++) {
                cells[j] = cells[j].trim();
            }

            if (result.isEmpty() && isHeader(cells)) {
                result.add(null);
                continue;
            }

            result.add(cells);
        }

        if (!result.isEmpty() && result.get(0) == null) {
            result.remove(0);
        }

        return result;
    }

    private static boolean isHeader(@NonNull final String[] cells) {
        return Arrays.stream(cells)
                .filter(cell -> !cell.isEmpty())
                .allMatch(cell -> cell.equals(cell.toUpperCase()) && !cell.matches(".*\\d.*"));
    }

    @NonNull
    public static String cell(@NonNull final String[] cells, final int index) {
        return cells.length > index ? cells[index] : "";
    }
}
