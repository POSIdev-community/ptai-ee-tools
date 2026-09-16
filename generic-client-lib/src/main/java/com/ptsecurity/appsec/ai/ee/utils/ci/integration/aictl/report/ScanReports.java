package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl.report;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ScanReports {
    @NonNull
    private final AieJsonReport english;

    private final AieJsonReport russian;

    @NonNull
    public ScanResult convert(@NonNull final ScanBrief scanBrief) throws GenericException {
        return ScanResultConverter.convert(scanBrief, english, russian);
    }

    public interface Supplier {
        @NonNull
        ScanReports get() throws GenericException;
    }
}
