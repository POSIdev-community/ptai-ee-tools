package com.ptsecurity.appsec.ai.ee.scan;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ScanDataPacked {
    public enum Type {
        SCAN_BRIEF_DETAILED
    }

    protected Type type;

    protected String data;
}
