package com.ptsecurity.misc.tools;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;

@Slf4j
public class BaseTest {
    @BeforeEach
    public void pre(@NonNull final TestInfo testInfo) {
        log.info("Test started: {}", testInfo.getDisplayName());
    }
}
