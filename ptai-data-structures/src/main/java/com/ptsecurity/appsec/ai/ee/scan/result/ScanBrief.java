package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Class that stores top-level information about completed AST job. That
 * information includes AST settings, policy assessment result and very
 * short statistic about scan duration, number of scanned / skipped
 * files / urls etc. This class have two descendants: ScanBriefDetailed
 * and even more detailed ScanResult
 */
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class ScanBrief {
    public enum ApiVersion {
        @Deprecated V36,
        @Deprecated V40,
        @Deprecated V41,
        V411, V420, V430, V44X, V450, V460, V470, V471, V472, V480, V481;

        @SneakyThrows
        public static boolean isDeprecated(@NonNull final ApiVersion version) {
            return null != ApiVersion.class.getField(version.name()).getAnnotation(Deprecated.class);
        }

        public boolean isDeprecated() {
            return isDeprecated(this);
        }
    }

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    @Builder.Default
    protected ApiVersion apiVersion = ApiVersion.V411;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiServerUrl;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiServerVersion;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String ptaiAgentVersion;

    @Getter
    @Setter
    @JsonProperty
    protected String ptaiAgentName;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected UUID id;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected UUID projectId;

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected String projectName;

    @Getter
    @Setter
    @JsonProperty
    @Builder.Default
    protected Boolean useAsyncScan = false;

    @Getter
    @Setter
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanSettings {
        @NonNull
        @JsonProperty
        protected UUID id;

        public enum Engine {
            AI, PM, TAINT, STATICCODEANALYSIS, DC, FINGERPRINT, CONFIGURATION, BLACKBOX
        }

        @Builder.Default
        @JsonProperty
        protected final Set<Engine> engines = new HashSet<>();

        @JsonProperty
        protected Boolean unpackUserPackages;

        @JsonProperty
        protected Boolean downloadDependencies;

        @JsonProperty
        protected Boolean usePublicAnalysisMethod;

        @JsonProperty
        protected Boolean useEntryAnalysisPoint;

        @RequiredArgsConstructor
        public enum Language {
            PHP("PHP"),
            JAVA("Java"),
            CSHARPWINONLY("CSharpWinOnly"),
            CSHARP("CSharp"),
            VB("VB"),
            JAVASCRIPT("JavaScript"),
            GO("Go"),
            CPP("CPlusPlus"),
            PYTHON("Python"),
            SQL("SQL"),
            OBJECTIVEC("ObjectiveC"),
            SWIFT("Swift"),
            KOTLIN("Kotlin"),
            RUBY("Ruby"),
            SOLIDITY("Solidity");

            public static Language fromString(@NonNull final String value) {
                for (Language language : Language.values())
                    if (language.value.equalsIgnoreCase(value)) return language;
                throw new IllegalArgumentException("No enum value " + Language.class.getCanonicalName() + "." + value);
            }

            @NonNull
            @Getter
            @JsonValue
            private final String value;
        }

        @JsonProperty
        protected Language language;

        @JsonProperty
        protected List<Language> languages;

        @JsonProperty
        protected String url;

        @JsonProperty
        protected Boolean autocheckAfterScan;

        @JsonProperty
        protected String customParameters;

        @JsonProperty
        protected String javaParameters;
    }

    @NonNull
    @Getter
    @Setter
    @JsonProperty
    protected ScanSettings scanSettings;

    @Getter
    @Setter
    @NonNull
    @Builder.Default
    @JsonProperty
    protected Policy.State policyState = Policy.State.NONE;

    @Getter
    @Setter
    @SuperBuilder
    @NoArgsConstructor
    @AllArgsConstructor
    @ToString
    public static class Statistics {
        /**
         * Scan execution date / time. Can't use Java 8 ZonedDateTime, Instant etc. as Jenkins
         * complaints "Refusing to marshal java.time.Instant for security reasons;
         * see https://jenkins.io/redirect/class-filter/"
         */
        @NonNull
        @JsonProperty
        protected String scanDateIso8601;

        @NonNull
        @JsonProperty
        protected String scanDurationIso8601;

        protected int totalFileCount;
        protected int totalUrlCount;
        protected int scannedFileCount;
        protected int scannedUrlCount;
    }

    @Getter
    @Setter
    protected Statistics statistics;

    public enum State {
        UNKNOWN, DONE, FAILED, ABORTED, ABORTED_FROM_CI
    }

    @Getter
    @Setter
    @NonNull
    @Builder.Default
    protected ScanBrief.State state = ScanBrief.State.UNKNOWN;
}