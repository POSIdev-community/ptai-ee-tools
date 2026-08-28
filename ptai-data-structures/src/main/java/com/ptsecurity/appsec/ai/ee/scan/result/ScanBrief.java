package com.ptsecurity.appsec.ai.ee.scan.result;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import com.ptsecurity.appsec.ai.ee.scan.settings.Policy;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.*;

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
        @Deprecated V36("3.6"),
        @Deprecated V40("4.0"),
        @Deprecated V41("4.1.0"),
        V411("4.1.1"),
        V420("4.2.0"),
        V430("4.3.0"),
        V44X("4.4"),
        V450("4.5.0"),
        V460("4.6.0"),
        V470("4.7.0"),
        V471("4.7.1"),
        V472("4.7.2"),
        V480("4.8.0"),
        V481("4.8.1"),
        V490("4.9.0"),
        V491("4.9.1"),
        V4100("4.10.0"),
        V4110("4.11.0"),
        V500("5.0.0"),
        V520("5.2.0"),
        V530("5.3.0"),
        V600("6.0.0"),
        V610("6.1.0"),
        V620("6.2.0");

        private final String prefix;

        ApiVersion(String prefix) {
            this.prefix = prefix;
        }

        @SneakyThrows
        public static boolean isDeprecated(@NonNull final ApiVersion version) {
            return null != ApiVersion.class.getField(version.name()).getAnnotation(Deprecated.class);
        }

        public boolean isDeprecated() {
            return isDeprecated(this);
        }

        public static ApiVersion fromString(String version) {
            return Arrays.stream(values())
                    .filter(v -> version.startsWith(v.prefix))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("Unknown version: " + version));
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
    protected String branchId;

    @Getter
    @Setter
    @JsonProperty
    protected String scanLabel;

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

        @JsonProperty
        protected String branchName;

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
            SOLIDITY("Solidity"),
            SCALA("Scala"),
            ONE_C("OneC"),
            DART("Dart");

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
