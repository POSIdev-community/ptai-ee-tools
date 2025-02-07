package com.ptsecurity.appsec.ai.ee.scan.result.issue.types;

import com.fasterxml.jackson.annotation.*;
import com.ptsecurity.appsec.ai.ee.scan.result.ScanResult;
import com.ptsecurity.misc.tools.helpers.HashHelper;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Common base parent class for all issues. As it is base it does
 * contain only fields that are not specific
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "class")
@JsonSubTypes({
        @JsonSubTypes.Type(value = BlackBoxIssue.class, name = "BLACKBOX"),
        @JsonSubTypes.Type(value = ConfigurationIssue.class, name = "CONFIGURATION"),
        @JsonSubTypes.Type(value = FingerprintIssue.class, name = "FINGERPRINT"),
        @JsonSubTypes.Type(value = UnknownIssue.class, name = "UNKNOWN"),
        @JsonSubTypes.Type(value = VulnerabilityIssue.class, name = "VULNERABILITY"),
        @JsonSubTypes.Type(value = WeaknessIssue.class, name = "WEAKNESS"),
        @JsonSubTypes.Type(value = YaraMatchIssue.class, name = "YARAMATCH"),
        @JsonSubTypes.Type(value = PygrepIssue.class, name = "PYGREP"),
        @JsonSubTypes.Type(value = ScaIssue.class, name = "SCA"),
        @JsonSubTypes.Type(value = FingerprintScaIssue.class, name = "FINGERPRINT_SCA")
})
public abstract class BaseIssue {
    public static Map<Class<? extends BaseIssue>, Type> TYPES = new HashMap<>();

    static {
        TYPES.put(UnknownIssue.class, Type.UNKNOWN);
        TYPES.put(BlackBoxIssue.class, Type.BLACKBOX);
        TYPES.put(ConfigurationIssue.class, Type.CONFIGURATION);
        TYPES.put(FingerprintIssue.class, Type.FINGERPRINT);
        TYPES.put(WeaknessIssue.class, Type.WEAKNESS);
        TYPES.put(VulnerabilityIssue.class, Type.VULNERABILITY);
        TYPES.put(YaraMatchIssue.class, Type.YARAMATCH);
        TYPES.put(PygrepIssue.class, Type.PYGREP);
        TYPES.put(ScaIssue.class, Type.SCA);
        TYPES.put(FingerprintScaIssue.class, Type.FINGERPRINT_SCA);
    }

    /**
     * Unique issue identifier
     */
    @JsonProperty("id")
    protected String id;

    /**
     * Issue group identifier. Null if issue doesn't belong to group
     */
    @JsonProperty("groupId")
    protected String groupId;

    /**
     * Unique issue type identifier
     */
    @JsonProperty("typeId")
    protected String typeId;

    public enum Type {
        VULNERABILITY, WEAKNESS, FINGERPRINT, CONFIGURATION, BLACKBOX, YARAMATCH, PYGREP, SCA, FINGERPRINT_SCA, UNKNOWN
    }

    public static String getIssueTypeKey(@NonNull final BaseIssue issue) {
        return HashHelper.md5(issue.getClazz().name() + "::" + issue.getTypeId());
    }

    @Builder.Default
    private transient String issueTypeKey = null;

    @JsonProperty("issueTypeKey")
    public String getIssueTypeKey() {
        if (null == issueTypeKey) issueTypeKey = getIssueTypeKey(this);
        // return getIssueTypeKey(this);
        return issueTypeKey;
    }

    /**
     * Issue type: vulnerability, weakness, SCA, DAST etc.
     */
    @JsonIgnore
    public Type getClazz() {
        return TYPES.get(getClass());
    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public enum Level {
        NONE(0),
        POTENTIAL(1),
        LOW(2),
        MEDIUM(3),
        HIGH(4);

        @Getter
        private final int value;
    }

    /**
     * Issue severity level
     */
    @JsonProperty("level")
    protected Level level;

    /**
     * True if issue marked as favorite in UI
     */
    @JsonProperty("isFavorite")
    protected Boolean favorite;

    /**
     * True if issue is a suspected vulnerability i.e. PT AI not
     * sure if it can be exploited
     */
    @JsonProperty("isSuspected")
    protected Boolean suspected;

    @JsonProperty("language")
    protected ScanResult.ScanSettings.Language language;

    /**
     * True if issue marked with suppress comment in source code
     */
    @JsonProperty("isSuppressed")
    protected Boolean suppressed;

    /**
     * Issue approval state. This state persisted between scans: if vulnerability
     * was marked as approved after last scan but developer haven't fixed it then
     * approval state will be automatically assigned to issue in a new scan results
     */
    public enum ApprovalState {
        /**
         * No approval state defined
         */
        NONE,
        /**
         * Issue approved
         */
        APPROVAL,
        /**
         * Issue declined
         */
        DISCARD,
        NOT_EXIST,
        /**
         * Issue approved during auto-check stage
         */
        AUTO_APPROVAL
    }

    /**
     * Issue approval state @see IssueApprovalState
     */
    @JsonProperty("approvalState")
    protected ApprovalState approvalState;

    @JsonProperty("isNew")
    protected Boolean isNew;

    /**
     * Unique vulnerability type identifier in the CWE classifier
     */
    @JsonProperty("cweId")
    protected List<String> cweId;
}
