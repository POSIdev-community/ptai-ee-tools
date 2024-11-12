package com.ptsecurity.appsec.ai.ee.server.integration.rest;

import com.ptsecurity.appsec.ai.ee.scan.result.ScanBrief;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.support.AnnotationSupport;

import java.util.*;

public class EnvironmentExecutionCondition implements ExecutionCondition {
    private static List<ScanBrief.ApiVersion> ALL = Arrays.asList(ScanBrief.ApiVersion.values());

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context){
        ScanBrief.ApiVersion activeEnvironment = Connection.CONNECTION().getVersion();
        if(activeEnvironment == null)
            return ConditionEvaluationResult.disabled("There is no active environment");

        Set<ScanBrief.ApiVersion> enabledEnvironments = getEnabledEnvironment(context);
        return enabledEnvironments.contains(activeEnvironment)
                ? ConditionEvaluationResult.enabled("Active environment is enabled")
                : ConditionEvaluationResult.disabled("Active environment is not enabled");
    }

    private Set<ScanBrief.ApiVersion> getEnabledEnvironment(ExtensionContext context) {
        Set<ScanBrief.ApiVersion> enabledEnvironments = new HashSet<>();
        // Check if method is annotated with Environment limitations
        Optional<Environment> environment = context.getElement()
                .flatMap(element -> AnnotationSupport.findAnnotation(element, Environment.class));
        if (environment.isPresent()) {
            Optional<ScanBrief.ApiVersion[]> enabledFor = environment.map(Environment::enabledFor);
            if (enabledFor.isPresent() && enabledFor.get().length > 0)
                // Enabled environments are defined explicitly
                enabledEnvironments.addAll(Arrays.asList(enabledFor.get()));
            else
                // No explicit definition, use all defined environments
                enabledEnvironments.addAll(ALL);
            Optional<ScanBrief.ApiVersion[]> disabledFor = environment.map(Environment::disabledFor);
            disabledFor.ifPresent(apiVersions -> Arrays.asList(apiVersions).forEach(enabledEnvironments::remove));
        } else
            // Method is not annotated, no environments restrictions
            enabledEnvironments.addAll(ALL);
        return enabledEnvironments;
    }
}