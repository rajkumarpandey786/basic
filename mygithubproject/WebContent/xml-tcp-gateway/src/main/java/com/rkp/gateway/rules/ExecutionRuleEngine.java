package com.rkp.gateway.rules;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.rkp.gateway.orchestrator.AggregatedResult;

@Component
public class ExecutionRuleEngine {

    private final List<ExecutionRuleConfig.Rule> rules;

    public ExecutionRuleEngine(ExecutionRuleConfig config) {

        this.rules = new ArrayList<>(config.getRules());

        this.rules.sort(
                Comparator.comparingInt(
                        ExecutionRuleConfig.Rule::getPriority));
    }

    public AggregatedResult evaluate(
            Map<String, String> responseCodes) {

        ExecutionRuleConfig.Rule defaultRule = null;

        for (ExecutionRuleConfig.Rule rule : rules) {

            if (rule.getWhen() == null ||
                    rule.getWhen().isEmpty()) {

                defaultRule = rule;
                continue;
            }

            if (matches(rule, responseCodes)) {

                return toResult(rule.getResult());
            }
        }

        if (defaultRule != null) {

            return toResult(defaultRule.getResult());
        }

        return new AggregatedResult(
                false,
                "96",
                "SYSTEM_ERROR",
                "REJECT",
                "H096",
                "NONE");
    }

    private boolean matches(
            ExecutionRuleConfig.Rule rule,
            Map<String, String> responseCodes) {

        for (Map.Entry<String, List<String>> condition :
                rule.getWhen().entrySet()) {

            String system = condition.getKey();

            List<String> allowedCodes =
                    condition.getValue();

            String actualCode =
                    responseCodes.get(system);

            if (actualCode == null) {
                return false;
            }

            if (!allowedCodes.contains(actualCode)) {
                return false;
            }
        }

        return true;
    }

    private AggregatedResult toResult(
            ExecutionRuleConfig.RuleResult result) {

        boolean success =
                "00".equals(result.getResponseCode());

        return new AggregatedResult(
                success,
                result.getResponseCode(),
                result.getMessage(),
                result.getAction(),
                result.getHostCode(),
                result.getSettlement());
    }
}