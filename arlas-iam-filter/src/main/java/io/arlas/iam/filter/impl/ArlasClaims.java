package io.arlas.iam.filter.impl;

import co.elastic.apm.api.Transaction;
import io.arlas.commons.rest.auth.RuleClaim;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MultivaluedMap;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ArlasClaims {
    private final static Logger LOGGER = LoggerFactory.getLogger(ArlasClaims.class);
    private final List<RuleClaim> rules;
    private final Map<String, List<String>> headers;
    private final Map<String, String> variables;

    public ArlasClaims(List<String> claims) {
        this.rules = new ArrayList<>();
        this.headers = new HashMap<>();
        this.variables = new HashMap<>();

        for (String claim : claims) {
            // a claim is either "rule:resource:verbs:priority" or "header:name:value" or "var:name:value"
            // value can contain ":" so we split up to 3 elements
            String[] splitClaim = claim.split(":", 3);
            if (splitClaim.length == 3) {
                switch (splitClaim[0].toLowerCase().trim()) {
                    case "r", "rule" -> {
                        String[] remains = splitClaim[2].split(":");
                        if (remains.length == 2) {
                            rules.add(new RuleClaim(splitClaim[1], remains[0], Integer.valueOf(remains[1].trim())));
                        } else {
                            rules.add(new RuleClaim(splitClaim[1], remains[0], 1));
                        }
                    }
                    case "h", "header" -> {
                        List<String> v = headers.get(splitClaim[1]);
                        if (v == null) {
                            v = new ArrayList<>();
                        }
                        v.add(splitClaim[2]);
                        headers.put(splitClaim[1], v);
                    }
                    case "v", "var", "variable" -> variables.put(splitClaim[1], splitClaim[2]);
                    default -> LOGGER.warn("Unknown claim format: " + claim);
                }
            } else {
                LOGGER.warn("Skipping invalid claim format: " + claim);
            }
        }

        Collections.sort(rules);
        variables.forEach(this::injectVariable);
    }

    public boolean isAllowed(String method, String path) {
        for (RuleClaim rule : rules) {
            if (rule.match(method, path)) {
                LOGGER.debug("Matching rule '" + rule +"' for path '" + path + "' with method " + method);
                return true; // stop at first matching rule
            }
            LOGGER.debug("NON Matching rule '" + rule +"' for path '" + path + "' with method " + method);
        }
        return false;
    }

    public void injectHeaders(MultivaluedMap<String, String> requestHeaders, Transaction transaction) {
        headers.forEach((k,v) -> {
            String value = String.join(",", v);
            LOGGER.debug("Injecting header '" + k +"' with value '" + value + "'");
            requestHeaders.add(k, value);
            transaction.setLabel(k, value);
        });
    }

    private void injectVariable(String var, String val) {
        rules.replaceAll(rc -> rc.withResource(replaceVar(rc.resource, var, Matcher.quoteReplacement(Pattern.quote(val)))));
        headers.replaceAll((header, value) -> {
            value.replaceAll(hv -> replaceVar(hv, var, val));
            return value;
        });
    }

    public static String replaceVar(String original, String var, String val) {
        String result = original.replaceAll("\\$\\{" + var + "}", val);
        LOGGER.debug("Injecting variable '" + var + "' in  '" + original +"' results in '" + result + "'");
        return result;
    }

    public List<RuleClaim> getRules() {
        return rules;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public Map<String, String> getVariables() {
        return variables;
    }

    public static String getHeaderColumnFilterDefault(String org) {
        return String.format("h:column-filter:%s_*:*", org);
    }
}
