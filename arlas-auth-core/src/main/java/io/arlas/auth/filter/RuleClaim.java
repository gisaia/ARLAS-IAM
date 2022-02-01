package io.arlas.auth.filter;

// TODO: copy from ARLAS Server. To be refactored
public class RuleClaim implements Comparable {
    public String resource; // regex
    public String verbs; // comma separated list of verbs: GET,POST
    public Integer priority; // number used to sort rules (matching order)

    RuleClaim(String resource, String verbs, Integer priority) {
        this.resource = resource;
        this.verbs = verbs.toLowerCase();
        this.priority = priority;
    }

    public RuleClaim withResource(String r) {
        this.resource = r;
        return this;
    }

    public boolean match(String method, String path) {
        return this.verbs.contains(method.toLowerCase()) && path.matches(this.resource);
    }

    @Override
    public int compareTo(Object other) {
        return ((RuleClaim)other).priority - this.priority;
    }

    @Override
    public String toString() {
        return "Rule[" +
                "r='" + resource + '\'' +
                "/v='" + verbs + '\'' +
                "/p=" + priority +
                ']';
    }
}
