import io.arlas.auth.filter.impl.ArlasPolicyEnforcer;

module arlas.auth.filter {
    exports io.arlas.auth.filter.impl;

    requires transitive arlas.commons;
    provides io.arlas.commons.rest.auth.PolicyEnforcer with ArlasPolicyEnforcer;

    requires java.annotation;
    requires org.slf4j;
}