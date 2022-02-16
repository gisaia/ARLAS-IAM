import io.arlas.auth.filter.impl.HTTPPolicyEnforcer;
import io.arlas.auth.filter.impl.Auth0PolicyEnforcer;

module arlas.auth.filter {
    exports io.arlas.auth.filter.impl;

    requires transitive arlas.commons;
    provides io.arlas.commons.rest.auth.PolicyEnforcer with HTTPPolicyEnforcer, Auth0PolicyEnforcer;

    requires co.elastic.apm.api;
    requires com.auth0.jwt;
    requires java.annotation;
    requires java.ws.rs;
    requires org.slf4j;
}