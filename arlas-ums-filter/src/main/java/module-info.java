import io.arlas.ums.config.AuthConfiguration;
import io.arlas.ums.filter.impl.Auth0PolicyEnforcer;
import io.arlas.ums.filter.impl.HTTPPolicyEnforcer;
import io.arlas.ums.filter.impl.KeycloakPolicyEnforcer;

module arlas.ums.filter {
    exports io.arlas.ums.filter.impl;
    exports io.arlas.ums.config;

    requires transitive arlas.commons;
    provides io.arlas.commons.rest.auth.PolicyEnforcer with HTTPPolicyEnforcer, Auth0PolicyEnforcer, KeycloakPolicyEnforcer;
    provides io.arlas.commons.config.ArlasAuthConfiguration with AuthConfiguration;

    requires co.elastic.apm.api;
    requires transitive com.auth0.jwt;
    requires com.fasterxml.jackson.annotation;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.yaml;
    requires java.annotation;
    requires java.ws.rs;
    requires keycloak.authz.client;
    requires keycloak.core;
    requires org.slf4j;
}