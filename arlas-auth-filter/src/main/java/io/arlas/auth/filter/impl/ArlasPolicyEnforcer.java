package io.arlas.auth.filter.impl;

import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class ArlasPolicyEnforcer implements PolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(ArlasPolicyEnforcer.class);
    private ArlasAuthConfiguration authConf;
    private boolean isLocal; // whether this class is used internally or as an external service in Arlas Server

    public ArlasPolicyEnforcer() {
        this.isLocal = false;
    }

    public ArlasPolicyEnforcer(ArlasAuthConfiguration conf) {
        this.authConf = conf;
        this.isLocal = true;

    }

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        this.authConf = conf;
        return this;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        // TODO
    }
}
