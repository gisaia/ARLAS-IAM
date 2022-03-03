package io.arlas.ums.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.ums.core.AuthService;
import io.arlas.ums.filter.impl.HTTPPolicyEnforcer;
import io.dropwizard.hibernate.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ext.Provider;
import java.util.Date;

@Provider
@Priority(Priorities.AUTHORIZATION)
/**
 * This is the policy enforcer to be used in Arlas Auth (this microservice)
 */
public class ArlasPolicyEnforcer extends HTTPPolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(ArlasPolicyEnforcer.class);
    private final AuthService authService;

    public ArlasPolicyEnforcer(AuthService authService, ArlasAuthConfiguration conf) {
        super(conf);
        this.authService = authService;
    }

    @Override
    @UnitOfWork
    protected DecodedJWT getPermissionToken(String token) throws Exception {
        DecodedJWT accessToken = authService.verifyToken(token);
        return JWT.decode(authService.createPermissionToken(accessToken.getSubject(), accessToken.getIssuer(), new Date()));
    }
}
