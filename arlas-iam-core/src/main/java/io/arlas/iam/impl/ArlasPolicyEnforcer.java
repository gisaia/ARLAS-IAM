package io.arlas.iam.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.cache.BaseCacheManager;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.filter.impl.AbstractPolicyEnforcer;
import io.arlas.iam.core.AuthService;
import io.dropwizard.hibernate.UnitOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ext.Provider;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

@Provider
@Priority(Priorities.AUTHORIZATION)
/*
  This is the policy enforcer to be used in Arlas Auth (this microservice)
 */
public class ArlasPolicyEnforcer extends AbstractPolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(ArlasPolicyEnforcer.class);
    private final AuthService authService;

    public ArlasPolicyEnforcer(AuthService authService, ArlasAuthConfiguration conf, BaseCacheManager cacheManager) {
        this.authConf = conf;
        this.authService = authService;
        this.cacheManager = cacheManager;
    }

    @Override
    @UnitOfWork
    protected Object getObjectToken(String token) throws Exception {
        LOGGER.debug("accessToken=" + decodeToken(token));
        DecodedJWT accessToken = authService.verifyToken(token);
        String rpt = authService.createPermissionToken(accessToken.getSubject(), accessToken.getIssuer(), new Date());
        LOGGER.debug("RPT=" + decodeToken(rpt));
        return JWT.decode(rpt);
    }

    @Override
    protected Map<String, Object> getRolesClaim(Object token) {
        Claim jwtClaimRoles = ((DecodedJWT) token).getClaim(authConf.claimRoles);
        if (!jwtClaimRoles.isNull()) {
            return jwtClaimRoles.asMap();
        } else {
            return Collections.emptyMap();
        }
    }
}
