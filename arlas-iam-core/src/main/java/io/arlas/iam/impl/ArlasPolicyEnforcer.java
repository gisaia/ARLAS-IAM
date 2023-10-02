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
import java.util.Optional;

import static io.arlas.commons.rest.utils.ServerConstants.ARLAS_API_KEY;

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
    protected Object getObjectToken(String token, String orgFilter) throws Exception {
        String rpt = null;
        if (token.startsWith(ARLAS_API_KEY)) {
            String[] key = token.split(":");
            LOGGER.debug("apiKeyId=" + key[1]);
            rpt = authService.createPermissionToken(key[1], key[2], ARLAS_API_KEY);
        } else {
            LOGGER.debug("accessToken=" + decodeToken(token));
            DecodedJWT accessToken = authService.verifyToken(token);
            rpt = authService.createPermissionToken(getSubject(accessToken), getSubjectEmail(accessToken), orgFilter, accessToken.getIssuer(), new Date());
        }
        LOGGER.debug("RPT=" + decodeToken(rpt));
        return JWT.decode(rpt);
    }

    @Override
    protected Map<String, Object> getRolesClaim(Object token, Optional<String> org) {
        Claim jwtClaimRoles = ((DecodedJWT) token).getClaim(authConf.claimRoles);
        if (!jwtClaimRoles.isNull()) {
            return jwtClaimRoles.asMap();
        } else {
            return Collections.emptyMap();
        }
    }
}
