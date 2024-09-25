/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;
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
        String rpt;
        if (token.startsWith(ARLAS_API_KEY)) {
            String[] key = token.split(":");
            LOGGER.debug("apiKeyId=" + key[1]);
            rpt = authService.createPermissionToken(key[1], key[2], ARLAS_API_KEY);
        } else {
            LOGGER.debug("accessToken=" + decodeToken(token));
            DecodedJWT accessToken = authService.verifyToken(token);
            rpt = authService.createPermissionToken(getSubject(accessToken), orgFilter, accessToken.getIssuer(), new Date());
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
