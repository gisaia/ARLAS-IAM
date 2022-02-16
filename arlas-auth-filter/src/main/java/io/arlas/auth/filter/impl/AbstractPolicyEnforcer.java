package io.arlas.auth.filter.impl;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Transaction;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Provider
@Priority(Priorities.AUTHORIZATION)
public abstract class AbstractPolicyEnforcer implements PolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(AbstractPolicyEnforcer.class);
    protected ArlasAuthConfiguration authConf;

    protected AbstractPolicyEnforcer() {}

    protected abstract DecodedJWT getPermissionToken(String accessToken) throws Exception;
    protected String getSubject(DecodedJWT token) {
        return token.getSubject();
    }

    protected Collection<String> getRolesClaim(DecodedJWT token) {
        Claim jwtClaimRoles = token.getClaim(authConf.claimRoles);
        if (!jwtClaimRoles.isNull()) {
            return jwtClaimRoles.asList(String.class);
        } else {
            return Collections.emptyList();
        }
    }

    protected List<String> getPermissionsClaim(DecodedJWT token){
        Claim jwtClaimPermissions = token.getClaim(authConf.claimPermissions);
        if (!jwtClaimPermissions.isNull()) {
            return jwtClaimPermissions.asList(String.class);
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        Transaction transaction = ElasticApm.currentTransaction();
        boolean isPublic = ctx.getUriInfo().getPath().concat(":").concat(ctx.getMethod()).matches(authConf.getPublicRegex());
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.toLowerCase().startsWith("bearer ")) {
            if (!isPublic && !ctx.getMethod().equals("OPTIONS")) {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            return;
        }

        try {
            DecodedJWT token = getPermissionToken(header.substring(7));

            ctx.getHeaders().remove(authConf.headerUser); // remove it in case it's been set manually
            String userId = getSubject(token);
            if (userId != null && !userId.isEmpty()) {
                ctx.getHeaders().putSingle(authConf.headerUser, userId);
                LOGGER.debug("Add Header [" + authConf.headerUser +": " + userId + "]");
                transaction.setUser(userId, "", "");
            }

            ctx.getHeaders().remove(authConf.headerGroup); // remove it in case it's been set manually
            Collection<String> roles = getRolesClaim(token);
            if (roles != null && !roles.isEmpty()) {
                List<String> groups = roles.stream()
                        .filter(r -> r.toLowerCase().startsWith("group"))
                        .collect(Collectors.toList());
                ctx.setProperty("groups", groups);
                ctx.getHeaders().put(authConf.headerGroup, groups);
                LOGGER.debug("Add Header [" + authConf.headerGroup +": " + groups + "]");
            }

            List<String> permissions = getPermissionsClaim(token);
            LOGGER.debug("Permissions: " + permissions);
            if (permissions != null && !permissions.isEmpty()) {
                ArlasClaims arlasClaims = new ArlasClaims(permissions);
                ctx.setProperty("claims", arlasClaims);
                if (arlasClaims.isAllowed(ctx.getMethod(), ctx.getUriInfo().getPath())) {
                    arlasClaims.injectHeaders(ctx.getHeaders(), transaction);
                    return;
                }
            }
            if (isPublic) {
                return;
            }
        } catch (Exception e) {
            LOGGER.warn("JWT verification failed.", e);
            if (!isPublic) {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            return;
        }
        ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
}
