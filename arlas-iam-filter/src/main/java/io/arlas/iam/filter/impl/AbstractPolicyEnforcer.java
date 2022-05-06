package io.arlas.iam.filter.impl;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Transaction;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import io.arlas.iam.config.AuthConfiguration;
import io.arlas.iam.config.TechnicalRoles;
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
import java.util.Set;
import java.util.stream.Collectors;

@Provider
@Priority(Priorities.AUTHORIZATION)
public abstract class AbstractPolicyEnforcer implements PolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(AbstractPolicyEnforcer.class);
    protected AuthConfiguration authConf;
    protected boolean injectPermissions = true;

    protected AbstractPolicyEnforcer() {}

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        this.authConf = (AuthConfiguration) conf;
        return this;
    }

    protected abstract Object getObjectToken(String accessToken) throws Exception;

    protected String getSubject(Object token) {
        return ((DecodedJWT)token).getSubject();
    }

    protected Collection<String> getRolesClaim(Object token) {
        Claim jwtClaimRoles = ((DecodedJWT)token).getClaim(authConf.claimRoles);
        if (!jwtClaimRoles.isNull()) {
            return jwtClaimRoles.asList(String.class);
        } else {
            return Collections.emptyList();
        }

    }

    protected List<String> getPermissionsClaim(Object token){
        Claim jwtClaimPermissions = ((DecodedJWT)token).getClaim(authConf.claimPermissions);
        if (!jwtClaimPermissions.isNull()) {
            return jwtClaimPermissions.asList(String.class);
        } else {
            return Collections.emptyList();
        }
    }

    private void addTechnicalRolesToPermissions(List<String> permissions, Collection<String> roles) {
        if (injectPermissions) {
            LOGGER.debug("Adding permissions of roles " + roles.toString() + " from map technical roles " + TechnicalRoles.getTechnicalRolesPermissions().toString());
            TechnicalRoles.getTechnicalRolesPermissions().entrySet().stream()
                    .filter(e -> roles.contains(e.getKey()))
                    .forEach(e -> permissions.addAll(e.getValue()));
        }
    }
    @Override
    public void filter(ContainerRequestContext ctx) {
        Transaction transaction = ElasticApm.currentTransaction();
        boolean isPublic = ctx.getUriInfo().getPath().concat(":").concat(ctx.getMethod()).matches(authConf.getPublicRegex());
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.toLowerCase().startsWith("bearer ")) {
            if (!isPublic && !"OPTIONS".equals(ctx.getMethod())) {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            return;
        }

        try {
            Object token = getObjectToken(header.substring(7));
            ctx.getHeaders().remove(authConf.headerUser); // remove it in case it's been set manually
            String userId = getSubject(token);
            if (userId != null && !userId.isEmpty()) {
                ctx.getHeaders().putSingle(authConf.headerUser, userId);
                LOGGER.debug("Add Header [" + authConf.headerUser +": " + userId + "]");
                transaction.setUser(userId, "", "");
            }

            ctx.getHeaders().remove(authConf.headerGroup); // remove it in case it's been set manually
            Collection<String> roles = getRolesClaim(token);
            if (!roles.isEmpty()) {
                Set<String> groups = roles.stream()
                        .filter(r -> r.toLowerCase().startsWith("group"))
                        .collect(Collectors.toSet());
                ctx.setProperty("groups", groups.stream().toList());
                ctx.getHeaders().put(authConf.headerGroup, groups.stream().toList());
                LOGGER.debug("Add Header [" + authConf.headerGroup +": " + groups + "]");
            }

            List<String> permissions = getPermissionsClaim(token);
            addTechnicalRolesToPermissions(permissions, roles);
            LOGGER.debug("Permissions: " + permissions.toString());
            if (!permissions.isEmpty()) {
                ArlasClaims arlasClaims = new ArlasClaims(permissions);
                ctx.setProperty("claims", arlasClaims.getRules());
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
