package io.arlas.iam.filter.impl;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Transaction;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.cache.BaseCacheManager;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import io.arlas.commons.utils.StringUtil;
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
import java.util.*;
import java.util.stream.Collectors;

@Provider
@Priority(Priorities.AUTHORIZATION)
public abstract class AbstractPolicyEnforcer implements PolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(AbstractPolicyEnforcer.class);
    protected AuthConfiguration authConf;
    protected BaseCacheManager cacheManager;
    protected boolean injectPermissions = true;

    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    protected AbstractPolicyEnforcer() {
    }

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        this.authConf = (AuthConfiguration) conf;
        return this;
    }

    @Override
    public PolicyEnforcer setCacheManager(BaseCacheManager baseCacheManager) {
        this.cacheManager = baseCacheManager;
        return this;
    }

    protected abstract Object getObjectToken(String accessToken) throws Exception;

    protected String getSubject(Object token) {
        return ((DecodedJWT) token).getSubject();
    }

    protected Collection<String> getRolesClaim(Object token) {
        Claim jwtClaimRoles = ((DecodedJWT) token).getClaim(authConf.claimRoles);
        if (!jwtClaimRoles.isNull()) {
            return jwtClaimRoles.asList(String.class);
        } else {
            return Collections.emptyList();
        }

    }

    protected List<String> getPermissionsClaim(Object token) {
        Claim jwtClaimPermissions = ((DecodedJWT) token).getClaim(authConf.claimPermissions);
        if (!jwtClaimPermissions.isNull()) {
            return jwtClaimPermissions.asList(String.class);
        } else {
            return Collections.emptyList();
        }
    }

    private void addTechnicalRolesToPermissions(List<String> permissions, Collection<String> roles) {
        if (injectPermissions) {
            LOGGER.debug("Adding permissions of roles " + roles.toString() + " from map technical roles "
                    + TechnicalRoles.getTechnicalRolesPermissions().toString() + " in existing permissions "
                    + permissions);
            TechnicalRoles.getTechnicalRolesPermissions().entrySet().stream()
                    .filter(e -> roles.contains(e.getKey()))
                    .filter(e -> e.getValue().size() > 0)
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

        String accessToken = header.substring(7);
        try {
            Boolean ok = cacheManager.getDecision(getDecisionCacheKey(ctx, accessToken));
            if (ok != null && !ok) {
                ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
            }
            Object token = getObjectToken(accessToken);
            ctx.getHeaders().remove(authConf.headerUser); // remove it in case it's been set manually
            String userId = getSubject(token);
            if (!StringUtil.isNullOrEmpty(userId)) {
                ctx.getHeaders().putSingle(authConf.headerUser, userId);
                LOGGER.debug("Add Header [" + authConf.headerUser + ": " + userId + "]");
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
                LOGGER.debug("Add Header [" + authConf.headerGroup + ": " + groups + "]");
            }

            List<String> permissions = getPermissionsClaim(token);
            addTechnicalRolesToPermissions(permissions, roles);
            LOGGER.debug("Permissions: " + permissions.toString());
            if (!permissions.isEmpty()) {
                ArlasClaims arlasClaims = new ArlasClaims(permissions);
                ctx.setProperty("claims", arlasClaims.getRules());
                if (ok || arlasClaims.isAllowed(ctx.getMethod(), ctx.getUriInfo().getPath())) {
                    arlasClaims.injectHeaders(ctx.getHeaders(), transaction);
                    cacheManager.putDecision(getDecisionCacheKey(ctx, accessToken), Boolean.TRUE);
                    return;
                }
            }
            if (isPublic) {
                cacheManager.putDecision(getDecisionCacheKey(ctx, accessToken), Boolean.TRUE);
                return;
            }
        } catch (Exception e) {
            LOGGER.warn("JWT verification failed.", e);
            if (!isPublic) {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            return;
        }
        cacheManager.putDecision(getDecisionCacheKey(ctx, accessToken), Boolean.FALSE);
        ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }

    private String getDecisionCacheKey(ContainerRequestContext ctx, String accessToken) {
        return StringUtil.concat(ctx.getMethod(), ":", ctx.getUriInfo().getPath(), ":", accessToken);
    }

    protected String decodeToken(String token) {
        String[] chunks = token.split("\\.");
        return new String(decoder.decode(chunks[0])) + new String(decoder.decode(chunks[1]));
    }
}