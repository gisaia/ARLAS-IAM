package io.arlas.auth.filter;

import co.elastic.apm.api.ElasticApm;
import co.elastic.apm.api.Transaction;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.auth.core.AuthService;
import io.arlas.auth.util.ArlasAuthServerConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

// TODO: copy from ARLAS Server. To be refactored

@Provider
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {
    private final Logger LOGGER = LoggerFactory.getLogger(AuthorizationFilter.class);
    private final ArlasAuthServerConfiguration authConf;
    private final AuthService authService;

    public AuthorizationFilter(ArlasAuthServerConfiguration conf, AuthService authService) {
        this.authConf = conf;
        this.authService = authService;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        Transaction transaction = ElasticApm.currentTransaction();
        boolean isPublic = ctx.getUriInfo().getPath().concat(":").concat(ctx.getMethod()).matches(authConf.getPublicRegex());
        String header = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.toLowerCase().startsWith("bearer ")) {
            if (isPublic || Objects.equals(ctx.getMethod(), "OPTIONS")) {
                return;
            } else {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        }

        try {
            // header presence and format already checked before in AuthenticationFilter
            DecodedJWT jwt = authService.verifyToken(header.substring(7));

            ctx.getHeaders().remove(authConf.headerUser); // remove it in case it's been set manually
            String userId = jwt.getSubject();
            if (userId != null && !userId.isBlank()) {
                ctx.getHeaders().putSingle(authConf.headerUser, userId);
                transaction.setUser(userId, "", "");
            }

            ctx.getHeaders().remove(authConf.headerGroup); // remove it in case it's been set manually
            Claim jwtClaimRoles = jwt.getClaim(authConf.claimRoles);
            if (!jwtClaimRoles.isNull()) {
                List<String> groups = jwtClaimRoles.asList(String.class)
                        .stream()
                        .filter(r -> r.toLowerCase().startsWith("group"))
                        .collect(Collectors.toList());
                ctx.setProperty("groups", groups);
                ctx.getHeaders().put(authConf.headerGroup, groups);
            }
            // TODO: use permissions from DB
//            Claim jwtClaimPermissions = jwt.getClaim(authConf.claimPermissions);
//            if (!jwtClaimPermissions.isNull()) {
//                ArlasClaims arlasClaims = new ArlasClaims(jwtClaimPermissions.asList(String.class));
//                ctx.setProperty("claims", arlasClaims);
//                // TODO: use permissions from DB
//                if (arlasClaims.isAllowed(ctx.getMethod(), ctx.getUriInfo().getPath())) {
//                    arlasClaims.injectHeaders(ctx.getHeaders(), transaction);
                    return;
//                }
//            }
//            if (isPublic) {
//                return;
//            } else {
//                ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
//            }
        } catch (JWTVerificationException e) {
            LOGGER.warn("JWT verification failed.", e);
            if (!isPublic) {
                ctx.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            return;
        }
//        ctx.abortWith(Response.status(Response.Status.FORBIDDEN).build());
    }
}
