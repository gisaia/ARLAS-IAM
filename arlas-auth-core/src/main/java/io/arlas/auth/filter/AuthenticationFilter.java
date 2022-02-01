package io.arlas.auth.filter;

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

// TODO: copy from ARLAS Server. To be refactored

@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {
    private final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);
    private final ArlasAuthServerConfiguration authConf;

    public AuthenticationFilter(ArlasAuthServerConfiguration conf) {
        this.authConf = conf;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String header = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        requestContext.setProperty("public", authConf.publicUris);
        LOGGER.info("Header = " + header);
        LOGGER.info("Header = " + requestContext.getHeaders().toString());
        if (header == null || !header.toLowerCase().startsWith("bearer ")) {
            //If public end point and no authorize verb
            if ( !requestContext.getUriInfo().getPath().concat(":").concat(requestContext.getMethod()).matches(authConf.getPublicRegex())  && requestContext.getMethod() != "OPTIONS") {
                requestContext.abortWith(
                        Response.status(Response.Status.UNAUTHORIZED)
                                .header(HttpHeaders.WWW_AUTHENTICATE,
                                        "Bearer realm=\"ARLAS Server secured access\"")
                                .build());

            }
        }
    }
}