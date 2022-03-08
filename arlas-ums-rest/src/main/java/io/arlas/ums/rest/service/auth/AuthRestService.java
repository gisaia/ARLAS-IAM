package io.arlas.ums.rest.service.auth;

import com.codahale.metrics.annotation.Timed;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.ums.core.AuthService;
import io.arlas.ums.rest.service.AbstractRestService;
import io.arlas.ums.util.ArlasAuthServerConfiguration;
import io.dropwizard.hibernate.UnitOfWork;
import io.swagger.annotations.*;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.Date;

@Path("/")
@Api(value = "/")
@SwaggerDefinition(
        info = @Info(contact = @Contact(email = "contact@gisaia.com", name = "Gisaia", url = "http://www.gisaia.com/"),
                title = "ARLAS UMS API - Authorization server",
                description = "auth REST services",
                license = @License(name = "Proprietary"),
                version = "API_VERSION"),
        schemes = { SwaggerDefinition.Scheme.HTTP, SwaggerDefinition.Scheme.HTTPS },
        securityDefinition = @SecurityDefinition(
                apiKeyAuthDefinitions = {
                        @ApiKeyAuthDefinition(key = "JWT", name = "Authorization", in = ApiKeyAuthDefinition.ApiKeyLocation.HEADER)
                }
        )
)
public class AuthRestService extends AbstractRestService {

    public AuthRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        super(authService, configuration);
    }

    @Timed
    @Path("permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Get permissions for a user given access token",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = String.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getPermissionToken(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws ArlasException {

        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createPermissionToken(getIdentityParam(headers).userId, uriInfo.getBaseUri().getHost(), new Date()))
                .type("text/plain")
                .build();
    }

}
