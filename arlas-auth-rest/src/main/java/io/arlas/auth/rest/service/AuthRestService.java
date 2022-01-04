package io.arlas.auth.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.auth.core.AuthService;
import io.arlas.auth.exceptions.NotFoundException;
import io.arlas.auth.exceptions.NotOwnerException;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;
import io.arlas.auth.rest.model.Error;
import io.arlas.auth.rest.model.UpdateData;
import io.arlas.auth.util.ArlasAuthServerConfiguration;
import io.arlas.auth.util.IdentityParam;
import io.dropwizard.hibernate.UnitOfWork;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Path("/auth")
@Api(value = "/auth")
@SwaggerDefinition(
        info = @Info(contact = @Contact(email = "contact@gisaia.com", name = "Gisaia", url = "http://www.gisaia.com/"),
                title = "ARLAS auth API",
                description = "auth REST services",
                license = @License(name = "Proprietary"),
                version = "API_VERSION"),
        schemes = { SwaggerDefinition.Scheme.HTTP, SwaggerDefinition.Scheme.HTTPS })
public class AuthRestService {
    Logger LOGGER = LoggerFactory.getLogger(AuthRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";

    private final AuthService authService;
    private final String userHeader;
    private final String organizationHeader;
    private final String groupsHeader;
    private final String anonymousValue;

    public AuthRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.userHeader = configuration.headerUser;
        this.organizationHeader = configuration.organizationHeader;
        this.groupsHeader = configuration.headerGroup;
        this.anonymousValue = configuration.anonymousValue;
    }

    // --------------- Users ---------------------

    @Timed
    @Path("user")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Creates a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "email", required = true)
            @NotNull @Valid String email
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createUser(email))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("user/{id}/verify")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Creates a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response verifyUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id,

            @ApiParam(name = "password", required = true)
            @NotNull @Valid String password
    ) {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.verifyUser(UUID.fromString(id), password))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("user")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Read a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response getUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws Exception {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(getUser(headers))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("user")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Delete the logged in user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response deleteUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.deleteUser(UUID.fromString(getIdentityParam(headers).userId)).get())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("user")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Update the logged in user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "updateData", required = true)
            @NotNull @Valid UpdateData updateData

    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.updateUser(getUser(headers), updateData.oldPassword, updateData.newPassword))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "List users of same organisations",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response getUsers(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws Exception {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listUsers(getUser(headers)))
                .type("application/json")
                .build();
    }

    // --------------- Organisations ---------------------
    @Timed
    @Path("organisation")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Creates an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createOrganisation(getUser(headers)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Delete an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response deleteOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.deleteOrganisation(getUser(headers), UUID.fromString(oid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "List organisations of the user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = Organisation.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response getOrganisations(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws Exception {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisations(getUser(headers)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/user")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a user to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addUserToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "email", required = true)
            @NotNull @Valid String email
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addUserToOrganisation(getUser(headers), email, UUID.fromString(oid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Removes a user from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeUserFromOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,
            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removeUserFromOrganisation(getUser(headers), UUID.fromString(uid), UUID.fromString(oid)))
                .type("application/json")
                .build();
    }


    //----------------- private -----------------

    private User getUser(HttpHeaders headers) throws NotFoundException {
        return authService.readUser(UUID.fromString(getIdentityParam(headers).userId), true);
    }

    private IdentityParam getIdentityParam(HttpHeaders headers) {
        String userId = Optional.ofNullable(headers.getHeaderString(this.userHeader))
                .orElse(this.anonymousValue);

        String organization = Optional.ofNullable(headers.getHeaderString(this.organizationHeader))
                .orElse(""); // in a context where resources are publicly available, no organisation is defined

        List<String> groups = Arrays.stream(
                        Optional.ofNullable(headers.getHeaderString(this.groupsHeader)).orElse("group/public").split(","))
                .map(g -> g.trim())
                .collect(Collectors.toList());

        LOGGER.info("User='" + userId + "' / Org='" + organization + "' / Groups='" + groups.toString() + "'");
        return new IdentityParam(userId, organization, groups);
    }

}
