package io.arlas.ums.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.ums.core.AuthService;
import io.arlas.ums.exceptions.*;
import io.arlas.ums.model.*;
import io.arlas.ums.rest.model.LoginData;
import io.arlas.ums.rest.model.NewUserData;
import io.arlas.ums.rest.model.Permissions;
import io.arlas.ums.rest.model.UpdateData;
import io.arlas.ums.util.ArlasAuthServerConfiguration;
import io.arlas.ums.util.IdentityParam;
import io.dropwizard.hibernate.UnitOfWork;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.util.*;
import java.util.stream.Collectors;

@Path("/")
@Api(value = "/")
@SwaggerDefinition(
        info = @Info(contact = @Contact(email = "contact@gisaia.com", name = "Gisaia", url = "http://www.gisaia.com/"),
                title = "ARLAS UMS API - IDP",
                description = "IDP REST services",
                license = @License(name = "Proprietary"),
                version = "API_VERSION"),
        schemes = { SwaggerDefinition.Scheme.HTTP, SwaggerDefinition.Scheme.HTTPS },
        securityDefinition = @SecurityDefinition(
                apiKeyAuthDefinitions = {
                        @ApiKeyAuthDefinition(key = "JWT", name = "Authorization", in = ApiKeyAuthDefinition.ApiKeyLocation.HEADER)
                }
        )
)
public class UmsRestService {
    Logger LOGGER = LoggerFactory.getLogger(UmsRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";

    protected final AuthService authService;
    protected final String userHeader;
    protected final String organizationHeader;
    protected final String groupsHeader;
    protected final String anonymousValue;

    public UmsRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.userHeader = configuration.authConf.headerUser;
        this.organizationHeader = configuration.organizationHeader;
        this.groupsHeader = configuration.authConf.headerGroup;
        this.anonymousValue = configuration.anonymousValue;
    }

    // --------------- Users ---------------------

    @Timed
    @Path("session")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "User login",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Session created.", response = LoginSession.class),
            @ApiResponse(code = 404, message = "Login failed", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response login(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "loginData", required = true)
            @NotNull @Valid LoginData loginData
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.login(loginData.email, loginData.password, uriInfo.getBaseUri().getHost()))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("session")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Delete session",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Session deleted.", response = String.class),
            @ApiResponse(code = 404, message = "Login failed", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response logout(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        authService.logout(getUser(headers).getId());
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity("Session deleted.")
                .type("text/plain")
                .build();
    }

    @Timed
    @Path("session/{refreshToken}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Refresh access token",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Session refreshed.", response = LoginSession.class),
            @ApiResponse(code = 404, message = "Login failed", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response refresh(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "refreshToken", required = true)
            @PathParam(value = "refreshToken") String refreshToken
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.refresh(getUser(headers), refreshToken, uriInfo.getBaseUri().getHost()))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Create a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Bad request.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "userData", required = true)
            @NotNull @Valid NewUserData userData
    ) throws AlreadyExistsException, InvalidEmailException, SendEmailException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createUser(userData.email, userData.locale, userData.timezone))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users/{id}/verify/{token}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Verify a user (through link received by email)",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Bad request.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response verifyUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id,

            @ApiParam(name = "token", required = true)
            @PathParam(value = "token") String token,

            @ApiParam(name = "password", required = true)
            @NotNull @Valid String password
    ) throws NonMatchingPasswordException, AlreadyVerifiedException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.verifyUser(UUID.fromString(id), token, password))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users/{id}")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Read a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotFoundException {

        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(getUser(headers, id))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users/{id}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Delete the logged in user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = String.class),
            @ApiResponse(code = 400, message = "Non matching passwords.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response deleteUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotFoundException {
        checkLoggedInUser(headers, id);
        authService.deleteUser(UUID.fromString(id));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity("User deleted.")
                .type("text/plain")
                .build();

    }

    @Timed
    @Path("users/{id}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update the logged in user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Non matching passwords.", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,


            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id,

            @ApiParam(name = "updateData", required = true)
            @NotNull @Valid UpdateData updateData

    ) throws NotFoundException, NonMatchingPasswordException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.updateUser(getUser(headers, id), updateData.oldPassword, updateData.newPassword))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("users")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List users of same organisations",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = User.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getUsers(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listUsers(getUser(headers)))
                .type("application/json")
                .build();
    }

    // --------------- Organisations ---------------------
    @Timed
    @Path("organisations")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Create an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createOrganisation(getUser(headers)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Delete an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = String.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response deleteOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        authService.deleteOrganisation(getUser(headers), UUID.fromString(oid));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity("organisation deleted")
                .type("text/plain")
                .build();
    }

    @Timed
    @Path("organisations")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List organisations of the user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = Organisation.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getOrganisations(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisations(getUser(headers)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a user to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addUserToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "email", required = true)
            @NotNull @Valid String email
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addUserToOrganisation(getUser(headers), email, UUID.fromString(oid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a user from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Organisation.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
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

    //----------------- roles -------------------

    @Timed
    @Path("organisations/{oid}/roles/{rname}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a role to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Role.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addRoleToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rname", required = true)
            @PathParam(value = "rname") String rname,

            @ApiParam(name = "permissions", required = true)
            @NotNull @Valid Permissions permissions
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createRole(getUser(headers), rname, UUID.fromString(oid),
                        permissions.permissions.stream().map(p -> new Permission(p, false)).collect(Collectors.toSet())))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/users/{uid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a role to a user in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addRoleToUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addRoleToUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a role from a user from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeRoleFromUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removeRoleFromUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)))
                .type("application/json")
                .build();
    }

    //----------------- groups -------------------

    @Timed
    @Path("organisations/{oid}/groups/{gname}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a group to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addGroupToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gname", required = true)
            @PathParam(value = "gname") String gname

    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createGroup(getUser(headers), gname, UUID.fromString(oid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups/{gid}/users/{uid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a user to a group in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addUserToGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gid", required = true)
            @PathParam(value = "gid") String gid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addUserToGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups/{gid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a user from a group in organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeUserFromGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gid", required = true)
            @PathParam(value = "gid") String gid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removeUserFromGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups/{gid}/roles/{rid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a role to a group in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addRoleToGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gid", required = true)
            @PathParam(value = "gid") String gid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addRoleToGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups/{gid}/roles/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Removes a role from a group from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeRoleFromGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gid", required = true)
            @PathParam(value = "gid") String gid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removeRoleFromGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    //----------------- permissions -----------------

    @Timed
    @Path("organisations/{oid}/users/{uid}/permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List permissions of a user within an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = String.class, responseContainer = "List"),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getPermissions(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listPermissions(getUser(headers), UUID.fromString(oid), UUID.fromString(uid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("permissions/{permission}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Adds a system permission",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Permission.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addSystemPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "permission", required = true)
            @PathParam(value = "permission") String permission
    ) {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createPermission(permission, true))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("permissions/{pid}/users/{uid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a permission to a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addPermissionToUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid

    ) throws NotFoundException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addPermissionToUser(UUID.fromString(uid), UUID.fromString(pid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("permissions/{pid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a permission from a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removePermissionFromUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid

    ) throws NotFoundException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removePermissionFromUser(UUID.fromString(uid), UUID.fromString(pid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("permissions/{pid}/roles/{rid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a permission to a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Role.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addPermissionToRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid

    ) throws NotFoundException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addPermissionToRole(UUID.fromString(rid), UUID.fromString(pid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("permissions/{pid}/roles/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a permission from a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Role.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removePermissionFromRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid

    ) throws NotFoundException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(authService.removePermissionFromRole(UUID.fromString(rid), UUID.fromString(pid)))
                .type("application/json")
                .build();
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

    //----------------- private -----------------

    protected void checkLoggedInUser(HttpHeaders headers, String id) throws NotFoundException {
        if (!id.equals(getIdentityParam(headers).userId)) {
            throw new NotFoundException("Logged in user " + getIdentityParam(headers).userId + " does not match requested id " + id);
        }
    }

    protected User getUser(HttpHeaders headers) throws NotFoundException {
        return authService.readUser(UUID.fromString(getIdentityParam(headers).userId), true);
    }

    protected User getUser(HttpHeaders headers, String id) throws NotFoundException {
        checkLoggedInUser(headers, id);
        return getUser(headers);
    }

    protected IdentityParam getIdentityParam(HttpHeaders headers) {
        String userId = Optional.ofNullable(headers.getHeaderString(this.userHeader))
                .orElse(this.anonymousValue);

        String organization = Optional.ofNullable(headers.getHeaderString(this.organizationHeader))
                .orElse(""); // in a context where resources are publicly available, no organisation is defined

        List<String> groups = Arrays.stream(
                        Optional.ofNullable(headers.getHeaderString(this.groupsHeader)).orElse("group/public").split(","))
                .map(String::trim)
                .collect(Collectors.toList());

        LOGGER.debug("User='" + userId + "' / Org='" + organization + "' / Groups='" + groups + "'");
        return new IdentityParam(userId, organization, groups);
    }
}
