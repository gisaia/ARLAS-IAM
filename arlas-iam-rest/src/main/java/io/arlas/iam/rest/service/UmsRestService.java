package io.arlas.iam.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.commons.rest.response.Error;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.config.AuthConfiguration;
import io.arlas.iam.config.TechnicalRoles;
import io.arlas.iam.core.AuthService;
import io.arlas.iam.model.LoginSession;
import io.arlas.iam.model.User;
import io.arlas.iam.rest.model.input.*;
import io.arlas.iam.rest.model.output.*;
import io.arlas.iam.rest.model.input.*;
import io.arlas.iam.rest.model.output.*;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.arlas.iam.util.IdentityParam;
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
                title = "ARLAS IAM API",
                description = "IAM REST services",
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
    private final Logger LOGGER = LoggerFactory.getLogger(UmsRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";

    protected final AuthService authService;
    protected final String userHeader;
    protected final String groupsHeader;
    protected final String anonymousValue;

    public UmsRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.userHeader = ((AuthConfiguration)configuration.arlasAuthConfiguration).headerUser;
        this.groupsHeader = ((AuthConfiguration)configuration.arlasAuthConfiguration).headerGroup;
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

            @ApiParam(name = "loginDef", required = true)
            @NotNull @Valid LoginDef loginDef
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.login(loginDef.email, loginDef.password, uriInfo.getBaseUri().getHost()))
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
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "userDef", required = true)
            @NotNull @Valid NewUserDef userDef
    ) throws AlreadyExistsException, InvalidEmailException, SendEmailException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.createUser(userDef.email, userDef.locale, userDef.timezone)))
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
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request.", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 412, message = "Verification token expired. A new one is sent.", response = Error.class),
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
    ) throws NonMatchingPasswordException, AlreadyVerifiedException, ExpiredTokenException, SendEmailException, NotFoundException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.verifyUser(UUID.fromString(id), token, password)))
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
    ) throws NotFoundException, NotAllowedException {
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
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Non matching passwords.", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,


            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id,

            @ApiParam(name = "updateDef", required = true)
            @NotNull @Valid UpdateDef updateDef

    ) throws NotFoundException, NonMatchingPasswordException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.updateUser(getUser(headers, id), updateDef.oldPassword, updateDef.newPassword)))
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
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = OrgData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.createOrganisation(getUser(headers))))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{name}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Create an organisation with a name. Only for IAM admin.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = OrgData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response createOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "name", required = true)
            @PathParam(value = "name") String name
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.createOrganisation(getUser(headers), name)))
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
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
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
            value = "List organisations of the logged in user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = OrgData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getOrganisations(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisations(getUser(headers)).stream().map(OrgData::new).toList())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List users of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = MemberData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getUsers(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisationUsers(getUser(headers), UUID.fromString(oid)).stream().map(MemberData::new).toList())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a user to an organisation. User must have an account already.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = OrgData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addUserToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "user", required = true)
            @NotNull @Valid OrgUserDef user
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.addUserToOrganisation(getUser(headers), user.email, UUID.fromString(oid), user.isOwner)))
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
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = OrgData.class),
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
    ) throws NotFoundException, NotOwnerException, NotAllowedException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.removeUserFromOrganisation(getUser(headers), UUID.fromString(uid), UUID.fromString(oid))))
                .type("application/json")
                .build();
    }

    //----------------- roles -------------------

    @Timed
    @Path("organisations/{oid}/roles")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a role to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addRoleToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.createRole(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid))))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List roles of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getRolesOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listRoles(getUser(headers), UUID.fromString(oid)).stream().map(RoleData::new).toList())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List roles of a user within an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class, responseContainer = "List"),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getRoles(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listRoles(getUser(headers), UUID.fromString(oid), UUID.fromString(uid)).stream().map(RoleData::new).toList())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles/{rid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a role to a user in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addRoleToUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.addRoleToUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid))))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a role from a user from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeRoleFromUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException, NotAllowedException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.removeRoleFromUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid))))
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
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = PermissionData.class, responseContainer = "List"),
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
                .entity(authService.listPermissions(getUser(headers), UUID.fromString(oid), UUID.fromString(uid)).stream().map(PermissionData::new).toList())
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a permission",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = PermissionData.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "permission", required = true)
            @NotNull @Valid PermissionDef permission
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.createPermission(getUser(headers), UUID.fromString(oid), permission.value, permission.description)))
                .type("application/json")
                .build();
    }


    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions/{pid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a permission to a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addPermissionToRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.addPermissionToRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(pid))))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions/{pid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a permission from a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removePermissionFromRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid
    ) throws NotFoundException, NotOwnerException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.removePermissionFromRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(pid))))
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

        List<String> groups = Arrays.stream(
                        Optional.ofNullable(headers.getHeaderString(this.groupsHeader)).orElse(TechnicalRoles.GROUP_PUBLIC).split(","))
                .map(String::trim)
                .collect(Collectors.toList());

        LOGGER.debug("User='" + userId + "' / Groups='" + groups + "'");
        return new IdentityParam(userId, groups);
    }
}
