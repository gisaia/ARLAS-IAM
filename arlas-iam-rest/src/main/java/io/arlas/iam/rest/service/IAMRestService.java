package io.arlas.iam.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.commons.rest.response.Error;
import io.arlas.filter.config.TechnicalRoles;
import io.arlas.iam.core.AuthService;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.model.ForbiddenOrganisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;
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
public class IAMRestService {
    private final Logger LOGGER = LoggerFactory.getLogger(IAMRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";

    protected final AuthService authService;
    protected final String userHeader;
    protected final String groupsHeader;
    protected final String anonymousValue;

    public IAMRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.userHeader = configuration.arlasAuthConfiguration.headerUser;
        this.groupsHeader = configuration.arlasAuthConfiguration.headerGroup;
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
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Session created.", response = LoginData.class),
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
                .entity(new LoginData(authService.login(loginDef.email, loginDef.password, uriInfo.getBaseUri().getHost())))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.TEXT_PLAIN_TYPE)
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
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Session refreshed.", response = LoginData.class),
            @ApiResponse(code = 401, message = "Invalid token.", response = Error.class),
            @ApiResponse(code = 404, message = "Login failed.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response refresh(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "refreshToken", required = true)
            @PathParam(value = "refreshToken") String refreshToken
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new LoginData(authService.refresh(getUser(headers), refreshToken, uriInfo.getBaseUri().getHost())))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    ) throws NonMatchingPasswordException, AlreadyVerifiedException, InvalidTokenException, SendEmailException, NotFoundException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.verifyUser(UUID.fromString(id), token, password)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response readUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotFoundException {

        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(getUser(headers, id)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.TEXT_PLAIN_TYPE)
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
            @NotNull @Valid UpdateUserDef updateDef

    ) throws NotFoundException, NonMatchingPasswordException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.updateUser(getUser(headers, id), updateDef.oldPassword, updateDef.newPassword)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenOrganisationNameException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.createOrganisation(getUser(headers))))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenOrganisationNameException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.createOrganisation(getUser(headers), name)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    ) throws NotFoundException, NotOwnerException, ForbiddenActionException {
        authService.deleteOrganisation(getUser(headers), UUID.fromString(oid));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity("organisation deleted")
                .type(MediaType.TEXT_PLAIN_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/check")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Check if user's organisation exists",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = OrgExists.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response checkOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgExists(authService.checkOrganisation(getUser(headers))))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = UserOrgData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getOrganisations(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException {
        User user = getUser(headers);
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisations(user).stream().map(o -> new UserOrgData(o, user)).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .entity(authService.listOrganisationUsers(getUser(headers), UUID.fromString(oid)).stream().map(MemberData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/emails")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List users of same domain than the organisation but not invited yet.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = String.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getEmails(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listUserEmailsFromOwnDomain(getUser(headers), UUID.fromString(oid)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Get a user of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = MemberData.class),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        Optional<OrganisationMember> u = authService.listOrganisationUsers(getUser(headers), UUID.fromString(oid))
                .stream()
                .filter(om -> om.getUser().is(UUID.fromString(uid)))
                .findFirst();
        if (u.isPresent()) {
            return Response.ok(uriInfo.getRequestUriBuilder().build())
                    .entity(new MemberData(u.get()))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        } else {
            throw new NotFoundException("User not found in organisation.");
        }
    }

    @Timed
    @Path("organisations/{oid}/users")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a user to an organisation. User account will be created if needed.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = OrgData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addUserToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "user", required = true)
            @NotNull @Valid OrgUserDef user
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException, SendEmailException, InvalidEmailException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.addUserToOrganisation(getUser(headers), user.email, UUID.fromString(oid), user.isOwner)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update ownership of an organisation by a user.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @ApiParam(name = "user", required = true)
            @NotNull @Valid UpdateOrgUserDef user
    ) throws NotFoundException, NotOwnerException, ForbiddenActionException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.updateUserInOrganisation(getUser(headers), UUID.fromString(uid), UUID.fromString(oid), user.isOwner)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    // ------------- forbidden organisations --------------

    @Timed
    @Path("organisations/forbidden")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a name to the forbidden organisations list.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation.", response = ForbiddenOrganisation.class),
            @ApiResponse(code = 400, message = "Not allowed.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addForbiddenOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "forbiddenOrganisation", required = true)
            @NotNull @Valid ForbiddenOrganisation forbiddenOrganisation
    ) throws AlreadyExistsException, NotFoundException, NotAllowedException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addForbiddenOrganisation(getUser(headers), forbiddenOrganisation))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/forbidden/{name}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Remove a name from the forbidden organisations list.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation.", response = String.class),
            @ApiResponse(code = 400, message = "Not allowed.", response = Error.class),
            @ApiResponse(code = 404, message = "Name not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response removeNameFromForbiddenOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "name", required = true)
            @PathParam(value = "name") String name
    ) throws NotFoundException, NotAllowedException {
        authService.removeForbiddenOrganisation(getUser(headers), name);
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity("ok")
                .type(MediaType.TEXT_PLAIN)
                .build();
    }

    @Timed
    @Path("organisations/forbidden")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List forbidden organisations.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = ForbiddenOrganisation.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response listForbiddenOrganisations(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers
    ) throws NotFoundException, NotAllowedException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listForbiddenOrganisation(getUser(headers)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/collections")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List collections of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = String.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getOrganisationCollections(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.getOrganisationCollections(getUser(headers), UUID.fromString(oid),
                        headers.getHeaderString(HttpHeaders.AUTHORIZATION)).stream().sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update a role in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation or role not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateRoleInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updateRole(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid), UUID.fromString(rid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .entity(authService.listRoles(getUser(headers), UUID.fromString(oid)).stream().map(RoleData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .entity(authService.listRoles(getUser(headers), UUID.fromString(oid), UUID.fromString(uid)).stream().map(RoleData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Modify roles of a user within an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = UserData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response putRoles(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @ApiParam(name = "ridList", required = true)
            @NotNull @Valid UpdateListDef ridList

    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, NotAllowedException, ForbiddenActionException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.updateRolesOfUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), ridList.ids), false))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .entity(new UserData(authService.addRoleToUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)), false))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
    ) throws NotFoundException, NotOwnerException, NotAllowedException, ForbiddenActionException {
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.removeRoleFromUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)), false))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    //----------------- groups -------------------

    @Timed
    @Path("organisations/{oid}/groups")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add a group to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addGroupToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.createGroup(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups/{rid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update a group in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation or role not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updateGroup(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid), UUID.fromString(rid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List groups of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getGroupsOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listGroups(getUser(headers), UUID.fromString(oid)).stream().map(RoleData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/groups")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List groups of a user within an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = RoleData.class, responseContainer = "List"),
            @ApiResponse(code = 400, message = "Bad request", response = Error.class),
            @ApiResponse(code = 404, message = "User or organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getGroups(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listGroups(getUser(headers), UUID.fromString(oid), UUID.fromString(uid)).stream().map(RoleData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .entity(authService.listPermissions(getUser(headers), UUID.fromString(oid), UUID.fromString(uid))
                        .stream()
                        .map(PermissionData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List permissions of an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = PermissionData.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "Organisation not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork(readOnly = true)
    public Response getPermissionsOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listPermissions(getUser(headers), UUID.fromString(oid)).stream().map(PermissionData::new).sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
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
            @ApiResponse(code = 400, message = "Permission already exists.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "permission", required = true)
            @NotNull @Valid PermissionDef permission
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.createPermission(getUser(headers), UUID.fromString(oid), permission.value, permission.description)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions/columnfilter")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Add column filter permission for the given collections.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = PermissionData.class),
            @ApiResponse(code = 400, message = "Permission already exists.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addColumnFilterPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "collections", required = true)
            @NotNull @Valid List<String> collections
    ) throws ArlasException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.createColumnFilter(getUser(headers),
                        UUID.fromString(oid), collections, headers.getHeaderString(HttpHeaders.AUTHORIZATION))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions/{pid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update a permission",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = PermissionData.class),
            @ApiResponse(code = 400, message = "Permission already exists.", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation or permission not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updatePermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "permission", required = true)
            @NotNull @Valid PermissionDef permission
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.updatePermission(getUser(headers), UUID.fromString(oid), UUID.fromString(pid), permission.value, permission.description)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions/columnfilter/{pid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update a column filter permission.",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = PermissionData.class),
            @ApiResponse(code = 400, message = "Permission already exists.", response = Error.class),
            @ApiResponse(code = 404, message = "Organisation or permission not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updateColumnFilterPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @ApiParam(name = "collections", required = true)
            @NotNull @Valid List<String> collections
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.updateColumnFilter(getUser(headers),
                        UUID.fromString(oid), UUID.fromString(pid), collections,
                        headers.getHeaderString(HttpHeaders.AUTHORIZATION))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "List permissions of a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = PermissionData.class, responseContainer = "List"),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response listPermissionOfRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listPermissionsOfRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid))
                        .stream()
                        .map(PermissionData::new)
                        .toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(authorizations = @Authorization("JWT"),
            value = "Update permissions of a role",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = RoleData.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response updatePermissionOfRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @ApiParam(name = "pidList", required = true)
            @NotNull @Valid UpdateListDef pidList

    ) throws NotFoundException, NotOwnerException {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updatePermissionsOfRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), pidList.ids)))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.APPLICATION_JSON_TYPE)
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
                .type(MediaType.TEXT_PLAIN_TYPE)
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
                .toList();

        LOGGER.debug("User='" + userId + "' / Groups='" + groups + "'");
        return new IdentityParam(userId, groups);
    }
}
