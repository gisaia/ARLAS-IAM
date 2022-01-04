package io.arlas.auth.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.auth.core.AuthService;
import io.arlas.auth.exceptions.NotFoundException;
import io.arlas.auth.exceptions.NotOwnerException;
import io.arlas.auth.model.*;
import io.arlas.auth.rest.model.Error;
import io.arlas.auth.rest.model.Permissions;
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

    //----------------- roles -------------------

    @Timed
    @Path("organisation/{oid}/role/{rname}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a role to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Role.class),
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
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createRole(getUser(headers), rname, UUID.fromString(oid), permissions.permissions))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/role/{rid}/users/{uid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a role to a user in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
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
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addRoleToUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/role/{rid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Removes a role from a user from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
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

    //----------------- roles -------------------

    @Timed
    @Path("organisation/{oid}/group/{gname}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a group to an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response addGroupToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "gname", required = true)
            @PathParam(value = "gname") String gname

    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createGroup(getUser(headers), gname, UUID.fromString(oid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/group/{gid}/users/{uid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a user to a group in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
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
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addUserToGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/group/{gid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Removes a user from a group in organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = User.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
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
    @Path("organisation/{oid}/group/{gid}/roles/{rid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Add a role to a group in an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = Group.class),
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
    ) throws Exception {
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addRoleToGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(gid)))
                .type("application/json")
                .build();
    }

    @Timed
    @Path("organisation/{oid}/group/{gid}/roles/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "Removes a role from a group from an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 202, message = "Successful operation", response = Group.class),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
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
    @Path("organisation/{oid}/user/{uid}/permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @ApiOperation(
            value = "List permissions of a user within an organisation",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 200, message = "Successful operation", response = Permissions.class, responseContainer = "List"),
            @ApiResponse(code = 404, message = "User not found.", response = Error.class),
            @ApiResponse(code = 500, message = "Arlas Error.", response = Error.class)})

    @UnitOfWork
    public Response getPermissions(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @ApiParam(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @ApiParam(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws Exception {
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
    @ApiOperation(
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
    @ApiOperation(
            value = "Add a permission to a user",
            produces = UTF8JSON,
            consumes = UTF8JSON
    )
    @ApiResponses(value = {@ApiResponse(code = 201, message = "Successful operation", response = User.class),
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
    @ApiOperation(
            value = "Removes a permission from a user",
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
    @ApiOperation(
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
    @ApiOperation(
            value = "Removes a permission from a role",
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
