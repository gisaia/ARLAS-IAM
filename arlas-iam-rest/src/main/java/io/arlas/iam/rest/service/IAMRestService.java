/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.arlas.iam.rest.service;

import com.codahale.metrics.annotation.Timed;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.exceptions.InvalidParameterException;
import io.arlas.commons.exceptions.NotAllowedException;
import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.commons.rest.response.Error;
import io.arlas.commons.rest.utils.ServerConstants;
import io.arlas.filter.core.IdentityParam;
import io.arlas.iam.core.AuthService;
import io.arlas.iam.exceptions.*;
import io.arlas.iam.model.*;
import io.arlas.iam.rest.model.input.*;
import io.arlas.iam.rest.model.output.*;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.arlas.iam.util.ArlasMessage;
import io.dropwizard.hibernate.UnitOfWork;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static io.arlas.commons.rest.utils.ServerConstants.ARLAS_ORG_FILTER;
import static io.arlas.filter.impl.AbstractPolicyEnforcer.*;

@Path("/")
@OpenAPIDefinition(
        info = @Info(
                title = "ARLAS IAM APIs",
                description = "IAM REST services",
                license = @License(name = "Proprietary"),
                contact = @Contact(email = "contact@gisaia.com", name = "Gisaia", url = "http://www.gisaia.com/"),
                version = "API_VERSION"),
        servers = {
                @Server(url = "/arlas_iam_server", description = "default server")
        }
)
@SecurityScheme(
        name = "JWT",
        type = io.swagger.v3.oas.annotations.enums.SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)

public class IAMRestService {
    private final Logger LOGGER = LoggerFactory.getLogger(IAMRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";
    public static final String EVENT_ACTION = "event.action";
    public static final String ORG_ID = "organization.id";

    protected final AuthService authService;
    private final ArlasAuthConfiguration configuration;
    private final long refreshTokenTtl;

    public IAMRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.configuration = configuration.arlasAuthConfiguration;
        this.refreshTokenTtl = configuration.arlasAuthConfiguration.refreshTokenTTL / 1000L;
    }

    private void logUAM(HttpServletRequest request, HttpHeaders headers, String action, String log) {
        logUAM(request, headers,  null, action, log);
    }

    private void logUAM(HttpServletRequest request, HttpHeaders headers, String oid, String action, String log) {
        String ip = Optional.ofNullable(request.getHeader(X_FORWARDED_FOR))
                .orElseGet(request::getRemoteAddr)
                .split(",")[0].trim();
        if (oid != null) MDC.put(ORG_ID, oid);
        Enumeration<String> orgFilter = request.getHeaders(ARLAS_ORG_FILTER);
        if (orgFilter.hasMoreElements()) {
            MDC.put(ORGANIZATION_NAME, orgFilter.nextElement());
        }
        if (MDC.get(USER_ID) == null) {
            MDC.put(USER_ID, getIdentityParam(headers).userId);
        }
        MDC.put(EVENT_KIND, EVENT);
        MDC.put(EVENT_CATEGORY, IAM);
        MDC.put(EVENT_TYPE, ALLOWED);
        MDC.put(HTTP_REQUEST_METHOD, request.getMethod());
        MDC.put(URL_PATH, request.getRequestURI());
        MDC.put(URL_QUERY, request.getQueryString());
        MDC.put(USER_AGENT_ORIGINAL, request.getHeader(HttpHeaders.USER_AGENT));
        MDC.put(HTTP_REQUEST_REFERRER, request.getHeader(REFERER));
        MDC.put(CLIENT_ADDRESS, ip);
        MDC.put(CLIENT_IP, ip);
        MDC.put(EVENT_ACTION, action);
        LOGGER.info(log);
        MDC.clear();
    }

    // --------------- Forward auth ---------------------
    @Timed
    @Path("auth")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Validate authentication to another URI"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "401", description = "Unauthenticated",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "403", description = "Forbidden",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response forwardAuth(
            @Context UriInfo uriInfo
    ) {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("ok"))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    // --------------- Users ---------------------

    @Timed
    @Path("session")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "User login"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Session created.",
                    content = @Content(schema = @Schema(implementation = LoginData.class))),
            @ApiResponse(responseCode = "404", description = "Login failed",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response login(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "loginDef", required = true)
            @NotNull @Valid LoginDef loginDef
    ) throws ArlasException {
        LoginSession loginSession = authService.login(loginDef.email, loginDef.password, uriInfo.getBaseUri().getHost());
        LoginData loginData = new LoginData(loginSession);
        String refreshTokenCookieValue = String.format(
                "refresh_token=%s; Path=/; Max-Age=%s; Secure; HttpOnly; SameSite=Strict",
                new RefreshTokenCookie(loginSession.refreshToken).getCookieValue(),
                refreshTokenTtl);
        Response response = Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(loginData)
                // setting manually as we can't use the NewCookie object because it doesn't accept SameSite attribute before jax-rs version 3.1
                .header("Set-Cookie", refreshTokenCookieValue)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        MDC.put(USER_ID, loginData.user.id.toString());
        logUAM(request, headers,  "session", "user-login");
        return response;
    }

    @Timed
    @Path("session")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete session"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Session deleted.",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "404", description = "Login failed",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response logout(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request
    ) throws NotFoundException {
        authService.logout(getUser(headers).getId());
        logUAM(request, headers,  "session", "user-logout");
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("Session deleted."))
                .header("Set-Cookie", "refresh_token=deleted; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Path=/;")
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("session/refresh")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "Refresh access token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Session refreshed.",
                    content = @Content(schema = @Schema(implementation = LoginData.class))),
            @ApiResponse(responseCode = "401", description = "Invalid token.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Login failed.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response refresh(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @CookieParam("refresh_token") Cookie refreshToken
    ) throws ArlasException {
        if (refreshToken == null) {
            throw new InvalidTokenException("Missing refresh token in cookie");
        }
        RefreshTokenCookie rt = new RefreshTokenCookie(refreshToken.getValue());
        LoginSession loginSession = authService.refresh(rt.userId, rt.refreshToken, uriInfo.getBaseUri().getHost());
        LoginData loginData = new LoginData(loginSession);
        String refreshTokenCookieValue = String.format(
                "refresh_token=%s; Path=/; Max-Age=%s; Secure; HttpOnly; SameSite=Strict",
                new RefreshTokenCookie(loginSession.refreshToken).getCookieValue(),
                refreshTokenTtl);
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(loginData)
                .header("Set-Cookie", refreshTokenCookieValue)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("/organisations/{oid}/users/{uid}/apikeys")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Create an API Key"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ApiKey.class))),
            @ApiResponse(responseCode = "400", description = "Bad request.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response createApiKey(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @Parameter(name = "apiKeyDef", required = true)
            @NotNull @Valid ApiKeyDef keyDef
    ) throws NotFoundException, NotAllowedException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createApiKey(getUser(headers), UUID.fromString(uid), UUID.fromString(oid), keyDef.name, keyDef.ttlInDays, keyDef.roleIds))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "users", String.format("create-api-key (name=%s)", keyDef.name));
        return response;
    }

    @Timed
    @Path("/organisations/{oid}/users/{uid}/apikeys/{kid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete an API Key"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "400", description = "Non matching passwords.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deleteApiKey(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @Parameter(name = "kid", required = true)
            @PathParam(value = "kid") String kid
    ) throws NotFoundException, NotAllowedException {
        authService.deleteApiKey(getUser(headers), UUID.fromString(uid), UUID.fromString(oid), UUID.fromString(kid));
        logUAM(request, headers,  "users", String.format("delete-api-key (id=%s)", kid));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("Api key deleted."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();

    }

    @Timed
    @Path("users")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "Create a user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response createUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "userDef", required = true)
            @NotNull @Valid NewUserDef userDef
    ) throws AlreadyExistsException, InvalidEmailException, SendEmailException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.createUser(userDef.email, userDef.locale, userDef.timezone)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "users", String.format("create-user-account (email=%s)", userDef.email));
        return response;
    }

    @Timed
    @Path("users/resetpassword")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "Request a password modification if forgotten (send email with link)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "400", description = "Bad request.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response askPasswordReset(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "email", required = true)
            @NotNull @Valid String email
    ) throws SendEmailException {
        authService.askPasswordReset(email);
        logUAM(request, headers,  "users", "ask-password-reset");
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("ok"))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("users/{id}/reset/{token}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "Reset user password (through link received by email)"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "412", description = "Verification token expired. A new one is sent.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response resetUserPassword(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id,

            @Parameter(name = "token", required = true)
            @PathParam(value = "token") String token,

            @Parameter(name = "password", required = true)
            @NotNull @Valid String password
    ) throws SendEmailException, NotFoundException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.resetUserPassword(UUID.fromString(id), token, password)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "users", "password-reset");
        return response;
    }

    @Timed
    @Path("users/{id}/verify/{token}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            summary = "Verify a user (through link received by email)"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "412", description = "Verification token expired. A new one is sent.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response verifyUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id,

            @Parameter(name = "token", required = true)
            @PathParam(value = "token") String token,

            @Parameter(name = "password", required = true)
            @NotNull @Valid String password
    ) throws NonMatchingPasswordException, AlreadyVerifiedException, InvalidTokenException, SendEmailException, NotFoundException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.verifyUser(UUID.fromString(id), token, password)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "users", "verify-user-account");
        return response;
    }

    @Timed
    @Path("users/{id}")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Read a user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response readUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotFoundException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(getUser(headers, id)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("users/{id}/activate")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Activate the given user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response activateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id
    ) {
        authService.activateUser(UUID.fromString(id));
        logUAM(request, headers,  "users", "activate-user-account");
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("User activated."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();

    }

    @Timed
    @Path("users/{id}/deactivate")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Deactivate the given user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deactivateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotAllowedException {
        authService.deactivateUser(UUID.fromString(id));
        logUAM(request, headers,  "users", "deactivate-user-account");
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("User deactivated."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();

    }

    @Timed
    @Path("users/{id}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete the given user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deleteUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id
    ) throws NotFoundException, NotAllowedException {
        authService.deleteUser(getUser(headers).getId(), UUID.fromString(id));
        logUAM(request, headers,  "users", "delete-user-account");
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("User deleted."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();

    }

    @Timed
    @Path("users/{id}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update the given user (absent attribute - null - are not updated)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Non matching passwords.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updateUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,


            @Parameter(name = "id", required = true)
            @PathParam(value = "id") String id,

            @Parameter(name = "updateDef", required = true)
            @NotNull @Valid UpdateUserDef ud

    ) throws NotFoundException, NonMatchingPasswordException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.updateUser(getUser(headers, id, false), ud.oldPassword, ud.newPassword, ud.firstName, ud.lastName, ud.locale, ud.timezone)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "users", "update-user");
        return response;
    }

    // --------------- Organisations ---------------------
    @Timed
    @Path("organisations")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Create an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = OrgData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response createOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenOrganisationNameException {
        OrgData data = new OrgData(authService.createOrganisation(getUser(headers)));
        logUAM(request, headers,  data.id.toString(), "organisations", "create-domain-organisation");
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(data)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{name}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Create an organisation with a name. Only for IAM admin."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = OrgData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response createOrganisationWithName(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,
            @Parameter(name = "name", required = true)
            @PathParam(value = "name") String name
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenOrganisationNameException, InvalidParameterException {
        if(name.contains("@")){
            throw new InvalidParameterException("An organisation name must not contain the @ character");
        }
        OrgData data = new OrgData(authService.createOrganisation(getUser(headers), name));
        logUAM(request, headers,  data.id.toString(), "organisations", String.format("create-custom-organisation (name=%s)", name));
        return Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(data)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deleteOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException, ForbiddenActionException {
        authService.deleteOrganisation(getUser(headers), UUID.fromString(oid));
        logUAM(request, headers,  oid, "organisations", "delete-organisation");
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("organisation deleted"))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/check")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Check if user's organisation exists"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = OrgExists.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List organisations of the logged in user"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserOrgData.class)))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List users of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = MemberData.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getUsers(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rname")
            @QueryParam(value = "rname") String rname
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listOrganisationUsers(getUser(headers), UUID.fromString(oid), rname)
                        .stream()
                        .filter(om -> !om.isAdmin())
                        .map(MemberData::new)
                        .sorted()
                        .toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/emails")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List users of same domain than the organisation but not invited yet."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = String.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getEmails(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Get a user of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = MemberData.class))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getUser(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException {
        Optional<OrganisationMember> u = authService.listOrganisationUsers(getUser(headers), UUID.fromString(oid), null)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a user to an organisation. User account will be created if needed."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = OrgData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addUserToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "user", required = true)
            @NotNull @Valid OrgUserDef user
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException, SendEmailException, InvalidEmailException, NotAllowedException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.addUserToOrganisation(getUser(headers), user.email, UUID.fromString(oid), user.rids)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-user (email=%s)", user.email));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Remove a user from an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = OrgData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response removeUserFromOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid
    ) throws NotFoundException, NotOwnerException, NotAllowedException {
        Response response = Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new OrgData(authService.removeUserFromOrganisation(getUser(headers), UUID.fromString(uid), UUID.fromString(oid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("remove-user (uid=%s)", uid));
        return response;
    }

    // ------------- forbidden organisations --------------

    @Timed
    @Path("organisations/forbidden")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a name to the forbidden organisations list."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation.",
                    content = @Content(schema = @Schema(implementation = ForbiddenOrganisation.class))),
            @ApiResponse(responseCode = "400", description = "Not allowed.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addForbiddenOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "forbiddenOrganisation", required = true)
            @NotNull @Valid ForbiddenOrganisation forbiddenOrganisation
    ) throws AlreadyExistsException, NotFoundException, NotAllowedException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(authService.addForbiddenOrganisation(getUser(headers), forbiddenOrganisation))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  "stoplist", String.format("add-forbidden-name (name=%s)", forbiddenOrganisation.name));
        return response;
    }

    @Timed
    @Path("organisations/forbidden/{name}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Remove a name from the forbidden organisations list."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation.",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "400", description = "Not allowed.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Name not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response removeNameFromForbiddenOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "name", required = true)
            @PathParam(value = "name") String name
    ) throws NotFoundException, NotAllowedException {
        authService.removeForbiddenOrganisation(getUser(headers), name);
        logUAM(request, headers,  "stoplist", String.format("remove-forbidden-name (name=%s)", name));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("ok"))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/forbidden")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List forbidden organisations."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = ForbiddenOrganisation.class)))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List collections of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = String.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getOrganisationCollections(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a role to an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addRoleToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.createRole(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-role (name=%s)", roleDef.name));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update a role in an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or role not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updateRoleInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @Parameter(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        Response response = Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updateRole(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid), UUID.fromString(rid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("update-role (rid=%s, new-name=%s)", rid, roleDef.name));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/roles")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List roles of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RoleData.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getRolesOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.listRoles(getUser(headers), UUID.fromString(oid))
                        .stream()
                        .filter(r -> r.getName().startsWith("role/arlas/"))
                        .map(RoleData::new)
                        .sorted().toList())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List roles of a user within an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RoleData.class)))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getRoles(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Modify roles of a user within an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response putRoles(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @Parameter(name = "ridList", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a role to a user in an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addRoleToUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.addRoleToUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)), false))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-role-to-user (uid=%s, rid=%s)", uid, rid));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/users/{uid}/roles/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Remove a role from a user from an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = UserData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response removeRoleFromUserInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
            @PathParam(value = "uid") String uid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException, NotAllowedException, ForbiddenActionException {
        Response response = Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new UserData(authService.removeRoleFromUser(getUser(headers), UUID.fromString(oid), UUID.fromString(uid), UUID.fromString(rid)), false))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("remove-role-from-user (uid=%s, rid=%s)", uid, rid));
        return response;
    }

    //----------------- groups -------------------

    @Timed
    @Path("organisations/{oid}/groups")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a group to an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addGroupToOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "roleDef", required = true)
            @NotNull @Valid RoleDef groupDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.createGroup(getUser(headers), groupDef.name, groupDef.description, UUID.fromString(oid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-group (name=%s)", groupDef.name));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/groups/{rid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update a role's group in an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or role not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updateGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @Parameter(name = "roleDef", required = true)
            @NotNull @Valid RoleDef roleDef
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException, ForbiddenActionException {
        Response response = Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updateGroup(getUser(headers), roleDef.name, roleDef.description, UUID.fromString(oid), UUID.fromString(rid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("update-group (rid=%s, new-name=%s)", rid, roleDef.name));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/groups/{rid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete a group from an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or role not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deleteGroupInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid

    ) throws NotFoundException, NotOwnerException, NotAllowedException {
        authService.deleteGroup(getUser(headers), UUID.fromString(oid), UUID.fromString(rid));
        logUAM(request, headers,  oid, "organisations", String.format("delete-group (rid=%s)", rid));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("Group deleted."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/groups")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List groups of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RoleData.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getGroupsOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List groups of a user within an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = RoleData.class)))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getGroups(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List permissions of a user within an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PermissionData.class)))),
            @ApiResponse(responseCode = "400", description = "Bad request",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "User or organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getPermissions(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "uid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List permissions of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PermissionData.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getPermissionsOfOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a permission"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = PermissionData.class))),
            @ApiResponse(responseCode = "400", description = "Permission already exists.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "permission", required = true)
            @NotNull @Valid PermissionDef permission
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.createPermission(getUser(headers), UUID.fromString(oid), permission.value, permission.description)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-permission (permission=%s)", permission.value));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/permissions/columnfilter/{pid}")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List collections of a column filter of an organisation"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = String.class)))),
            @ApiResponse(responseCode = "404", description = "Organisation not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getCollectionsOfColumnFiltersInOrganisation(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.getCollectionsOfColumnFilter(getUser(headers), UUID.fromString(oid), UUID.fromString(pid), headers.getHeaderString(HttpHeaders.AUTHORIZATION)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions/columnfilter")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add column filter permission for the given collections."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = PermissionData.class))),
            @ApiResponse(responseCode = "400", description = "Permission already exists.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addColumnFilterPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "collections", required = true)
            @NotNull @Valid List<String> collections
    ) throws ArlasException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.createColumnFilter(getUser(headers),
                        UUID.fromString(oid), collections, headers.getHeaderString(HttpHeaders.AUTHORIZATION))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-columnfilter (collections=%s)", collections));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/permissions/{pid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update a permission"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = PermissionData.class))),
            @ApiResponse(responseCode = "400", description = "Permission already exists.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or permission not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updatePermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @Parameter(name = "permission", required = true)
            @NotNull @Valid PermissionDef permission
    ) throws NotFoundException, NotOwnerException, AlreadyExistsException {
        Response response = Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.updatePermission(getUser(headers), UUID.fromString(oid), UUID.fromString(pid), permission.value, permission.description)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("update-permission (pid=%s, new-value=%s)", pid, permission.value));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/permissions/{pid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Delete a permission"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = ArlasMessage.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or permission not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response deletePermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid

    ) throws NotFoundException, NotOwnerException, NotAllowedException {
        authService.deletePermission(getUser(headers), UUID.fromString(oid), UUID.fromString(pid));
        logUAM(request, headers,  oid, "organisations", String.format("delete-permission (pid=%s)", pid));
        return Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new ArlasMessage("Permission deleted."))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Timed
    @Path("organisations/{oid}/permissions/columnfilter/{pid}")
    @PUT
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update a column filter permission."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = PermissionData.class))),
            @ApiResponse(responseCode = "400", description = "Permission already exists.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "404", description = "Organisation or permission not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updateColumnFilterPermission(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid,

            @Parameter(name = "collections", required = true)
            @NotNull @Valid List<String> collections
    ) throws ArlasException {
        Response response = Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(new PermissionData(authService.updateColumnFilter(getUser(headers),
                        UUID.fromString(oid), UUID.fromString(pid), collections,
                        headers.getHeaderString(HttpHeaders.AUTHORIZATION))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("update-columnfilter (pid=%s, new-collections=%s)", pid, collections));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "List permissions of a role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = PermissionData.class)))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response listPermissionOfRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid
    ) throws NotFoundException, NotOwnerException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
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
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Update permissions of a role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response updatePermissionOfRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @Parameter(name = "pidList", required = true)
            @NotNull @Valid UpdateListDef pidList

    ) throws NotFoundException, NotOwnerException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.updatePermissionsOfRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), pidList.ids)))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("update-role-permissions (rid=%s, new-permissions=%s)", rid, pidList.ids));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions/{pid}")
    @POST
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Add a permission to a role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response addPermissionToRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid
    ) throws NotFoundException, NotOwnerException {
        Response response = Response.created(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.addPermissionToRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(pid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("add-permission-to-role (rid=%s, pid=%s)", rid, pid));
        return response;
    }

    @Timed
    @Path("organisations/{oid}/roles/{rid}/permissions/{pid}")
    @DELETE
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Remove a permission from a role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = RoleData.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork
    public Response removePermissionFromRole(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,
            @Context HttpServletRequest request,

            @Parameter(name = "oid", required = true)
            @PathParam(value = "oid") String oid,

            @Parameter(name = "rid", required = true)
            @PathParam(value = "rid") String rid,

            @Parameter(name = "pid", required = true)
            @PathParam(value = "pid") String pid
    ) throws NotFoundException, NotOwnerException {
        Response response = Response.accepted(uriInfo.getRequestUriBuilder().build())
                .entity(new RoleData(authService.removePermissionFromRole(getUser(headers), UUID.fromString(oid), UUID.fromString(rid), UUID.fromString(pid))))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        logUAM(request, headers,  oid, "organisations", String.format("remove-permission-from-role (rid=%s, pid=%s)", rid, pid));
        return response;
    }

    @Timed
    @Path("permissions")
    @GET
    @Produces(UTF8JSON)
    @Consumes(UTF8JSON)
    @Operation(
            security = @SecurityRequirement(name = "JWT"),
            summary = "Get permissions for a user given access token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = String.class))),
            @ApiResponse(responseCode = "404", description = "User not found.",
                    content = @Content(schema = @Schema(implementation = Error.class))),
            @ApiResponse(responseCode = "500", description = "Arlas Error.",
                    content = @Content(schema = @Schema(implementation = Error.class)))})

    @UnitOfWork(readOnly = true)
    public Response getPermissionToken(
            @Context UriInfo uriInfo,
            @Context HttpHeaders headers,

            @Parameter(name = ServerConstants.ARLAS_ORG_FILTER)
            @QueryParam(value = ServerConstants.ARLAS_ORG_FILTER) String orgFilter
    ) throws ArlasException {
        return Response.ok(uriInfo.getRequestUriBuilder().build())
                .entity(authService.createPermissionToken(headers, orgFilter))
                .type(MediaType.APPLICATION_JSON_TYPE)
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
        return getUser(headers, id, true);
    }

    protected User getUser(HttpHeaders headers, String id, boolean checkSame) throws NotFoundException {
        if (checkSame) { checkLoggedInUser(headers, id); }
        return getUser(headers);
    }

    protected IdentityParam getIdentityParam(HttpHeaders headers) {
        return new IdentityParam(configuration, headers);
    }
}
