package io.arlas.auth.rest;

import io.arlas.auth.core.AuthService;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;

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

    public AuthRestService(AuthService authService) {
        this.authService = authService;
    }


}
