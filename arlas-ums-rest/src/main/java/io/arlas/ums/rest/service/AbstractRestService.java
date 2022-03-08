package io.arlas.ums.rest.service;

import io.arlas.commons.exceptions.NotFoundException;
import io.arlas.ums.core.AuthService;
import io.arlas.ums.model.User;
import io.arlas.ums.util.ArlasAuthServerConfiguration;
import io.arlas.ums.util.IdentityParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public abstract class AbstractRestService {
    Logger LOGGER = LoggerFactory.getLogger(AbstractRestService.class);
    public static final String UTF8JSON = MediaType.APPLICATION_JSON + ";charset=utf-8";

    protected final AuthService authService;
    protected final String userHeader;
    protected final String organizationHeader;
    protected final String groupsHeader;
    protected final String anonymousValue;

    protected AbstractRestService(AuthService authService, ArlasAuthServerConfiguration configuration) {
        this.authService = authService;
        this.userHeader = configuration.arlasAuthConfiguration.headerUser;
        this.organizationHeader = configuration.organizationHeader;
        this.groupsHeader = configuration.arlasAuthConfiguration.headerGroup;
        this.anonymousValue = configuration.anonymousValue;
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
