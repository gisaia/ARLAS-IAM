package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class ForbiddenOrganisationNameException extends ArlasAuthException {
    private static final long serialVersionUID = 1L;

    public ForbiddenOrganisationNameException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public ForbiddenOrganisationNameException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public ForbiddenOrganisationNameException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
