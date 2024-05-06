package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import jakarta.ws.rs.core.Response;

public class ForbiddenOrganisationNameException extends ArlasException {
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
