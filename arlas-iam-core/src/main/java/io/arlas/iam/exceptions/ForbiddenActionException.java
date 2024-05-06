package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import jakarta.ws.rs.core.Response;

public class ForbiddenActionException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public ForbiddenActionException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public ForbiddenActionException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public ForbiddenActionException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
