package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import jakarta.ws.rs.core.Response;

public class InvalidTokenException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public InvalidTokenException() {
        super();
        status = Response.Status.UNAUTHORIZED;
    }

    public InvalidTokenException(String message) {
        super(message);
        status = Response.Status.UNAUTHORIZED;
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.UNAUTHORIZED;
    }
}