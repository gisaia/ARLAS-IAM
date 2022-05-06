package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import javax.ws.rs.core.Response;

public class NonMatchingPasswordException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public NonMatchingPasswordException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public NonMatchingPasswordException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public NonMatchingPasswordException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}