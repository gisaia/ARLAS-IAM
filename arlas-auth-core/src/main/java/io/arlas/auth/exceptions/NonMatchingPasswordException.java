package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class NonMatchingPasswordException extends ArlasAuthException {
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