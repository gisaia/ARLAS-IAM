package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import javax.ws.rs.core.Response;

public class ExpiredKeyException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public ExpiredKeyException() {
        super();
        status = Response.Status.UNAUTHORIZED;
    }

    public ExpiredKeyException(String message) {
        super(message);
        status = Response.Status.UNAUTHORIZED;
    }

    public ExpiredKeyException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.UNAUTHORIZED;
    }
}