package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import javax.ws.rs.core.Response;

public class ExpiredTokenException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public ExpiredTokenException() {
        super();
        status = Response.Status.PRECONDITION_FAILED;
    }

    public ExpiredTokenException(String message) {
        super(message);
        status = Response.Status.PRECONDITION_FAILED;
    }

    public ExpiredTokenException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.PRECONDITION_FAILED;
    }
}