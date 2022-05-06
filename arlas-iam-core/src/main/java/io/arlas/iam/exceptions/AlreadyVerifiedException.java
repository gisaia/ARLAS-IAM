package io.arlas.iam.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import javax.ws.rs.core.Response;

public class AlreadyVerifiedException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public AlreadyVerifiedException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public AlreadyVerifiedException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public AlreadyVerifiedException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
