package io.arlas.ums.exceptions;

import io.arlas.commons.exceptions.ArlasException;

import javax.ws.rs.core.Response;

public class AlreadyExistsException extends ArlasException {
    private static final long serialVersionUID = 1L;

    public AlreadyExistsException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public AlreadyExistsException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public AlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
