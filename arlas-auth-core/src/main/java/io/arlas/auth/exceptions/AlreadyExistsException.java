package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class AlreadyExistsException extends ArlasAuthException {
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
