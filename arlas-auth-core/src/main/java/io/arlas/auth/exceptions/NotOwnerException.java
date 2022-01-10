package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class NotOwnerException extends ArlasAuthException {
    private static final long serialVersionUID = 1L;

    public NotOwnerException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public NotOwnerException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public NotOwnerException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}

