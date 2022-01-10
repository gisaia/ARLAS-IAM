package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class NotFoundException extends ArlasAuthException {

    private static final long serialVersionUID = 1L;

    public NotFoundException() {
        super();
        status  = Response.Status.NOT_FOUND;
    }

    public NotFoundException(String message) {
        super(message);
        status  = Response.Status.NOT_FOUND;
    }

    public NotFoundException(String message, Throwable cause) {
        super(message, cause);
        status  = Response.Status.NOT_FOUND;
    }

}

