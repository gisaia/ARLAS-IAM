package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class InvalidEmailException extends ArlasAuthException {
    private static final long serialVersionUID = 1L;

    public InvalidEmailException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public InvalidEmailException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public InvalidEmailException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
