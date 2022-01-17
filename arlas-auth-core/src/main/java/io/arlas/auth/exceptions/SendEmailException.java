package io.arlas.auth.exceptions;

import javax.ws.rs.core.Response;

public class SendEmailException extends ArlasAuthException {
    private static final long serialVersionUID = 1L;

    public SendEmailException() {
        super();
        status = Response.Status.BAD_REQUEST;
    }

    public SendEmailException(String message) {
        super(message);
        status = Response.Status.BAD_REQUEST;
    }

    public SendEmailException(String message, Throwable cause) {
        super(message, cause);
        status = Response.Status.BAD_REQUEST;
    }
}
