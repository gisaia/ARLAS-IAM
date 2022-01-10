package io.arlas.auth.exceptions;

import io.arlas.auth.response.Error;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class ArlasAuthException extends Exception {
    private static final long serialVersionUID = 1L;

    protected Response.Status status = Response.Status.INTERNAL_SERVER_ERROR;

    public ArlasAuthException() {
    }

    public ArlasAuthException(String message) {
        super(message);
    }

    public ArlasAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    public Response getResponse() {
        return Response.status(status).entity(new Error(status.getStatusCode(), this.getClass().getName(), this.getMessage()))
                .type(MediaType.APPLICATION_JSON).build();
    }

    public static Response getResponse(Exception e, Response.Status status, String message) {
        return Response.status(status).entity(new Error(status.getStatusCode(), e.getClass().getName(), message))
                .type(MediaType.APPLICATION_JSON).build();
    }
}
