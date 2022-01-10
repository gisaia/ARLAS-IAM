package io.arlas.auth.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class IllegalArgumentExceptionMapper implements ExceptionMapper<IllegalArgumentException> {
    private Logger logger;

    public IllegalArgumentExceptionMapper() {
        logger = LoggerFactory.getLogger(IllegalArgumentExceptionMapper.class);
    }

    @Override
    public Response toResponse(IllegalArgumentException e) {
        logger.warn(e.getMessage());
        return ArlasAuthException.getResponse(e, Response.Status.BAD_REQUEST, e.getMessage());
    }
}
