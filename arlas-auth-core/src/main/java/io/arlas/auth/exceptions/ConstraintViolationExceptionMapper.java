package io.arlas.auth.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class ConstraintViolationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    public static final String errorMessage = "Invalid JSON parameter. All required fields in userSubscription are mandatory.";

    private Logger logger;

    public ConstraintViolationExceptionMapper() {
        logger = LoggerFactory.getLogger(ConstraintViolationExceptionMapper.class);
    }

    @Override
    public Response toResponse(ConstraintViolationException e) {
        logger.warn(errorMessage);
        return ArlasAuthException.getResponse(e, Response.Status.BAD_REQUEST, errorMessage);
    }
}