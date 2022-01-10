package io.arlas.auth.exceptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;


@Provider
public class ArlasAuthExceptionMapper implements ExceptionMapper<ArlasAuthException> {
    private Logger logger;

    public ArlasAuthExceptionMapper() {
        logger = LoggerFactory.getLogger(ArlasAuthExceptionMapper.class);
    }

    @Override
    public Response toResponse(ArlasAuthException e) {
        logger.warn(e.getMessage());
        return e.getResponse();
    }
}
