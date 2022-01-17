package io.arlas.auth.exceptions;

public class ArlasConfigurationException extends ArlasAuthException {
    private static final long serialVersionUID = 1L;

    public ArlasConfigurationException() {
        super();
    }

    public ArlasConfigurationException(String message) {
        super(message);
    }

    public ArlasConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
