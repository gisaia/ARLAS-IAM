package io.arlas.iam.util;


public class ArlasMessage {
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String message;
    public ArlasMessage(String message) {
        this.message = message;
    }
}
