package io.arlas.iam.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.commons.config.ArlasConfiguration;

import javax.validation.Valid;

public class ArlasAuthServerConfiguration extends ArlasConfiguration {

    @Valid
    @JsonProperty("smtp")
    public final SMTPConfiguration smtp = new SMTPConfiguration();

    @JsonProperty("verify_email")
    public boolean verifyEmail;

    @JsonProperty("anonymous_value")
    public String anonymousValue;
}
