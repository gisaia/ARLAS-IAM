package io.arlas.ums.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.commons.config.ArlasConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class ArlasAuthServerConfiguration extends ArlasConfiguration {

    @Valid
    @JsonProperty("smtp")
    public final SMTPConfiguration smtp = new SMTPConfiguration();

    @JsonProperty("verify_email")
    public boolean verifyEmail;

    @NotNull
    @JsonProperty("arlas_organization_header")
    public String organizationHeader;

    @JsonProperty("anonymous_value")
    public String anonymousValue;
}
