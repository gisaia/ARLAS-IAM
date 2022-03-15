package io.arlas.ums.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.commons.config.ArlasCorsConfiguration;
import io.arlas.commons.exceptions.ArlasConfigurationException;
import io.arlas.ums.config.AuthConfiguration;
import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class ArlasAuthServerConfiguration extends Configuration {
    @JsonProperty("swagger")
    public SwaggerBundleConfiguration swaggerBundleConfiguration;

    @Valid
    @JsonProperty("database")
    public DataSourceFactory database = new DataSourceFactory();

    @Valid
    @JsonProperty("smtp")
    public SMTPConfiguration smtp = new SMTPConfiguration();

    @JsonProperty("verify_email")
    public boolean verifyEmail;

    @JsonProperty("arlas_auth")
    public AuthConfiguration authConf;

    @JsonProperty("arlas_cors")
    public ArlasCorsConfiguration arlasCorsConfiguration;

    @NotNull
    @JsonProperty("arlas_organization_header")
    public String organizationHeader;

    @JsonProperty("anonymous_value")
    public String anonymousValue;

    public void check() throws ArlasConfigurationException {
        if (swaggerBundleConfiguration == null) {
            throw new ArlasConfigurationException("Swagger configuration missing in config file.");
        }
        authConf.check();
        if (arlasCorsConfiguration == null) {
            arlasCorsConfiguration = new ArlasCorsConfiguration();
            arlasCorsConfiguration.enabled = false;
        }
    }
}
