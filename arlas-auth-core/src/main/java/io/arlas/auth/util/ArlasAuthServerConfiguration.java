package io.arlas.auth.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.auth.impl.ArlasPolicyEnforcer;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.config.ArlasCorsConfiguration;
import io.arlas.commons.exceptions.ArlasConfigurationException;
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

    @JsonProperty("access_token_ttl")
    public long accessTokenTTL;

    @JsonProperty("refresh_token_ttl")
    public long refreshTokenTTL;

    @JsonProperty("verify_email")
    public boolean verifyEmail;

    @JsonProperty("arlas-base-uri")
    public String arlasBaseUri;

    @JsonProperty("arlas_auth")
    public ArlasAuthConfiguration arlasAuthConfiguration;

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
        if (arlasAuthConfiguration == null) {
            arlasAuthConfiguration = new ArlasAuthConfiguration();
            arlasAuthConfiguration.policyClass = ArlasPolicyEnforcer.class.getCanonicalName();
        } else {
            arlasAuthConfiguration.check();
        }
        if (arlasCorsConfiguration == null) {
            arlasCorsConfiguration = new ArlasCorsConfiguration();
            arlasCorsConfiguration.enabled = false;
        }
    }
}
