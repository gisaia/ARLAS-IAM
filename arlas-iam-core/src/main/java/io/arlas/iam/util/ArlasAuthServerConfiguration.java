package io.arlas.iam.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.commons.config.ArlasConfiguration;
import io.dropwizard.db.DataSourceFactory;

import javax.validation.Valid;

public class ArlasAuthServerConfiguration extends ArlasConfiguration {
    @Valid
    @JsonProperty("database")
    public DataSourceFactory database = new DataSourceFactory();

    @Valid
    @JsonProperty("smtp")
    public final SMTPConfiguration smtp = new SMTPConfiguration();

    @JsonProperty("verify_email")
    public boolean verifyEmail;

    @JsonProperty("create_private_org")
    public boolean createPrivateOrg;

    @JsonProperty("api_key_max_ttl")
    public int apiKeyMaxTtl;

    @JsonProperty("arlas_server_base_path")
    public String arlasServerBasePath;
}
