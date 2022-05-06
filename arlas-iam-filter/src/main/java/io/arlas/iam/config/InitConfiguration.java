package io.arlas.iam.config;

import com.fasterxml.jackson.annotation.JsonProperty;

public class InitConfiguration {
    @JsonProperty("admin")
    public String admin;
    @JsonProperty("password")
    public String password;
    @JsonProperty("timezone")
    public String timezone;
    @JsonProperty("locale")
    public String locale;
    @JsonProperty("organisation")
    public String organisation;
}
