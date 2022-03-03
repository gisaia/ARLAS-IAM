package io.arlas.ums.util;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotNull;

public class SMTPConfiguration {
    @NotNull
    @JsonProperty("activated")
    public boolean activated;

    @JsonProperty("host")
    public String host;

    @JsonProperty("port")
    public String port = "25";

    @JsonProperty("from")
    public String from;

    @JsonProperty("username")
    public String username;

    @JsonProperty("password")
    public String password;

    @JsonProperty("link")
    public String link;

    @JsonProperty("template_dir")
    public String templateDir;

    @JsonProperty("template_file")
    public String templateFile;
}
