package io.arlas.iam.util;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotNull;

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

    @JsonProperty("verify_link")
    public String verifyLink;

    @JsonProperty("reset_link")
    public String resetLink;

    @JsonProperty("template_dir")
    public String templateDir;

    @JsonProperty("verify_template_file")
    public String verifyTemplateFile;

    @JsonProperty("reset_template_file")
    public String resetTemplateFile;
}
