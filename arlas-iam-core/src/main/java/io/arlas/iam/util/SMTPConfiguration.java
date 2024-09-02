/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
