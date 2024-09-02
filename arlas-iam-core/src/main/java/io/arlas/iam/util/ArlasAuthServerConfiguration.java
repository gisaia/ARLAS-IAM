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
import io.arlas.commons.config.ArlasConfiguration;
import io.dropwizard.db.DataSourceFactory;

import jakarta.validation.Valid;

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
