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

package io.arlas.auth.util;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.arlas.auth.exceptions.ArlasConfigurationException;
import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.HttpMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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

    @JsonProperty("arlas-base-uri")
    public String arlasBaseUri;

    //    @JsonProperty("arlas_cors")
//    public ArlasCorsConfiguration arlarsCorsConfiguration;

    @NotNull
    @JsonProperty("arlas_organization_header")
    public String organizationHeader;

    @NotNull
    @JsonProperty("header_user")
    public String headerUser;

    @NotNull
    @JsonProperty("header_group")
    public String headerGroup;

    @JsonProperty("anonymous_value")
    public String anonymousValue;

    @JsonProperty("public_uris")
    public List<String> publicUris;

    @JsonProperty("claim_roles")
    public String claimRoles;

    @JsonProperty("claim_permissions")
    public String claimPermissions;

    private String publicRegex;

    public String getPublicRegex()  {
        // [swagger.*:*, persist.*:GET/POST/DELETE}]
        if (this.publicRegex == null) {
            final String allMethods = ":" + String.join("/", Arrays.asList(HttpMethod.DELETE, HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.POST, HttpMethod.PUT));
            String pathToVerbs = Optional.ofNullable(this.publicUris)
                    .orElse(Collections.emptyList())
                    .stream()
                    .map(u -> !u.contains(":") ? u.concat(allMethods) : (u.endsWith(":*") ? u.replace(":*", allMethods) : u))
                    .flatMap(uri -> {
                        String path = uri.split(":")[0];
                        String verbs = uri.split(":")[1];
                        return Arrays.stream(verbs.split("/")).map(verb -> path.concat(":").concat(verb));
                    })
                    .collect(Collectors.joining("|"));
            this.publicRegex = "^(".concat(pathToVerbs).concat(")");
        }
        return this.publicRegex;
    }

    public void check() throws ArlasConfigurationException {
        if (swaggerBundleConfiguration == null) {
            throw new ArlasConfigurationException("Swagger configuration missing in config file.");
        }
//        if (arlasAuthConfiguration == null) {
//            arlasAuthConfiguration = new ArlasAuthConfiguration();
//            arlasAuthConfiguration.enabled = false;
//        } else {
//            arlasAuthConfiguration.check();
//        }
//        if (arlarsCorsConfiguration == null) {
//            arlarsCorsConfiguration = new ArlasCorsConfiguration();
//            arlarsCorsConfiguration.enabled = false;
//        }
    }
}
