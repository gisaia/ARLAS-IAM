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

package io.arlas.iam.model;

import io.dropwizard.jackson.JsonSnakeCase;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Entity
@Table(name = "tokenSecret")
@JsonSnakeCase
public class TokenSecret {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @Column
    private byte[] secret;

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    private TokenSecret() {}

    public TokenSecret(byte[] secret){
        this.secret = secret;
    }

    public UUID getId() {
        return id;
    }

    private void setId(UUID id) {
        this.id = id;
    }

    public byte[] getSecret() {
        return secret;
    }

    private void setSecret(byte[] secret) {
        this.secret = secret;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }
}
