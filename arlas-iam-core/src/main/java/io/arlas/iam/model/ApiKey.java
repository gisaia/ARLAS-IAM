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

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "apiKey")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class ApiKey {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @Column
    private String name;

    @NaturalId
    @Column
    private String keyId;

    @Column
    private String keySecret;

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private int ttlInDays;

    @ManyToOne
    @JoinColumn(name = "id_user")
    private User owner;

    @ManyToOne
    @JoinColumn(name = "id_org")
    private Organisation org;

    @ManyToMany(mappedBy="apiKeys")
    private Set<Role> roles = new HashSet<>();

    public ApiKey() {}

    public ApiKey(String name, String keyId, String keySecret, int ttlInDays, User owner, Organisation org, Set<Role> roles) {
        this.name = name;
        this.keyId = keyId;
        this.keySecret = keySecret;
        this.ttlInDays = ttlInDays;
        this.owner = owner;
        this.org = org;
        this.roles = roles;
    }

    @PreRemove
    private void removeRoleAssociations() {
        for (Role role : this.roles) {
            role.getApiKeys().remove(this);
        }
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getKeySecret() {
        return keySecret;
    }

    public void setKeySecret(String keySecret) {
        this.keySecret = keySecret;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public int getTtlInDays() {
        return ttlInDays;
    }

    public void setTtlInDays(int ttlInDays) {
        this.ttlInDays = ttlInDays;
    }

    public Organisation getOrg() {
        return org;
    }

    public void setOrg(Organisation org) {
        this.org = org;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApiKey apiKey = (ApiKey) o;
        return Objects.equals(getId(), apiKey.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId());
    }
}
