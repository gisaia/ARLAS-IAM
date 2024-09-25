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
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "permission")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Permission {
    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NotNull
    @Column(columnDefinition = "TEXT")
    private String value;

    @Column
    private String description;

    @ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "RolePermission",
            joinColumns = @JoinColumn(name = "id_permission"),
            inverseJoinColumns = @JoinColumn(name = "id_role"))
    private Set<Role> roles = new HashSet<>();

    @ManyToOne
    @JoinColumn(name = "id_organisation")
    private Organisation organisation;

    private Permission() {}

    public Permission(String value, String description, Organisation org) {
        this.value = value;
        this.description = description;
        this.organisation = org;
    }

    public UUID getId() {
        return id;
    }

    private void setId(UUID id) {
        this.id = id;
    }

    public boolean is(UUID uuid) {
        return this.id.equals(uuid);
    }

    public String getValue() {
        return value;
    }

    public Permission setValue(String value) {
        this.value = value;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public Permission setDescription(String description) {
        this.description = description;
        return this;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
        role.getPermissions().remove(this);
    }

    public void addRole(Role role) {
        this.roles.add(role);
        role.getPermissions().add(this);
    }

    public Organisation getOrganisation() {
        return organisation;
    }

    public void setOrganisation(Organisation organisation) {
        this.organisation = organisation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Permission that = (Permission) o;
        return getValue().equals(that.getValue()) && Objects.equals(getOrganisation(), that.getOrganisation());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getValue(), getOrganisation());
    }

    @Override
    public String toString() {
        return "Permission{" +
                "value='" + value + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}
