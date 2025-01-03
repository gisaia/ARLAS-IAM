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
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "organisation")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class Organisation {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NaturalId
    @Column
    private String name;

    @Column(name="display_name")
    private String displayName;

    @OneToMany(mappedBy = "pk.org", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private Set<OrganisationMember> members = new HashSet<>();

    @OneToMany(mappedBy="organisation", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private Set<Permission> permissions = new HashSet<>();

    @OneToMany(mappedBy="organisation", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private Set<Role> roles = new HashSet<>();

    private Organisation() {}

    public Organisation(String name) {
        this.setName(name);
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

    public boolean is(Organisation o) {
        return o != null && this.id.equals(o.getId());
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
        this.displayName = name.indexOf(".") != -1 ? name.substring(0, name.indexOf(".")) : name;
    }

    public Organisation setDisplayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Set<OrganisationMember> getMembers() {
        return members;
    }

    public void setMembers(Set<OrganisationMember> members) {
        this.members = members;
    }

    public boolean addMember(OrganisationMember organisationMember) {
        return this.members.add(organisationMember);
    }

    public boolean removeMember(OrganisationMember organisationMember) {
        return this.members.remove(organisationMember);
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void addRole(Role role) {
        this.roles.add(role);
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Organisation that = (Organisation) o;
        return getName().equals(that.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName());
    }

}
