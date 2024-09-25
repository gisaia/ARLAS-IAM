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

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.dropwizard.jackson.JsonSnakeCase;
import jakarta.persistence.*;

@Entity
@Table(name = "organisationMember")
@JsonSnakeCase
public class OrganisationMember {

    @Id
    @JsonIgnore
    private OrganisationMemberPk pk;

    @Basic
    @Convert(converter = org.hibernate.type.NumericBooleanConverter.class)
    @Column(name="is_owner")
    private boolean isOwner;

    @Basic
    @Convert(converter = org.hibernate.type.NumericBooleanConverter.class)
    @Column(name="is_admin")
    private boolean isAdmin = false;

    private OrganisationMember() {}

    public OrganisationMember(User user, Organisation organisation, boolean isOwner) {
        this(user, organisation, isOwner, false);
    }

    public OrganisationMember(User user, Organisation organisation, boolean isOwner, boolean isAdmin) {
        this.pk = new OrganisationMemberPk(user, organisation);
        this.isOwner = isOwner;
        this.isAdmin = isAdmin;
    }

    public OrganisationMemberPk getPk() {
        return pk;
    }

    public void setPk(OrganisationMemberPk pk) {
        this.pk = pk;
    }

    public boolean isOwner() {
        return isOwner;
    }

    public void setOwner(boolean isOwner) {
        this.isOwner = isOwner;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean admin) {
        isAdmin = admin;
    }

    public User getUser() {
        return pk.getUser();
    }

    public void setUser(User user) {
        getPk().setUser(user);
    }

    public Organisation getOrganisation() {
        return pk.getOrganisation();
    }

    public void setOrganisation(Organisation organisation) {
        getPk().setOrganisation(organisation);
    }
}