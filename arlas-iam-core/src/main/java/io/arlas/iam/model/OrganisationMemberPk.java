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

import jakarta.persistence.CascadeType;
import jakarta.persistence.Embeddable;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import java.io.Serial;
import java.util.Objects;

@Embeddable
public class OrganisationMemberPk implements java.io.Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @ManyToOne(cascade= CascadeType.REMOVE)
    @JoinColumn(name = "id_user")
    private User user;

    @ManyToOne(cascade= CascadeType.REMOVE)
    @JoinColumn(name = "id_organisation")
    private Organisation org;

    private OrganisationMemberPk() {}

    public OrganisationMemberPk(User user, Organisation organisation) {
        this.user = user;
        this.org = organisation;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User u) {
        this.user = u;
    }

    public Organisation getOrganisation() {
        return org;
    }

    public void setOrganisation(Organisation o) {
        this.org = o;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OrganisationMemberPk that = (OrganisationMemberPk) o;
        return getUser().equals(that.getUser()) && org.equals(that.org);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUser(), org);
    }
}