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

package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;

import java.util.UUID;

public class UserOrgData implements Comparable {
    public UUID id;
    public String name;
    public String displayName;
    public boolean isOwner;

    public UserOrgData(Organisation o, User u) {
        this.id = o.getId();
        this.name = o.getName();
        this.displayName = o.getDisplayName();
        this.isOwner = o.getMembers().stream()
                .filter(m -> m.getUser().is(u.getId()))
                .map(OrganisationMember::isOwner)
                .findFirst()
                .orElse(false);
    }

    @Override
    public int compareTo(Object o) {
        return name.compareTo(((UserOrgData) o).name);
    }
}
