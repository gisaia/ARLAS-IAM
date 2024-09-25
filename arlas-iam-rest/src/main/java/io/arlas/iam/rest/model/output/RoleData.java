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

import io.arlas.iam.model.Role;

import java.util.UUID;

public class RoleData implements Comparable<RoleData> {
    public UUID id;
    public String name;

    public String fullName;
    public String description;
    public OrgData organisation;

    public boolean isGroup;
    public boolean isTechnical;

    public RoleData(Role r) {
        this.id = r.getId();
        this.isGroup = r.isGroup();
        this.name = isGroup ? r.getName().substring(r.getName().lastIndexOf("/")+1) : r.getName();
        this.fullName = r.getName();
        this.description = r.getDescription();
        this.isTechnical = r.isTechnical();
        if (r.getOrganisation().isPresent()) {
            this.organisation = new OrgData(r.getOrganisation().get(), false);
        }
    }

    @Override
    public int compareTo(RoleData o) {
        return name.compareTo(o.name);
    }
}
