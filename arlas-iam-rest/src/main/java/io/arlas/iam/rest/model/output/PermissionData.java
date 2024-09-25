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

import io.arlas.iam.model.Permission;

import java.util.List;
import java.util.UUID;

public class PermissionData implements Comparable {
    public UUID id;
    public String value;
    public String description;
    public List<RoleData> roles;

    public PermissionData(Permission p) {
        this.id = p.getId();
        this.value = p.getValue();
        this.description = p.getDescription();
        this.roles = p.getRoles().stream().map(RoleData::new).toList();
    }

    @Override
    public int compareTo(Object o) {
        return value.compareTo(((PermissionData) o).value);
    }

}
