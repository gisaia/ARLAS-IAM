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

package io.arlas.iam.test;

import io.restassured.path.json.JsonPath;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import io.restassured.response.ValidatableResponse;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthITUser extends AuthEndpoints {

    @Test
    public void test000CreateUser() {
        userId1 = createUser(USER1).then().statusCode(201)
                .body("email", equalTo(USER1))
                .extract().jsonPath().get("id");

        userId2 = createUser(USER2).then().statusCode(201)
                .body("email", equalTo(USER2))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test001CreateUserAlreadyExisting() {
        createUser(USER1).then().statusCode(400);
    }

    @Test
    public void test002CreateUserInvalidEmail() {
         createUser("u1foo").then().statusCode(400);
    }

    @Test
    public void test010Login() {
        ExtractableResponse<Response> response = login(USER1).then().statusCode(200).extract();
        JsonPath json = response.jsonPath();
        token1 = json.get("access_token");
        refreshToken1 = response.cookie("refresh_token");
        token2 = login(USER2).then().statusCode(200)
                .extract().jsonPath().get("access_token");
        tokenAdmin = login(ADMIN, ADMIN_PASSWORD).then().statusCode(200)
                .extract().jsonPath().get("access_token");
    }

    @Test
    public void test011RefreshToken() {
        token1 = refreshToken(refreshToken1).then().statusCode(200)
                .extract().jsonPath().get("access_token");
    }

    @Test
    public void test012LoginWithUnknownEmail() {
        login("u3@bar.com").then().statusCode(404);
    }

    @Test
    public void test013LoginWithInvalidPassword() {
        login(USER1, "notsecret").then().statusCode(404);
    }

    @Test
    public void test015ChangePassword() {
        changePassword(userId1, userId1, "secret", "newsecret").then().statusCode(201)
                .body("email", equalTo(USER1));

        logout(USER1).then().statusCode(200);

        refreshToken(refreshToken1).then().statusCode(401);

        token1 = login(USER1, "newsecret").then().statusCode(200)
                .extract().jsonPath().get("access_token");

    }

    @Test
    public void test016ChangeWrongPassword() {
        changePassword(userId1, userId1, "othersecret", "newsecret").then().statusCode(400);
    }

    @Test
    public void test018UpdateUser() {
        updateUser(userId1, "John", "Doe", "fr_FR", "Europe/London").then().statusCode(201)
                .body("firstName", equalTo("John"))
                .body("lastName", equalTo("Doe"))
                .body("locale", equalTo("fr_FR"))
                .body("timezone", equalTo("Europe/London"))
        ;
    }

//    @Test
//    public void test018Logout() {
//        logout(userId1).then().statusCode(200);
//        getUser(userId1).then().statusCode(401);
//
//        JsonPath json = login(USER1).then().statusCode(200).extract().jsonPath();
//        token1 = json.get("access_token");
//        refreshToken1 = json.get("refresh_token.value");
//    }

    @Test
    public void test020GetUserSelf() {
        getUser(userId1).then().statusCode(200).body("email", equalTo(USER1));
    }

    @Test
    public void test021GetUserNotSelf() {
        getUser(userId2).then().statusCode(404);
    }

    @Test
    public void test022GetUserNotFound() {
        getUser("unknownId").then().statusCode(404);
    }

    @Test
    public void test030CreateOwnDomainOrganisation() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(1));

        orgId = createOrganisation(userId1).then().statusCode(201)
                .body("name", equalTo(ORG))
                .body("displayName", equalTo(ORG_DISPLAY))
                .body("members", hasSize(1))
                .body("members[0].isOwner", equalTo(true))
                .body("members[0].member.email", is(USER1))
                .extract().jsonPath().get("id");

        getUser(userId1).then().statusCode(200)
                .body("organisations", hasSize(2))
                .body("organisations[1].name", equalTo(ORG));

        groupPublicId = listGroups().then().extract().jsonPath().get("[0].id");
    }

    @Test
    public void test031CreateExistingOrganisation() {
        createOrganisation(userId1).then().statusCode(400);
        createOrganisation(userId2).then().statusCode(400);
    }

    @Test
    public void test032ListOrganisations() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(2))
                .body("[1].name", equalTo(ORG));
    }

    @Test
    public void test033CheckOrganisation() {
        checkOrganisation(userId1).then().statusCode(200);
    }

    @Test
    public void test034DeleteOrganisationNotOwner() {
        deleteOrganisation(userId2).then().statusCode(403);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(2));
    }

    @Test
    public void test039ListUsersOfDomain() {
        listUsersOfDomain().then().statusCode(200)
                .body("", hasSize(1))
                .body("[0]", is(USER2));
    }

    @Test
    public void test040ListUsers() {
        listUsersOfOrganisation(userId1, null).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].member.email", is(USER1));
    }

    @Test
    public void test041AddUserToOrganisation() {
        addUserToOrganisation(userId1, USER2).then().statusCode(201);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(2));
        listUsersOfOrganisation(userId1, null).then().statusCode(200)
                .body("", hasSize(2));
    }

    @Test
    public void test042GetUserFromOrganisationAsOwner() {
        getUserFromOrganisation(userId1, userId2).then().statusCode(200)
                .body("member.email", equalTo(USER2));
    }

    @Test
    public void test043GetUserFromOrganisationAsUser() {
        getUserFromOrganisation(userId2, userId1).then().statusCode(403);
    }

    @Test
    public void test050AddRoleToOrganisation() {
        fooRoleId1 = createRole(userId1, ROLE1, ROLE1_DESC).then().statusCode(201)
                .body("name", equalTo(ROLE1))
                .body("description", equalTo(ROLE1_DESC))
                .extract().jsonPath().get("id");

        fooRoleId2 = createRole(userId1, ROLE2, ROLE2_DESC).then().statusCode(201)
                .body("name", equalTo(ROLE2))
                .body("description", equalTo(ROLE2_DESC))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test051AddExistingRoleToOrganisation() {
        createRole(userId1, ROLE1, ROLE1_DESC).then().statusCode(400);
    }

    @Test
    public void test052AddRoleToOrganisationNotOwned() {
        createRole(userId2, "whatever_role", "").then().statusCode(403);
    }

    @Test
    public void test053AddUserInRole() {
        addRoleToUser(userId1, userId2, fooRoleId1).then().statusCode(201)
                .body("id", equalTo(userId2));

        addRoleToUser(userId1, userId2, fooRoleId2).then().statusCode(201)
                .body("id", equalTo(userId2));
    }

    @Test
    public void test054ListUsersWithRole() {
        listUsersOfOrganisation(userId1, ROLE1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].member.email", is(USER2));
    }

    @Test
    public void test055AddUserInRoleNotOwned() {
        addRoleToUser(userId2, userId1, fooRoleId1).then().statusCode(403);
    }

    @Test
    public void test056AddRoleToUser() {
        updateRolesOfUser(userId1, userId2, fooRoleId1).then().statusCode(200)
                .body("id", equalTo(userId2));
    }

    @Test
    public void test057ListRolesOfUser() {
        listUserRoles(userId1, userId2).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test058ListRolesOfOrg() {
        // returns "role/arlas/..." only
        listOrgRoles().then().statusCode(200)
                .body("", hasSize(6));
    }

    @Test
    public void test059UpdateRole() {
        updateRole(userId1, fooRoleId1, ROLE1, ROLE1_DESC_UPDATED).then().statusCode(200)
                .body("description", equalTo(ROLE1_DESC_UPDATED));
    }

    @Test
    public void test060AddPermissions() {
        permissionId1 = addPermission(userId1, PERMISSION1, PERMISSION1_DESC).then().statusCode(201)
                .body("value", equalTo(PERMISSION1))
                .body("description", equalTo(PERMISSION1_DESC))
                .extract().jsonPath().get("id");
        permissionId2 = addPermission(userId1, PERMISSION2, PERMISSION2_DESC).then().statusCode(201)
                .body("value", equalTo(PERMISSION2))
                .body("description", equalTo(PERMISSION2_DESC))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test061AddPermissionToRole() {
        addPermissionToRole(userId1, fooRoleId1, permissionId1).then().statusCode(201);
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test062ListUserPermissions() {
        listPermissionsOfUser(userId1, userId2).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].value", is(oneOf(PERMISSION1, PERMISSION2, PERMISSION_GROUP)));
    }

    @Test
    public void test063ListOrgPermissions() {
        listPermissionsOfOrganisation().then().statusCode(200)
                .body("", hasSize(3));
    }

    @Test
    public void test064UpdatePermissions() {
        updatePermission(userId1, permissionId1, PERMISSION1, PERMISSION1_DESC_UPDATED).then().statusCode(200)
                .body("description", equalTo(PERMISSION1_DESC_UPDATED));
    }

    @Test
    public void test065ListPermissionsOfRole() {
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].value", equalTo(PERMISSION1));
    }

    @Test
    public void test066DeletePermissionsOfRole() {
        deletePermissionFromRole(userId1, fooRoleId1, permissionId1).then().statusCode(202);
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(0));
    }

    @Test
    public void test067UpdatePermissionsOfRole() {
        updatePermissionsOfRole(userId1, fooRoleId1, permissionId1).then().statusCode(201);
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test068DeletePermission() {
        String pid = addPermission(userId1, "pdelete", "permission to be deleted").then().statusCode(201)
                .body("value", equalTo("pdelete"))
                .body("description", equalTo("permission to be deleted"))
                .extract().jsonPath().get("id");
        addPermissionToRole(userId1, fooRoleId1, pid).then().statusCode(201);
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(2));
        deletePermission(userId1, pid).then().statusCode(202);
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test070AddGroup() {
        groupId1 = addGroup(userId1, GRP1, GRP1_DESC).then().statusCode(201)
                .body("name", equalTo(GRP1))
                .body("description", equalTo(GRP1_DESC))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test071UpdateGroup() {
        updateGroup(userId1, groupId1, GRP1, GRP1_DESC_UPDATED).then().statusCode(200)
                .body("name", equalTo(GRP1))
                .body("description", equalTo(GRP1_DESC_UPDATED));
    }

    @Test
    public void test072ListGroupsOfOrganisation() {
        listGroups().then().statusCode(200)
                .body("", hasSize(2));
    }

    @Test
    public void test073ListGroupsOfUser() {
        listGroups(userId1, userId2).then().statusCode(200)
                .body("", hasSize(0));
    }

    @Test
    public void test074AddGroupToUser() {
        addRoleToUser(userId1, userId2, groupId1).then().statusCode(201)
                .body("roles", hasSize(9));
        listGroups(userId1, userId2).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test075DeleteGroup() {
        String gid = addGroup(userId1, "gdelete", "group to be deleted").then().statusCode(201)
                .body("name", equalTo("gdelete"))
                .body("description", equalTo("group to be deleted"))
                .extract().jsonPath().get("id");
        addRoleToUser(userId1, userId2, gid).then().statusCode(201)
                .body("roles", hasSize(10));
        listGroups(userId1, userId2).then().statusCode(200)
                .body("", hasSize(2));
        deleteGroup(gid).then().statusCode(202);
        listGroups(userId1, userId2).then().statusCode(200)
                .body("", hasSize(1));
    }

    @Test
    public void test075DeleteTechnicalGroup() {
        deleteGroup(groupPublicId).then().statusCode(400);
    }

    @Test
    public void test081AddForbiddenOrg() {
        addForbiddenOrg("gisaia.com").then().statusCode(201)
                .body("name", equalTo("gisaia.com"));
    }

    @Test
    public void test082ListForbiddenOrg() {
        getForbiddenOrgs().then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].name", equalTo("gisaia.com"));
    }

    @Test
    public void test083CreateForbiddenOrg() {
        createOrganisationWithName("gisaia.com").then().statusCode(400);
    }

    @Test
    public void test084DeleteFromForbiddenOrg() {
        deleteForbiddenOrg("gisaia.com").then().statusCode(202);
    }

    @Test
    public void test085CreateOrgWithName() {
        String oid = createOrganisationWithName("gisaia.com").then().statusCode(201)
                .extract().jsonPath().get("id");
        deleteOrganisation("admin", oid, "gisaia.com").then().statusCode(202);
    }

    @Test
    public void test091CreateApiKey() {
        ValidatableResponse json = createApiKey(userId1, "apikey1", fooRoleId1, 1).then().statusCode(201);
        apiKeyUUID = json.extract().jsonPath().get("id");
        apiKeyId = json.extract().jsonPath().get("keyId");
        apiKeySecret = json.extract().jsonPath().get("keySecret");
    }

    @Test
    public void test092UseApiKeyForAuthorizedEndpoint() {
        given()
                .header(ARLAS_API_KEY_ID, apiKeyId)
                .header(ARLAS_API_KEY_SECRET, apiKeySecret)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations"))
                .then().statusCode(200)
                .body("", hasSize(2)); // owner org + foo.com
    }

    @Test
    public void test093UseApiKeyForUnauthorizedEndpoint() {
        given()
                .header(ARLAS_API_KEY_ID, apiKeyId)
                .header(ARLAS_API_KEY_SECRET, apiKeySecret)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/xxx"))
                .then().statusCode(403);
    }

    @Test
    public void test094DeleteApiKey() {
        deleteApiKey(userId1, apiKeyUUID).then().statusCode(202);
        // check that associated role is not removed:
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200);
    }

    // TODO: needs collections to be existing in ARLAS server to test these
//    @Test
//    public void test100CreateColumnFilter() {
//        cfId = createColumnFilter().then().statusCode(201)
//                .extract().jsonPath().get("id");
//    }
//
//    @Test
//    public void test101GetColumnFilter() {
//        getColumnFilter(cfId).then().statusCode(200)
//                .body("", hasSize(2))
//                .body("[0]", is(oneOf("collection1","collection2")))
//                .body("[1]", is(oneOf("collection1","collection2")));
//    }
//
//    @Test
//    public void test102UpdateColumnFilter() {
//        updateColumnFilter(cfId).then().statusCode(200)
//                .body("", hasSize(1))
//                .body("[0]", is("collection1"));
//    }

    @Test
    public void test900DeleteUserFromRole() {
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(9)); // 2 added: fooRole1 and fooGroup1
        deleteUserFromRole(userId1, userId2, fooRoleId1).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(8));
        // check that associated role is not removed:
        listPermissionsOfRole(userId1, fooRoleId1).then().statusCode(200);
    }

    @Test
    public void test901DeleteUserFromOrganisation() {
        deleteUserFromOrganisation(userId1, userId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(1));
        // check that org is not deleted
        listOrgRoles().then().statusCode(200);
        // check that user is not deleted
        getUser(userId2, userId2).then().statusCode(200);
    }

    @Test
    public void test902DeactivateUser() {
        deactivateUser(userId1, userId2).then().statusCode(202);
    }

    @Test
    public void test903ActivateUser() {
        activateUser(userId1, userId2).then().statusCode(202);
    }

    @Test
    public void test904DeleteUserNotSelf() {
        deleteUser(userId1, userId2).then().statusCode(400);
    }

    @Test
    public void test905DeleteUserSelf() {
        addUserToOrganisation(userId1, USER2).then().statusCode(201);
        listUsersOfOrganisation(userId1, null).then().statusCode(200)
                .body("", hasSize(2));
        deleteUser(userId2, userId2).then().statusCode(202);
        // check that org is not deleted
        listUsersOfOrganisation(userId1, null).then().statusCode(200)
                .body("", hasSize(1));
        // check that roles are not deleted
        listOrgRoles().then().statusCode(200)
                .body("", hasSize(6));

    }

    @Test
    public void test906DeleteOrganisationAsOwner() {
        deleteOrganisation(userId1).then().statusCode(202);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(1));
    }

    @Test
    public void test907DeleteUserSelf() {
        deleteUser(userId1, userId1).then().statusCode(202);
    }
}
