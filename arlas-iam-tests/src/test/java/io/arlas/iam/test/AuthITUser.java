package io.arlas.iam.test;

import io.restassured.path.json.JsonPath;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

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
        JsonPath json = login(USER1).then().statusCode(200).extract().jsonPath();
        token1 = json.get("accessToken");
        refreshToken1 = json.get("refreshToken.value");
        token2 = login(USER2).then().statusCode(200)
                .extract().jsonPath().get("accessToken");
    }

    @Test
    public void test011RefreshToken() {
        token1 = refreshToken(userId1, refreshToken1).then().statusCode(200)
                .extract().jsonPath().get("accessToken");
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
        changePassword(userId1, "secret", "newsecret").then().statusCode(201)
                .body("email", equalTo(USER1));

        logout(USER1).then().statusCode(200);

        token1 = login(USER1, "newsecret").then().statusCode(200)
                .extract().jsonPath().get("accessToken");

    }

    @Test
    public void test016ChangeWrongPassword() {
        changePassword(userId1, "othersecret", "newsecret").then().statusCode(400);
    }

    @Test
    public void test017ChangePasswordOtherUser() {
        updateUser(userId2, "password2", "newpassword2").then().statusCode(404);
    }

//    @Test
//    public void test018Logout() {
//        logout(userId1).then().statusCode(200);
//        getUser(userId1).then().statusCode(401);
//
//        token1 = login(USER1, refreshToken1).then().statusCode(200)
//                .extract().jsonPath().get("accessToken");
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
        deleteOrganisation(userId2).then().statusCode(400);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(2));
    }

    @Test
    public void test040ListUsers() {
        listUsers(userId1, null).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].member.email", is(USER1));
    }

    @Test
    public void test041AddUserToOrganisation() {
        addUserToOrganisation(userId1, USER2).then().statusCode(201);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(2));
        listUsers(userId1, null).then().statusCode(200)
                .body("", hasSize(2));
    }

    @Test
    public void test042GetUserFromOrganisationAsOwner() {
        getUserFromOrganisation(userId1, userId2).then().statusCode(200)
                .body("member.email", equalTo(USER2));
    }

    @Test
    public void test043GetUserFromOrganisationAsUser() {
        getUserFromOrganisation(userId2, userId1).then().statusCode(400);
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
        createRole(userId2, "whatever_role", "").then().statusCode(400);
    }

    @Test
    public void test053AddUserInRole() {
        addUserInRole(userId1, userId2, fooRoleId1).then().statusCode(201)
                .body("id", equalTo(userId2));

        addUserInRole(userId1, userId2, fooRoleId2).then().statusCode(201)
                .body("id", equalTo(userId2));
        // TODO check role list
    }

    @Test
    public void test054ListUsersWithRole() {
        listUsers(userId1, ROLE1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].member.email", is(USER2));
    }

    @Test
    public void test054AddUserInRoleNotOwned() {
        addUserInRole(userId2, userId1, fooRoleId1).then().statusCode(400);
    }

    @Test
    public void test060AddPermission() {
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
    }

    @Test
    public void test062ListUserPermissions() {
        listPermissions(userId1, userId2).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].value", is(oneOf(PERMISSION1, PERMISSION2, PERMISSION_GROUP)));
    }

    @Test
    public void test900DeleteUserFromRole() {
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(8)); // 2 created
        deleteUserFromRole(userId1, userId2, fooRoleId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(7));
    }

    @Test
    public void test901DeleteUserFromOrganisation() {
        deleteUserFromOrganisation(userId1, userId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(1));
    }

    @Test
    public void test902DeleteOrganisationAsOwner() {
        deleteOrganisation(userId1).then().statusCode(202);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(1));
    }

    @Test
    public void test903DeleteUserNotSelf() {
        deleteUser(userId1, userId2).then().statusCode(404);
    }

    @Test
    public void test904DeleteUserSelf() {
        deleteUser(userId1, userId1).then().statusCode(202);
        deleteUser(userId2, userId2).then().statusCode(202);
    }


}
