package io.arlas.auth.test;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.util.Optional;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthITUser {
    public static final String USER1 = "u1@foo.com";
    public static final String USER2 = "u2@foo.com";
    public static final String ORG = "foo";
    public static final String GRP1 = "fooGroup1";
    public static final String ROLE1 = "fooRole1";
    public static final String ROLE2 = "fooRole2";
    public static final String SYS_PERMISSION1 = "sysPerm1";
    public static final String SYS_PERMISSION2 = "sysPerm2";
    public static final String PERMISSIONS = """
                {"permissions":["p1"]}
                """;

    protected static String arlasAppPath;
    protected static final String userHeader;
    protected static String userId1;
    protected static String userId2;
    protected static String orgId;
    protected static String fooGroupId1;
    protected static String fooRoleId1;
    protected static String fooRoleId2;
    protected static String permissionId1;
    protected static String permissionId2;

    static {
        userHeader = Optional.ofNullable(System.getenv("ARLAS_USER_HEADER")).orElse("arlas-user");

        String arlasHost = Optional.ofNullable(System.getenv("ARLAS_AUTH_HOST")).orElse("localhost");
        int arlasPort = Integer.parseInt(Optional.ofNullable(System.getenv("ARLAS_AUTH_PORT")).orElse("9997"));
        RestAssured.baseURI = "http://" + arlasHost;
        RestAssured.port = arlasPort;
        RestAssured.basePath = "";
        String arlasPrefix = Optional.ofNullable(System.getenv("ARLAS_AUTH_PREFIX")).orElse("/arlas_auth_server");
        arlasAppPath = Optional.ofNullable(System.getenv("ARLAS_AUTH_APP_PATH")).orElse("/");
        if (arlasAppPath.endsWith("/")) arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        arlasAppPath = arlasAppPath + arlasPrefix;
        if (arlasAppPath.endsWith("//")) arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        if (!arlasAppPath.endsWith("/")) arlasAppPath = arlasAppPath + "/auth/";
    }

    @Test
    public void test01CreateUser() {
        userId1 = createUser(USER1).then().statusCode(201)
                .body("email", equalTo(USER1))
                .extract().jsonPath().get("id");
        userId2 = createUser(USER2).then().statusCode(201)
                .body("email", equalTo(USER2))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test02CreateUserAlreadyExisting() {
        createUser(USER1).then().statusCode(400);
    }

    @Test
    public void test03CreateUserInvalidEmail() {
         createUser("u1@foo").then().statusCode(400);
    }

    // TODO: find a way to read the verification email and extract the token
//    @Test
//    public void test04VerifyUser() {
//        given()
//                .contentType("application/json")
//                .pathParam("id", userId1)
//                .body("password1")
//                .post(arlasAppPath.concat("users/{id}/verify"))
//                .then().statusCode(201)
//                .body("email", equalTo(USER1))
//                .body("verified", equalTo(true));
//
//        given()
//                .contentType("application/json")
//                .pathParam("id", userId2)
//                .body("password2")
//                .post(arlasAppPath.concat("users/{id}/verify"))
//                .then().statusCode(201)
//                .body("email", equalTo(USER2))
//                .body("verified", equalTo(true));
//    }

    @Test
    public void test05GetUserSelf() {
        getUser(userId1).then().statusCode(200).body("email", equalTo(USER1));
    }

    @Test
    public void test06GetUserNotSelf() {
        getUser(userId2).then().statusCode(404);
    }

    @Test
    public void test07GetUserNotFound() {
        getUser("unknownId").then().statusCode(404);
    }

    @Test
    public void test08UpdateUserSelf() {
        updateUser(userId1, "password1", "newpassword1").then().statusCode(201);
        // trick to check that the password has been changed:
        updateUser(userId1, "newpassword1", "password1").then().statusCode(201);
    }

    @Test
    public void test09UpdateUserNotSelf() {
        updateUser(userId2, "password2", "newpassword2").then().statusCode(404);
    }

    @Test
    public void test10CreateOrganisation() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(0));

        orgId = createOrganisation(userId1).then().statusCode(201)
                .body("name", equalTo(ORG))
                .body("members", hasSize(1))
                .body("members[0].owner", equalTo(true))
                .body("members[0].user.email", equalTo(USER1))
                .extract().jsonPath().get("id");

        getUser(userId1).then().statusCode(200)
                .body("organisations", hasSize(1))
                .body("organisations[0].organisation.name", equalTo(ORG));
    }

    @Test
    public void test11ListUsers() {
        listUsers(userId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].id", equalTo(userId1));
    }

    @Test
    public void test11ListOrganisations() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].name", equalTo(ORG))
                .body("[0].members", hasSize(1))
                .body("[0].members[0].owner", equalTo(true))
                .body("[0].members[0].user.email", equalTo(USER1));
    }

    @Test
    public void test12CreateExistingOrganisation() {
        createOrganisation(userId1).then().statusCode(400);
        createOrganisation(userId2).then().statusCode(400);
    }

    @Test
    public void test13DeleteOrganisationNotOwner() {
        deleteOrganisation(userId2).then().statusCode(400);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(1));
    }

    @Test
    public void test14AddUserToOrganisation() {
        addUserToOrganisation(userId1, USER2).then().statusCode(201);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(1))
                .body("organisations[0].organisation.name", equalTo(ORG))
                .body("organisations[0].organisation.members", hasSize(2));
    }

    @Test
    public void test15ListUsers() {
        listUsers(userId1).then().statusCode(200)
                .body("", hasSize(2));
    }

    @Test
    public void test15AddGroupToOrganisation() {
        fooGroupId1 = createGroup(userId1,GRP1).then().statusCode(201)
                .body("name", equalTo(GRP1))
                .body("organisation.name", equalTo(ORG))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test16AddExistingGroupToOrganisation() {
        createGroup(userId1, GRP1).then().statusCode(400);
    }

    @Test
    public void test17AddGroupToOrganisationNotOwned() {
        createGroup(userId2, "fooGroup2").then().statusCode(400);
    }

    @Test
    public void test18AddUserInGroup() {
        addUserInGroup(userId1, userId2).then().statusCode(201)
                .body("groups", hasSize(1))
                .body("groups[0]", equalTo(fooGroupId1));
    }

    @Test
    public void test19AddUserInGroupNotOwner() {
        addUserInGroup(userId2, userId1).then().statusCode(400);
    }

    @Test
    public void test20AddRoleToOrganisation() {
        fooRoleId1 = createRole(userId1, ROLE1, PERMISSIONS).then().statusCode(201)
                .body("name", equalTo(ROLE1))
                .body("organisations[0].name", equalTo(ORG))
                .extract().jsonPath().get("id");

        fooRoleId2 = createRole(userId1, ROLE2, PERMISSIONS).then().statusCode(201)
                .body("name", equalTo(ROLE2))
                .body("organisations[0].name", equalTo(ORG))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test21AddExistingRoleToOrganisation() {
        createRole(userId1, ROLE1, PERMISSIONS).then().statusCode(400);
    }

    @Test
    public void test22AddRoleToOrganisationNotOwned() {
        createRole(userId2, "role2", PERMISSIONS).then().statusCode(400);
    }

    @Test
    public void test23AddUserInRole() {
        addUserInRole(userId1, userId2, fooRoleId1).then().statusCode(201)
                .body("roles", hasSize(1))
                .body("roles[0]", equalTo(fooRoleId1));

        addUserInRole(userId1, userId2, fooRoleId2).then().statusCode(201)
                .body("roles", hasSize(2));
    }

    @Test
    public void test24AddUserInRoleNotOwned() {
        addUserInRole(userId2, userId1, fooRoleId1).then().statusCode(400);
    }

    @Test
    public void test30AddRoleInGroup() {
        addRoleInGroup(userId1, fooRoleId1).then().statusCode(201)
                .body("roles", hasSize(1))
                .body("roles[0]", equalTo(fooRoleId1));
        addRoleInGroup(userId1, fooRoleId2).then().statusCode(201)
                .body("roles", hasSize(2));
    }

    @Test
    public void test35AddSystemPermission() {
        permissionId1 = addSystemPermission(userId1, SYS_PERMISSION1).then().statusCode(201)
                .body("value", equalTo(SYS_PERMISSION1))
                .extract().jsonPath().get("id");
        permissionId2 = addSystemPermission(userId1, SYS_PERMISSION2).then().statusCode(201)
                .body("value", equalTo(SYS_PERMISSION2))
                .extract().jsonPath().get("id");
    }

    @Test
    public void test36AddPermissionToRole() {
        addPermissionToRole(userId1, fooRoleId1, permissionId1).then().statusCode(201)
                .body("permissions", hasSize(2));
    }

    @Test
    public void test37AddPermissionToUser() {
        addPermissionToUser(userId1, userId2, permissionId2).then().statusCode(201)
                .body("permissions", hasSize(1))
                .body("permissions[0].id", equalTo(permissionId2));
    }

    @Test
    public void test38ListPermissions() {
        listPermissions(userId1, userId2).then().statusCode(200)
                .body("", hasSize(3))
                .body("[0]", isOneOf("p1", SYS_PERMISSION1, SYS_PERMISSION2));
    }

    @Test
    public void test92DeleteNonEmptyRoleFromGroup() {
        deleteRoleFromGroup(userId1, fooRoleId1).then().statusCode(202)
                .body("roles", hasSize(1))
                .body("members", hasSize(1));
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(2))
                .body("groups", hasSize(1));
    }

    @Test
    public void test93DeleteUserFromRole() {
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(2));
        deleteUserFromRole(userId1, userId2, fooRoleId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(1));
    }

    @Test
    public void test94DeleteEmptyRoleFromGroup() {
        deleteRoleFromGroup(userId1, fooRoleId2).then().statusCode(202)
                .body("roles", hasSize(0));
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(1));
    }

    @Test
    public void test95DeleteUserFromGroup() {
        deleteUserFromGroup(userId1, userId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("groups", hasSize(0));
    }

    @Test
    public void test96DeleteUserFromOrganisation() {
        deleteUserFromOrganisation(userId1, userId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("organisations", hasSize(0));
    }

    @Test
    public void test97DeleteOrganisationAsOwner() {
        deleteOrganisation(userId1).then().statusCode(202);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(0));
        getUser(userId2, userId2).then().statusCode(200).body("groups", hasSize(0));
    }

    @Test
    public void test98DeleteUserNotSelf() {
        deleteUser(userId1, userId2).then().statusCode(404);
    }

    @Test
    public void test99DeleteUserSelf() {
        deleteUser(userId1, userId1).then().statusCode(202);
        deleteUser(userId2, userId2).then().statusCode(202);
    }

    // ----------------

    protected RequestSpecification givenForUser(String id) {
        return given().header(userHeader, id);
    }

    protected Response createUser(String email) {
        return given()
                .contentType("application/json")
                .body(email)
                .post(arlasAppPath.concat("users"));
    }

    protected Response getUser(String id) {
        return getUser(userId1, id);
    }

    protected Response getUser(String actingId, String id) {
        return givenForUser(actingId)
                .pathParam("id", id)
                .contentType("application/json")
                .get(arlasAppPath.concat("users/{id}"));
    }

    protected Response updateUser(String id, String p1, String p2) {
        return givenForUser(userId1)
                .pathParam("id", id)
                .body(String.format("""
                        {"oldPassword":"%s","newPassword":"%s"}
                        """, p1, p2))
                .contentType("application/json")
                .put(arlasAppPath.concat("users/{id}"));
    }

    protected Response deleteUser(String actingId, String targetId) {
        return givenForUser(actingId)
                .pathParam("id", targetId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("users/{id}"));
    }

    protected Response createOrganisation(String userId) {
        return givenForUser(userId)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations"));

    }

    protected Response listOrganisations(String userId) {
        return givenForUser(userId)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations"));

    }

    protected Response deleteOrganisation(String userId) {
        return givenForUser(userId)
                .pathParam("oid", orgId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}"));

    }

    protected Response addUserToOrganisation(String actingId, String email) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .contentType("application/json")
                .body(email)
                .post(arlasAppPath.concat("organisations/{oid}/users"));

    }

    protected Response deleteUserFromOrganisation(String actingId, String userId) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("uid", userId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/users/{uid}"));

    }

    protected Response createGroup(String actingId, String gname) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("gname", gname)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/groups/{gname}"));

    }

    protected Response addUserInGroup(String actingId, String uid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("gid", fooGroupId1)
                .pathParam("uid", uid)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/groups/{gid}/users/{uid}"));

    }

    protected Response deleteUserFromGroup(String actingId, String uid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("gid", fooGroupId1)
                .pathParam("uid", uid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/groups/{gid}/users/{uid}"));

    }

    protected Response createRole(String actingId, String rname, String permissions) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("rname", rname)
                .body(permissions)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/roles/{rname}"));
    }

    protected Response addUserInRole(String actingId, String uid, String rid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("rid", rid)
                .pathParam("uid", uid)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/roles/{rid}/users/{uid}"));
    }

    protected Response deleteUserFromRole(String actingId, String uid, String rid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("rid", rid)
                .pathParam("uid", uid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/roles/{rid}/users/{uid}"));
    }

    protected Response addRoleInGroup(String actingId, String rid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("gid", fooGroupId1)
                .pathParam("rid", rid)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/groups/{gid}/roles/{rid}"));
    }

    protected Response deleteRoleFromGroup(String actingId, String rid) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("gid", fooGroupId1)
                .pathParam("rid", rid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/groups/{gid}/roles/{rid}"));
    }

    protected Response listUsers(String userId) {
        return givenForUser(userId)
                .contentType("application/json")
                .get(arlasAppPath.concat("users"));

    }

    protected Response listPermissions(String actingId, String userId) {
        return givenForUser(actingId)
                .pathParam("oid", orgId)
                .pathParam("uid", userId)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/{oid}/users/{uid}/permissions"));
    }

    protected Response addSystemPermission(String actingId, String pvalue) {
        return givenForUser(actingId)
                .pathParam("pvalue", pvalue)
                .contentType("application/json")
                .post(arlasAppPath.concat("permissions/{pvalue}"));
    }

    protected Response addPermissionToUser(String actingId, String userId, String pid) {
        return givenForUser(actingId)
                .pathParam("pid", pid)
                .pathParam("uid", userId)
                .contentType("application/json")
                .post(arlasAppPath.concat("permissions/{pid}/users/{uid}"));
    }

    protected Response deletePermissionFromUser(String actingId, String userId, String pid) {
        return givenForUser(actingId)
                .pathParam("pid", pid)
                .pathParam("uid", userId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("permissions/{pid}/users/{uid}"));
    }

    protected Response addPermissionToRole(String actingId, String rid, String pid) {
        return givenForUser(actingId)
                .pathParam("pid", pid)
                .pathParam("rid", rid)
                .contentType("application/json")
                .post(arlasAppPath.concat("permissions/{pid}/roles/{rid}"));
    }

    protected Response deletePermissionFromRole(String actingId, String rid, String pid) {
        return givenForUser(actingId)
                .pathParam("pid", pid)
                .pathParam("rid", rid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("permissions/{pid}/roles/{rid}"));
    }

}
