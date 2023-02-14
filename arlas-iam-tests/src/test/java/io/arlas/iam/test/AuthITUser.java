package io.arlas.iam.test;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.util.Optional;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthITUser {
    private static final String AUTH_HEADER = "authorization";
    private static final String ADMIN = "auth.arlas.cloud@gisaia.com";
    private static final String USER1 = "u1@foo.com";
    private static final String USER2 = "u2@foo.com";
    private static final String ORG = "foo.com";
    private static final String ORG_DISPLAY = "foo";
    private static final String ROLE1 = "fooRole1";
    private static final String ROLE1_DESC = "fooRole1 desc";
    private static final String ROLE2 = "fooRole2";
    private static final String ROLE2_DESC = "fooRole2_desc";
    private static final String PERMISSION1 = "p1";
    private static final String PERMISSION1_DESC = "p1_desc";
    private static final String PERMISSION2 = "p2";
    private static final String PERMISSION2_DESC = "p2_desc";
    private static final String PERMISSION_GROUP = "h:column-filter:*:*";

    protected static String arlasAppPath;
    protected static final String userHeader;
    protected static String userId1;
    protected static String userId2;
    protected static String orgId;
    protected static String fooRoleId1;
    protected static String fooRoleId2;
    protected static String permissionId1;
    protected static String permissionId2;
    protected static String token1;
    protected static String token2;

    static {
        userHeader = Optional.ofNullable(System.getenv("ARLAS_USER_HEADER")).orElse("arlas-user");

        String arlasHost = Optional.ofNullable(System.getenv("ARLAS_IAM_HOST")).orElse("localhost");
        int arlasPort = Integer.parseInt(Optional.ofNullable(System.getenv("ARLAS_IAM_PORT")).orElse("9997"));
        RestAssured.baseURI = "http://" + arlasHost;
        RestAssured.port = arlasPort;
        RestAssured.basePath = "";
        String arlasPrefix = Optional.ofNullable(System.getenv("ARLAS_IAM_PREFIX")).orElse("/arlas_iam_server");
        arlasAppPath = Optional.ofNullable(System.getenv("ARLAS_IAM_APP_PATH")).orElse("/");
        if (arlasAppPath.endsWith("/")) arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        arlasAppPath = arlasAppPath + arlasPrefix;
        if (arlasAppPath.endsWith("//")) arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        if (!arlasAppPath.endsWith("/")) arlasAppPath = arlasAppPath + "/";
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
         createUser("u1foo").then().statusCode(400);
    }

    @Test
    public void test04Login() {
        token1 = login(USER1).then().statusCode(200)
                .extract().jsonPath().get("accessToken");
        token2 = login(USER2).then().statusCode(200)
                .extract().jsonPath().get("accessToken");
    }

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
        updateUser(userId1, "secret", "newsecret").then().statusCode(201);
        // trick to check that the password has been changed:
        updateUser(userId1, "newsecret", "secret").then().statusCode(201);
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
                .body("displayName", equalTo(ORG_DISPLAY))
                .body("members", hasSize(1)) // admin + owner
                .body("members[0].isOwner", equalTo(true))
                .body("members[0].member.email", is(USER1))
                .extract().jsonPath().get("id");

        getUser(userId1).then().statusCode(200)
                .body("organisations", hasSize(1))
                .body("organisations[0].name", equalTo(ORG));
    }

    @Test
    public void test11ListUsers() {
        listUsers(userId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].member.email", is(USER1));
    }

    @Test
    public void test11ListOrganisations() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].name", equalTo(ORG));
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
                .body("organisations[0].name", equalTo(ORG));
    }

    @Test
    public void test15ListUsers() {
        listUsers(userId1).then().statusCode(200)
                .body("", hasSize(2));
    }

    @Test
    public void test20AddRoleToOrganisation() {
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
    public void test21AddExistingRoleToOrganisation() {
        createRole(userId1, ROLE1, ROLE1_DESC).then().statusCode(400);
    }

    @Test
    public void test22AddRoleToOrganisationNotOwned() {
        createRole(userId2, "whatever_role", "").then().statusCode(400);
    }

    @Test
    public void test23AddUserInRole() {
        addUserInRole(userId1, userId2, fooRoleId1).then().statusCode(201)
                .body("id", equalTo(userId2));

        addUserInRole(userId1, userId2, fooRoleId2).then().statusCode(201)
                .body("id", equalTo(userId2));
        // TODO check role list
    }

    @Test
    public void test24AddUserInRoleNotOwned() {
        addUserInRole(userId2, userId1, fooRoleId1).then().statusCode(400);
    }

    @Test
    public void test35AddPermission() {
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
    public void test36AddPermissionToRole() {
        addPermissionToRole(userId1, fooRoleId1, permissionId1).then().statusCode(201);
    }

    @Test
    public void test38ListPermissions() {
        listPermissions(userId1, userId2).then().statusCode(200)
                .body("", hasSize(2))
                .body("[0].value", is(oneOf(PERMISSION1, PERMISSION2, PERMISSION_GROUP)));
    }

    @Test
    public void test93DeleteUserFromRole() {
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(4)); // 2 automatic roles + 2 created
        deleteUserFromRole(userId1, userId2, fooRoleId2).then().statusCode(202);
        getUser(userId2, userId2).then().statusCode(200)
                .body("roles", hasSize(3));
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

//    protected RequestSpecification givenForUser(String id) {
//        return given().header(userHeader, id);
//    }

    protected Response createUser(String email) {
        return given()
                .contentType("application/json")
                .body(String.format("""
                        {"email": "%s", "locale": "fr", "timezone":"Europe/Paris"}
                        """, email))
                .post(arlasAppPath.concat("users"));
    }

    protected Response login(String email) {
        return given()
                .contentType("application/json")
                .body(String.format("""
                        {"email": "%s", "password": "secret"}
                        """, email))
                .post(arlasAppPath.concat("session"));
    }

    protected String getToken(String userId) {
        if (userId.equals(userId1)) {
            return "bearer " + token1;
        } else {
            return "bearer " + token2;
        }
    }

    protected Response getUser(String id) {
        return getUser(userId1, id);
    }

    protected Response getUser(String actingId, String id) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("id", id)
                .contentType("application/json")
                .get(arlasAppPath.concat("users/{id}"));
    }

    protected Response updateUser(String id, String p1, String p2) {
        return given()
                .header(AUTH_HEADER, getToken(userId1))
                .pathParam("id", id)
                .body(String.format("""
                        {"oldPassword":"%s","newPassword":"%s"}
                        """, p1, p2))
                .contentType("application/json")
                .put(arlasAppPath.concat("users/{id}"));
    }

    protected Response deleteUser(String actingId, String targetId) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("id", targetId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("users/{id}"));
    }

    protected Response createOrganisation(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations"));

    }

    protected Response listOrganisations(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId1))
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations"));

    }

    protected Response deleteOrganisation(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .pathParam("oid", orgId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}"));

    }

    protected Response addUserToOrganisation(String actingId, String email) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .contentType("application/json")
                .body(String.format("""
                        {"email":"%s","isOwner": false}
                        """, email))
                .post(arlasAppPath.concat("organisations/{oid}/users"));

    }

    protected Response deleteUserFromOrganisation(String actingId, String userId) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("uid", userId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/users/{uid}"));

    }

    protected Response createRole(String actingId, String rname, String description) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .body(String.format("""
                        {"name":"%s","description":"%s"}
                        """, rname, description))
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/roles"));
    }

    protected Response listUserRoles(String actingId, String uid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("uid", uid)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/{oid}/users/{uid}/roles"));
    }

    protected Response addUserInRole(String actingId, String uid, String rid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("rid", rid)
                .pathParam("uid", uid)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/users/{uid}/roles/{rid}"));
    }

    protected Response deleteUserFromRole(String actingId, String uid, String rid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("rid", rid)
                .pathParam("uid", uid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("organisations/{oid}/users/{uid}/roles/{rid}"));
    }

    protected Response listUsers(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .pathParam("oid", orgId)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/{oid}/users"));

    }

    protected Response listPermissions(String actingId, String userId) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("uid", userId)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/{oid}/users/{uid}/permissions"));
    }

    protected Response addPermission(String actingId, String pvalue, String pdesc) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .body(String.format("""
                        {"value":"%s","description": "%s"}
                        """, pvalue, pdesc))
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/permissions"));
    }

    protected Response deletePermissionFromUser(String actingId, String userId, String pid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("pid", pid)
                .pathParam("uid", userId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("permissions/{pid}/users/{uid}"));
    }

    protected Response addPermissionToRole(String actingId, String rid, String pid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("pid", pid)
                .pathParam("rid", rid)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisations/{oid}/roles/{rid}/permissions/{pid}"));
    }

    protected Response deletePermissionFromRole(String actingId, String rid, String pid) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("pid", pid)
                .pathParam("rid", rid)
                .contentType("application/json")
                .delete(arlasAppPath.concat("permissions/{pid}/roles/{rid}"));
    }

}
