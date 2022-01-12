package io.arlas.auth.test;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.util.Optional;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthITUser {
    public static final String USER1 = "u1@foo.com";
    public static final String USER2 = "u2@foo.com";
    protected static String arlasAppPath;
    protected static final String userHeader;
    protected static String userId1;
    protected static String userId2;
    protected static String orgId;

    static {
        userHeader = Optional.ofNullable(System.getenv("ARLAS_USER_HEADER")).orElse("arlas-user");

        String arlasHost = Optional.ofNullable(System.getenv("ARLAS_AUTH_HOST")).orElse("localhost");
        int arlasPort = Integer.parseInt(Optional.ofNullable(System.getenv("ARLAS_AUTH_PORT")).orElse("9997"));
        RestAssured.baseURI = "http://" + arlasHost;
        RestAssured.port = arlasPort;
        RestAssured.basePath = "";
        String arlasPrefix = Optional.ofNullable(System.getenv("ARLAS_AUTH_PREFIX")).orElse("/arlas_auth_server");
        arlasAppPath = Optional.ofNullable(System.getenv("ARLAS_AUTH_APP_PATH")).orElse("/");
        if (arlasAppPath.endsWith("/"))
            arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        arlasAppPath = arlasAppPath + arlasPrefix;
        if (arlasAppPath.endsWith("//"))
            arlasAppPath = arlasAppPath.substring(0, arlasAppPath.length() - 1);
        if (!arlasAppPath.endsWith("/"))
            arlasAppPath = arlasAppPath + "/auth/";
    }

    @Test
    public void test01CreateUser() {
        userId1 = createUser(USER1)
                .then().statusCode(201)
                .body("email", equalTo(USER1))
                .extract().jsonPath().get("id");
        userId2 = createUser(USER2)
                .then().statusCode(201)
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

    @Test
    public void test04VerifyUser() {
        given()
                .contentType("application/json")
                .pathParam("id", userId1)
                .body("password1")
                .post(arlasAppPath.concat("user/{id}/verify"))
                .then().statusCode(201)
                .body("email", equalTo(USER1))
                .body("verified", equalTo(true));

        given()
                .contentType("application/json")
                .pathParam("id", userId2)
                .body("password2")
                .post(arlasAppPath.concat("user/{id}/verify"))
                .then().statusCode(201)
                .body("email", equalTo(USER2))
                .body("verified", equalTo(true));
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
                .body("name", equalTo("foo"))
                .body("members", hasSize(1))
                .body("members[0].owner", equalTo(true))
                .body("members[0].user.email", equalTo(USER1))
                .extract().jsonPath().get("id");

        getUser(userId1).then().statusCode(200)
                .body("organisations", hasSize(1))
                .body("organisations[0].organisation.name", equalTo("foo"));
    }

    @Test
    public void test11ListOrganisations() {
        listOrganisations(userId1).then().statusCode(200)
                .body("", hasSize(1))
                .body("[0].name", equalTo("foo"))
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
    public void test14DeleteOrganisationAsOwner() {
        deleteOrganisation(userId1).then().statusCode(202);
        getUser(userId1).then().statusCode(200).body("organisations", hasSize(0));
    }

    @Test
    public void test90DeleteUserNotSelf() {
        deleteUser(userId1, userId2).then().statusCode(404);
    }

    @Test
    public void test91DeleteUserSelf() {
        deleteUser(userId1, userId1).then().statusCode(202);
        deleteUser(userId2, userId2).then().statusCode(202);
    }

    // ----------------

    protected Response createUser(String email) {
        return given()
                .contentType("application/json")
                .body(email)
                .post(arlasAppPath.concat("user"));
    }

    protected Response getUser(String id) {
        return givenForUser(userId1)
                .pathParam("id", id)
                .contentType("application/json")
                .get(arlasAppPath.concat("user/{id}"));
    }

    protected Response updateUser(String id, String p1, String p2) {
        return givenForUser(userId1)
                .pathParam("id", id)
                .body(String.format("""
                        {"oldPassword":"%s","newPassword":"%s"}
                        """, p1, p2))
                .contentType("application/json")
                .put(arlasAppPath.concat("user/{id}"));
    }

    protected Response deleteUser(String actingId, String targetId) {
        return givenForUser(actingId)
                .pathParam("id", targetId)
                .contentType("application/json")
                .delete(arlasAppPath.concat("user/{id}"));
    }

    protected Response createOrganisation(String userId) {
        return givenForUser(userId)
                .contentType("application/json")
                .post(arlasAppPath.concat("organisation"));

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
                .delete(arlasAppPath.concat("organisation/{oid}"));

    }

    protected RequestSpecification givenForUser(String id) {
        return given().header(userHeader, id);
    }
}
