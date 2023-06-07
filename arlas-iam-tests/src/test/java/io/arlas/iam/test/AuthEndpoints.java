package io.arlas.iam.test;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

import java.util.Optional;

import static io.restassured.RestAssured.given;

public class AuthEndpoints {
    protected static final String AUTH_HEADER = "authorization";
    protected static final String ADMIN = "auth.arlas.cloud@gisaia.com";
    protected static final String ADMIN_PASSWORD = "admin";
    protected static final String USER1 = "u1@foo.com";
    protected static final String USER2 = "u2@foo.com";
    protected static final String ORG = "foo.com";
    protected static final String ORG_DISPLAY = "foo";
    protected static final String ROLE1 = "fooRole1";
    protected static final String ROLE1_DESC = "fooRole1 desc";
    protected static final String ROLE2 = "fooRole2";
    protected static final String ROLE2_DESC = "fooRole2 desc";
    protected static final String PERMISSION1 = "p1";
    protected static final String PERMISSION1_DESC = "p1 desc";
    protected static final String PERMISSION2 = "p2";
    protected static final String PERMISSION2_DESC = "p2 desc";
    protected static final String PERMISSION_GROUP = "h:column-filter:*:*";

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
    protected static String refreshToken1;
    protected static String token2;
    protected static String tokenAdmin;

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

    protected Response createUser(String email) {
        return given()
                .contentType("application/json")
                .body(String.format("""
                        {"email": "%s", "locale": "fr", "timezone":"Europe/Paris"}
                        """, email))
                .post(arlasAppPath.concat("users"));
    }

    protected Response login(String email) {
        return login(email, "secret");
    }

    protected Response login(String email, String password) {
        return given()
                .contentType("application/json")
                .body(String.format("""
                        {"email": "%s", "password": "%s"}
                        """, email, password))
                .post(arlasAppPath.concat("session"));
    }

    protected Response refreshToken(String userId, String refreshToken) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .contentType("application/json")
                .pathParam("refreshToken", refreshToken)
                .put(arlasAppPath.concat("session/{refreshToken}"));
    }

    protected Response logout(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .contentType("application/json")
                .delete(arlasAppPath.concat("session"));
    }

    protected Response changePassword(String userId, String oldPassword, String password) {
        return given()
                .header(AUTH_HEADER, getToken(userId))
                .contentType("application/json")
                .pathParam("id", userId)
                .body(String.format("""
                        {"oldPassword": "%s", "newPassword": "%s"}
                        """, oldPassword, password))
                .put(arlasAppPath.concat("users/{id}"));
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

    protected Response checkOrganisation(String userId) {
        return given()
                .header(AUTH_HEADER, getToken(userId1))
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/check"));

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
                        {"email":"%s","rids": []}
                        """, email))
                .post(arlasAppPath.concat("organisations/{oid}/users"));

    }

    protected Response getUserFromOrganisation(String actingId, String userId) {
        return given()
                .header(AUTH_HEADER, getToken(actingId))
                .pathParam("oid", orgId)
                .pathParam("uid", userId)
                .contentType("application/json")
                .get(arlasAppPath.concat("organisations/{oid}/users/{uid}"));

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

    protected Response listUsers(String userId, String rname) {
        RequestSpecification req = given()
                .header(AUTH_HEADER, getToken(userId))
                .pathParam("oid", orgId);
        if (rname != null) {
            req = req.queryParam("rname", rname);
        }
        return req.contentType("application/json")
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
