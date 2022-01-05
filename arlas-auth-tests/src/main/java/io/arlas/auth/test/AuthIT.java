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

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AuthIT {
    protected static String arlasAppPath;
    private static final String userHeader;

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
         String id = createUser("u1@foo.com")
                .then().statusCode(201)
                .body("email", equalTo("u1@foo.com"))
                .extract().jsonPath().get("id");
    }

    protected Response createUser(String email) {
        return given()
                .contentType("application/json")
                .body(email)
                .post(arlasAppPath.concat("user"));
    }

    protected RequestSpecification givenForUser(String userId) {
        return given().header(userHeader, userId);
    }
}
