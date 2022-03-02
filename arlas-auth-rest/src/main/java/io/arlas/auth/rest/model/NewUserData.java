package io.arlas.auth.rest.model;

import java.util.Locale;

public class NewUserData {
    public String email;
    public String locale = Locale.ENGLISH.toString();
    public String timezone = "Europe/Paris";

    public NewUserData(){}
}
