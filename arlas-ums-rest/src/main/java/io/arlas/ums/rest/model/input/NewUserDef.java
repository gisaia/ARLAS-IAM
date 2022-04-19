package io.arlas.ums.rest.model.input;

import java.util.Locale;

public class NewUserDef {
    public String email;
    public String locale = Locale.ENGLISH.toString();
    public String timezone = "Europe/Paris";

    public NewUserDef(){}
}
