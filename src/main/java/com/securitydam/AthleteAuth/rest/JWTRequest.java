package com.securitydam.AthleteAuth.rest;


import org.springframework.beans.factory.annotation.Required;

import javax.validation.constraints.*;

public class JWTRequest {

    @NotBlank(message = "Email cannot be empty!")
    @Email(message = "Email is Invalid!")
    public String email;

    @NotBlank(message = "Password cannot be empty!")
    @Size(min = 7,max = 12,message = "Password must be between 7-12 characters")
    public String password;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
