package com.securitydam.AthleteAuth.rest;

public class JWTResponse {
    public String token;

    public JWTResponse(String token){
        this.token = "Bearer " + token;
    }
}
