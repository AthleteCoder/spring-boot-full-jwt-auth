package com.securitydam.AthleteAuth.entities;

import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

@Document(collection = "users")
public class AppUser {
    public String email;
    public String password;
    public List<String> permissions;
    public List<USER_ROLES> roles;

    public List<String> getPermissions() {
        return this.permissions;
    }

    public List<USER_ROLES> getRoles() {
        return roles;
    }

    public void setRoles(List<USER_ROLES> roles) {
        this.roles = roles;
    }
    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

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

//    public List<SimpleGrantedAuthority> getAuthorities(){
//        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
//        this.permissions.forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
//        this.roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(role.name())));
//        return authorities;
//    }

}
