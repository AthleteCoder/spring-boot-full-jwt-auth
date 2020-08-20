package com.securitydam.AthleteAuth.auth;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
public @interface IsAdmin {
}
