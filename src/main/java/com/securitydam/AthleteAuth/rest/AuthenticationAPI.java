package com.securitydam.AthleteAuth.rest;

import com.securitydam.AthleteAuth.auth.AdminOrModerator;
import com.securitydam.AthleteAuth.auth.IsAdmin;
import com.securitydam.AthleteAuth.entities.AppUser;
import com.securitydam.AthleteAuth.entities.Authority;
import com.securitydam.AthleteAuth.entities.USER_ROLES;
import com.securitydam.AthleteAuth.repositories.UserRepository;
import com.securitydam.AthleteAuth.services.JWTUserDetailsService;
import com.securitydam.AthleteAuth.utils.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class AuthenticationAPI {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private JWTUserDetailsService jwtUserDetailsService;


    @PostMapping("/register")
    @ResponseBody
    public ResponseEntity register(@RequestBody @Valid JWTRequest jwtRequest, Errors errors){
        if(errors.hasErrors()){
            return handleErrors(errors);
        }
        AppUser user = new AppUser();
        user.setEmail(jwtRequest.email);
        user.setPassword(passwordEncoder.encode(jwtRequest.password));
        List<USER_ROLES> roles = new ArrayList<>();
        roles.add(USER_ROLES.ROLE_USER);
        user.setRoles(roles);
        List<String> permissions = new ArrayList<>();
        user.setPermissions(permissions);
        return ResponseEntity.ok().body(userRepository.save(user));
    }

    @PostMapping("/token")
    @ResponseBody
    public ResponseEntity token(@RequestBody @Valid JWTRequest jwtRequest, Errors errors) {
        if(errors.hasErrors()){
            return handleErrors(errors);
        }
        authenticate(jwtRequest.getEmail(), jwtRequest.getPassword());

        final UserDetails userDetails = jwtUserDetailsService
                .loadUserByUsername(jwtRequest.getEmail());
        final String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JWTResponse(token));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAnyAuthority('ADMIN:VIEW') " + " && hasRole('ADMIN')")
    public String admin(){
        return "ADMIN";
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    public String AdminOrUser(){
        return "ADMIN & USER";
    }

    @GetMapping("/special")
    @PreAuthorize("hasAnyAuthority('SPECIAL:VIEW')")
    public String special(){
        return "SPECIAL VIEW";
    }

    @GetMapping("/adminonly")
    @IsAdmin
    public String adminOnly(){
        return "Admin only!";
    }

    @GetMapping("/adminormoderator")
    @AdminOrModerator
    public String adminOrModerator(){
        return "Admin or moderator";
    }

    private void authenticate(String username, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new AccessDeniedException("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new AccessDeniedException("INVALID_CREDENTIALS", e);
        }
    }

    private ResponseEntity handleErrors(Errors errors){
        List<String> errorsResponse = new ArrayList<>();
        errors.getAllErrors().forEach(err -> errorsResponse.add(err.getDefaultMessage()));
        return ResponseEntity.badRequest().body(errorsResponse);
    }
}
