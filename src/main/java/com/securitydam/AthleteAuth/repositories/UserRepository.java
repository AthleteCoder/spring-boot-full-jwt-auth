package com.securitydam.AthleteAuth.repositories;

import com.securitydam.AthleteAuth.entities.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserRepository extends MongoRepository<AppUser,String> {
    AppUser findByEmail(String email);
}
