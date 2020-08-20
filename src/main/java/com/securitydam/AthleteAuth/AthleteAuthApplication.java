package com.securitydam.AthleteAuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

@SpringBootApplication
public class AthleteAuthApplication {


	public static void main(String[] args) {
		SpringApplication.run(AthleteAuthApplication.class, args);
	}

}
