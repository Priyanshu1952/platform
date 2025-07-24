package com.tj.services.ums;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class UmsApplication {
	public static void main(String[] args) {
		SpringApplication.run(UmsApplication.class, args);
	}
}
