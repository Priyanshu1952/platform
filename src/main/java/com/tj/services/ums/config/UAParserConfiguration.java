package com.tj.services.ums.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ua_parser.Parser;

@Configuration
public class UAParserConfiguration {

    @Bean
    public Parser uaParser() {
        return new Parser();
    }
}