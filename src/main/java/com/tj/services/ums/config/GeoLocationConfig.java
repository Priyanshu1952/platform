package com.tj.services.ums.config;

import com.maxmind.geoip2.DatabaseReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;

@Configuration
public class GeoLocationConfig {

    @Value("classpath:${geoip.db.path}")
    private Resource geoIpDb;

    @Bean
    @ConditionalOnProperty(name = "geoip.mmdb.enabled", havingValue = "true", matchIfMissing = false)
    public DatabaseReader databaseReader() throws IOException {
        InputStream database = new ClassPathResource("geolite2/GeoLite2-City.mmdb").getInputStream();
        return new DatabaseReader.Builder(database).build();
    }

}
