package com.tj.services.ums.repository;

import com.tj.services.ums.model.GeoLocation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GeoLocationRepository extends JpaRepository<GeoLocation, Long> {

    Optional<GeoLocation> findByIp(String ip);

    boolean existsByIp(String ip);
}
