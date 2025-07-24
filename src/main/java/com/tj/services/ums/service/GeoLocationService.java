package com.tj.services.ums.service;

import com.tj.services.ums.model.GeoLocation;

import java.util.List;
import java.util.Optional;

public interface GeoLocationService {
    Optional<GeoLocation> getLocationByIp(String ip);
    GeoLocation saveOrUpdateLocation(GeoLocation location);
    boolean existsByIp(String ip);

    boolean isBlockedCountry(String remoteIp, List<String> blockedCountries);

    Optional<GeoLocation> getLocationFromIp(String ip);
    boolean isProxyConnection(String ip);
}
