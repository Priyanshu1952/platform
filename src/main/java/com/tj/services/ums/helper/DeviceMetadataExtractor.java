package com.tj.services.ums.helper;

import com.tj.services.ums.dto.DeviceMetadata;
import com.tj.services.ums.service.GeoLocationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import ua_parser.Parser;
import jakarta.servlet.http.HttpServletRequest;

@Component
@RequiredArgsConstructor
public class DeviceMetadataExtractor {

    private final Parser uapParser;
    private final GeoLocationService geoLocationService;

    public DeviceMetadata extractDeviceMetadata(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String ipAddress = request.getRemoteAddr();

        String deviceType = detectDeviceType(userAgent);
        String location = String.valueOf(geoLocationService.getLocationFromIp(ipAddress));
        boolean isProxy = geoLocationService.isProxyConnection(ipAddress);

        return DeviceMetadata.builder()
                .deviceId(request.getHeader("deviceid"))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceType(deviceType)
                .location(location)
                .isProxy(isProxy)
                .build();
    }

    private String detectDeviceType(String userAgent) {
        if (userAgent == null) return "UNKNOWN";
        return uapParser.parse(userAgent).device.family;
    }
}