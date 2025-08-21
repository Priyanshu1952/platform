package com.tj.services.ums.dto;

import com.tj.services.ums.model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmulationResponse {
    private Boolean success;
    private String message;
    private String emulatedAccessToken;
    private User targetUser;
    private UUID sessionId;
} 