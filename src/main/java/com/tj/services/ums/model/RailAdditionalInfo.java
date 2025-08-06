package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RailAdditionalInfo {
    private String railUserId;
    private String railUserType;
    private String railStatus;
    private String railCategory;
    private String railDivision;
    private String railZone;
    private String railStation;
    private LocalDateTime railOnboardingDate;
    private String railApprovalNumber;
    private String railDocumentStatus;
    private Boolean railActive;
}
