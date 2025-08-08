package com.tj.services.ums.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
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
