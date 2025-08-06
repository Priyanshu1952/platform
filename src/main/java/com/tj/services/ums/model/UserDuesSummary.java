package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDuesSummary {
    private Double totalDues;
    private Double overdueDues;
    private Double currentDues;
    private LocalDate nextDueDate;
    private Integer overdueCount;
    private String currency;
    private String dueType; // PAYMENT, CREDIT, LOAN
}
