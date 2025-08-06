package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DailyUsageInfo {
    private LocalDate date;
    private Double dailyLimit;
    private Double usedAmount;
    private Double remainingAmount;
    private Integer transactionCount;
    private Integer maxTransactions;
    private Boolean limitExceeded;
    private String resetTime;
}
