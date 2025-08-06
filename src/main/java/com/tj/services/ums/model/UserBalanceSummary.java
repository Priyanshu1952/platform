package com.tj.services.ums.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserBalanceSummary {
    private Double availableBalance;
    private Double creditLimit;
    private Double usedCredit;
    private Double totalBalance;
    private Double blockedAmount;
    private Double pendingAmount;
    private String currency;
    private String balanceType; // WALLET, CREDIT, PREPAID
}
