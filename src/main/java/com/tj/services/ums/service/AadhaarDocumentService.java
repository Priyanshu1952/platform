package com.tj.services.ums.service;

import com.tj.services.ums.dto.AadhaarDocumentData;
import com.tj.services.ums.dto.AadhaarDocumentResult;
import com.tj.services.ums.dto.OtpRequestResult;
import org.springframework.web.multipart.MultipartFile;

/**
 * Service interface for Aadhaar document operations
 * Supports multiple approaches for Aadhaar PDF retrieval and management
 */
public interface AadhaarDocumentService {
    
    /**
     * Download e-Aadhaar PDF using Aadhaar number and OTP
     * This uses official UIDAI APIs for document retrieval
     * 
     * @param aadhaarNumber The 12-digit Aadhaar number
     * @param otp OTP received on registered mobile/email
     * @param userId User ID for audit and storage
     * @return byte array of the PDF document
     */
    byte[] downloadEAadhaarPdf(String aadhaarNumber, String otp, String userId);
    
    /**
     * Verify and store uploaded Aadhaar PDF
     * This allows users to upload their own Aadhaar PDF for verification
     * 
     * @param file Uploaded Aadhaar PDF file
     * @param aadhaarNumber Expected Aadhaar number for verification
     * @param userId User ID for audit and storage
     * @return verification result with extracted data
     */
    AadhaarDocumentResult verifyAndStoreAadhaarPdf(MultipartFile file, String aadhaarNumber, String userId);
    
    /**
     * Retrieve stored Aadhaar PDF for a user
     * 
     * @param userId User ID
     * @return byte array of the stored PDF document
     */
    byte[] getStoredAadhaarPdf(String userId);
    
    /**
     * Extract data from Aadhaar PDF using OCR/parsing
     * This uses Surepass e-Aadhaar API or similar services
     * 
     * @param pdfBytes PDF file as byte array
     * @return extracted Aadhaar data
     */
    AadhaarDocumentData extractDataFromPdf(byte[] pdfBytes);
    
    /**
     * Request OTP for e-Aadhaar download
     * This initiates the OTP process for official e-Aadhaar download
     * 
     * @param aadhaarNumber The 12-digit Aadhaar number
     * @return OTP request result
     */
    OtpRequestResult requestEAadhaarOtp(String aadhaarNumber);
}
