"""
Layer 1: Signature Scanner - Detects fixed cryptographic constants
"""
import torch
import torch.nn as nn
from typing import Dict, List, Optional
import numpy as np
import struct

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    AES_SBOX, SHA256_K, MD5_INIT, ECC_P256_PRIME, RSA_OID_PATTERNS,
    SIGNATURE_FEATURES, SIGNATURE_FEATURE_DIM, ENTROPY_THRESHOLD
)
from utils.entropy import calculate_shannon_entropy, has_high_entropy


class SignatureScanner:
    """
    Non-AI feature extractor that detects fixed cryptographic constants.
    
    Scans binary data for known cryptographic algorithm signatures:
    - AES S-box
    - SHA-256 constants
    - MD5 constants
    - ECC domain parameters
    - RSA ASN.1 sequences
    - High entropy regions
    
    Example:
        >>> scanner = SignatureScanner()
        >>> features = scanner.scan(firmware_bytes)
        >>> # Returns: torch.tensor([1, 1, 0, 0, 0, 1])  # Feature vector
    """
    
    def __init__(self):
        """Initialize signature scanner with known constants."""
        self.aes_sbox = AES_SBOX
        self.sha256_k = SHA256_K
        self.md5_init = MD5_INIT
        self.ecc_p256 = ECC_P256_PRIME
        self.rsa_oids = RSA_OID_PATTERNS
        self.entropy_threshold = ENTROPY_THRESHOLD
    
    def _search_bytes(self, data: bytes, pattern: bytes) -> bool:
        """
        Search for byte pattern in data.
        
        Args:
            data: Binary data to search
            pattern: Pattern to find
            
        Returns:
            True if pattern found
        """
        return pattern in data
    
    def _search_uint32(self, data: bytes, values: List[int], endian: str = 'big') -> bool:
        """
        Search for 32-bit integer values in data.
        
        Args:
            data: Binary data to search
            values: List of 32-bit integers to find
            endian: Byte order ('big' or 'little')
            
        Returns:
            True if any value found
        """
        if len(data) < 4:
            return False
        
        for value in values:
            # Try both endianness
            pattern_big = struct.pack('>I', value)
            pattern_little = struct.pack('<I', value)
            
            if pattern_big in data or pattern_little in data:
                return True
        
        return False
    
    def _detect_aes_sbox(self, data: bytes) -> bool:
        """
        Detect AES S-box in binary data.
        
        The AES S-box is a 256-byte lookup table with distinctive values.
        We check for the first 16 bytes as a signature.
        
        Args:
            data: Binary data
            
        Returns:
            True if AES S-box signature found
        """
        # Check for first 16 bytes of S-box (distinctive pattern)
        sbox_prefix = self.aes_sbox[:16]
        return self._search_bytes(data, sbox_prefix)
    
    def _detect_sha256_constants(self, data: bytes) -> bool:
        """
        Detect SHA-256 K constants.
        
        Args:
            data: Binary data
            
        Returns:
            True if SHA-256 constants found
        """
        # Check for first few K values
        for k_val in self.sha256_k[:4]:  # Check first 4 constants
            pattern_big = struct.pack('>I', k_val)
            pattern_little = struct.pack('<I', k_val)
            if pattern_big in data or pattern_little in data:
                return True
        return False
    
    def _detect_md5_constants(self, data: bytes) -> bool:
        """
        Detect MD5 initial constants.
        
        Args:
            data: Binary data
            
        Returns:
            True if MD5 constants found
        """
        # Check for MD5 initial values (A, B, C, D)
        for init_val in self.md5_init:
            pattern_big = struct.pack('>I', init_val)
            pattern_little = struct.pack('<I', init_val)
            if pattern_big in data or pattern_little in data:
                return True
        return False
    
    def _detect_ecc_params(self, data: bytes) -> bool:
        """
        Detect ECC P-256 domain parameters.
        
        Args:
            data: Binary data
            
        Returns:
            True if ECC parameters found
        """
        # Check for P-256 prime (first 16 bytes as signature)
        p256_prefix = self.ecc_p256[:16]
        return self._search_bytes(data, p256_prefix)
    
    def _detect_rsa_asn1(self, data: bytes) -> bool:
        """
        Detect RSA ASN.1 OID patterns.
        
        Args:
            data: Binary data
            
        Returns:
            True if RSA ASN.1 patterns found
        """
        for oid_pattern in self.rsa_oids:
            if self._search_bytes(data, oid_pattern):
                return True
        return False
    
    def scan(self, data: bytes) -> torch.Tensor:
        """
        Scan binary data for cryptographic signatures.
        
        Args:
            data: Binary firmware data
            
        Returns:
            Feature vector as torch.Tensor of shape (SIGNATURE_FEATURE_DIM,)
            
        Example:
            >>> features = scanner.scan(firmware_bytes)
            >>> # Returns: tensor([1., 1., 0., 0., 0., 1.])
        """
        if not data:
            return torch.zeros(SIGNATURE_FEATURE_DIM, dtype=torch.float32)
        
        features = {
            "AES_SBOX_FOUND": 1.0 if self._detect_aes_sbox(data) else 0.0,
            "SHA256_CONST_FOUND": 1.0 if self._detect_sha256_constants(data) else 0.0,
            "MD5_CONST_FOUND": 1.0 if self._detect_md5_constants(data) else 0.0,
            "ECC_PARAM_FOUND": 1.0 if self._detect_ecc_params(data) else 0.0,
            "RSA_ASN1_FOUND": 1.0 if self._detect_rsa_asn1(data) else 0.0,
            "ENTROPY_HIGH": 1.0 if has_high_entropy(data, self.entropy_threshold) else 0.0
        }
        
        # Convert to fixed-length vector
        feature_vector = torch.tensor([
            features["AES_SBOX_FOUND"],
            features["SHA256_CONST_FOUND"],
            features["MD5_CONST_FOUND"],
            features["ECC_PARAM_FOUND"],
            features["RSA_ASN1_FOUND"],
            features["ENTROPY_HIGH"]
        ], dtype=torch.float32)
        
        return feature_vector
    
    def scan_batch(self, data_list: List[bytes]) -> torch.Tensor:
        """
        Scan multiple binary data samples.
        
        Args:
            data_list: List of binary data samples
            
        Returns:
            Feature tensor of shape (batch_size, SIGNATURE_FEATURE_DIM)
        """
        features = [self.scan(data) for data in data_list]
        return torch.stack(features)

