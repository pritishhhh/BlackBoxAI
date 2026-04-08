"""
Layer 1: Proprietary Signature Scanner
Detects patterns unique to proprietary cryptographic implementations.
"""
import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Optional
import struct

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    SIGNATURE_FEATURE_DIM, ENTROPY_THRESHOLD,
    HIGH_XOR_THRESHOLD, HIGH_SHIFT_THRESHOLD, HIGH_ARITHMETIC_THRESHOLD
)


class ProprietarySignatureScanner:
    """
    Non-AI feature extractor for detecting proprietary cryptographic patterns.
    
    Scans binary data for patterns indicative of custom crypto:
    - Custom S-boxes (non-standard substitution tables)
    - Proprietary permutation patterns
    - Round-based structures
    - Key scheduling patterns
    - Heavy bitwise operations (XOR, shift, rotate)
    - Arithmetic patterns (modular arithmetic)
    - High entropy regions
    - Loop structures
    
    Example:
        >>> scanner = ProprietarySignatureScanner()
        >>> features = scanner.scan(firmware_bytes)
        >>> # Returns: torch.tensor([1, 0, 1, 1, 1, 0, 1, 0])  # 8-dim feature vector
    """
    
    # Known S-box fragments to detect (AES, DES, etc. to distinguish from proprietary)
    KNOWN_SBOX_FRAGMENTS = [
        bytes([0x63, 0x7c, 0x77, 0x7b]),  # AES S-box start
        bytes([0x52, 0x09, 0x6a, 0xd5]),  # AES S-box fragment
        bytes([0xe2, 0x4e, 0x99, 0x80]),  # DES S-box fragment
    ]
    
    # Known hash constants
    KNOWN_HASH_CONSTANTS = [
        0x6a09e667,  # SHA-256
        0xbb67ae85,  # SHA-256
        0x67452301,  # MD5
        0xefcdab89,  # MD5
    ]
    
    def __init__(self):
        """Initialize the proprietary signature scanner."""
        self.entropy_threshold = ENTROPY_THRESHOLD
        self.xor_threshold = HIGH_XOR_THRESHOLD
        self.shift_threshold = HIGH_SHIFT_THRESHOLD
        self.arith_threshold = HIGH_ARITHMETIC_THRESHOLD
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0.0
        
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        return -np.sum(probabilities * np.log2(probabilities))
    
    def _detect_custom_sbox(self, data: bytes) -> bool:
        """
        Detect custom (non-standard) S-box in data.
        
        A custom S-box is a 256-byte permutation that:
        - Has high entropy (close to 8)
        - Contains most values 0-255
        - Doesn't match known S-boxes
        """
        if len(data) < 256:
            return False
        
        # Search for potential S-boxes
        for i in range(0, len(data) - 256, 32):
            chunk = data[i:i + 256]
            
            # Check if it's a near-permutation
            unique_values = len(set(chunk))
            if unique_values < 230:
                continue
            
            # Check entropy
            entropy = self._calculate_entropy(chunk)
            if entropy < 7.5:
                continue
            
            # Check it's not a known S-box
            is_known = False
            for known_fragment in self.KNOWN_SBOX_FRAGMENTS:
                if known_fragment in chunk:
                    is_known = True
                    break
            
            if not is_known:
                return True
        
        return False
    
    def _detect_permutation_table(self, data: bytes) -> bool:
        """Detect permutation tables (bit/byte shuffling patterns)."""
        if len(data) < 64:
            return False
        
        # Look for sequences that could be permutation indices
        for i in range(0, len(data) - 64, 16):
            chunk = data[i:i + 64]
            
            # Check for sequential-like patterns with all unique values
            unique_vals = len(set(chunk))
            if unique_vals < 55:  # Should have mostly unique values
                continue
            
            # Check if values are in valid range for permutation
            max_val = max(chunk)
            if max_val < 128 and unique_vals > 50:
                return True
        
        return False
    
    def _detect_round_structure(self, data: bytes) -> bool:
        """Detect round-based crypto structure (repeated patterns)."""
        if len(data) < 256:
            return False
        
        # Look for repeated code patterns indicating rounds
        pattern_size = 32
        pattern_counts = {}
        
        for i in range(0, len(data) - pattern_size, 8):
            pattern = data[i:i + pattern_size]
            pattern_hash = hash(pattern)
            pattern_counts[pattern_hash] = pattern_counts.get(pattern_hash, 0) + 1
        
        # If any pattern repeats 4+ times, likely has rounds
        max_repeats = max(pattern_counts.values()) if pattern_counts else 0
        return max_repeats >= 4
    
    def _detect_key_schedule(self, data: bytes) -> bool:
        """Detect key scheduling patterns."""
        # Key schedules typically have:
        # - XOR operations
        # - Rotation/shift operations
        # - Table lookups
        
        xor_count = 0
        shift_count = 0
        
        for i in range(len(data) - 1):
            byte = data[i]
            
            # XOR patterns (0x30-0x35)
            if 0x30 <= byte <= 0x35:
                xor_count += 1
            
            # Shift/rotate patterns (0xC0-0xD3)
            if 0xC0 <= byte <= 0xD3:
                shift_count += 1
        
        # Key schedules have significant XOR and shift operations
        return xor_count > 20 and shift_count > 10
    
    def _is_bitwise_heavy(self, data: bytes) -> bool:
        """Check if code is heavy on bitwise operations."""
        bitwise_ops = 0
        
        for byte in data:
            # XOR (0x30-0x35)
            if 0x30 <= byte <= 0x35:
                bitwise_ops += 1
            # AND (0x20-0x25)
            if 0x20 <= byte <= 0x25:
                bitwise_ops += 1
            # OR (0x08-0x0D)
            if 0x08 <= byte <= 0x0D:
                bitwise_ops += 1
            # Shift/rotate (0xC0-0xD3)
            if 0xC0 <= byte <= 0xD3:
                bitwise_ops += 1
        
        return bitwise_ops >= self.xor_threshold + self.shift_threshold
    
    def _is_arithmetic_heavy(self, data: bytes) -> bool:
        """Check if code is heavy on arithmetic operations."""
        arith_ops = 0
        
        for byte in data:
            # ADD (0x00-0x05)
            if 0x00 <= byte <= 0x05:
                arith_ops += 1
            # MUL/DIV (0xF6, 0xF7)
            if byte in [0xF6, 0xF7]:
                arith_ops += 2  # Weight more for crypto
            # INC/DEC
            if 0x40 <= byte <= 0x4F:
                arith_ops += 1
        
        return arith_ops >= self.arith_threshold
    
    def _has_high_entropy_region(self, data: bytes) -> bool:
        """Check for high entropy regions (encrypted/compressed data)."""
        if len(data) < 128:
            return self._calculate_entropy(data) >= self.entropy_threshold
        
        # Check multiple regions
        chunk_size = 128
        for i in range(0, len(data) - chunk_size, chunk_size // 2):
            chunk = data[i:i + chunk_size]
            if self._calculate_entropy(chunk) >= self.entropy_threshold:
                return True
        
        return False
    
    def _detect_loop_structure(self, data: bytes) -> bool:
        """Detect loop structures common in crypto."""
        loop_indicators = 0
        
        for i in range(len(data) - 1):
            byte = data[i]
            
            # LOOP instruction (0xE2)
            if byte == 0xE2:
                loop_indicators += 2
            
            # Backward jump patterns
            if byte in [0x75, 0x74, 0x79, 0x7F]:  # Conditional jumps
                if i + 1 < len(data) and data[i + 1] > 0x80:  # Negative offset
                    loop_indicators += 1
            
            # DEC + JNZ pattern
            if i + 2 < len(data):
                if byte == 0x48 and data[i + 1] == 0x75:  # DEC + JNZ
                    loop_indicators += 2
        
        return loop_indicators >= 4
    
    def scan(self, data: bytes) -> torch.Tensor:
        """
        Scan binary data for proprietary cryptographic signatures.
        
        Args:
            data: Binary firmware/code data
            
        Returns:
            Feature vector of shape (SIGNATURE_FEATURE_DIM,)
            
        Features:
            [0] HAS_SBOX: Custom S-box detected
            [1] HAS_PERMUTATION: Permutation table detected
            [2] HAS_ROUNDS: Round-based structure detected
            [3] HAS_KEY_SCHEDULE: Key scheduling pattern detected
            [4] BITWISE_HEAVY: Heavy on bitwise operations
            [5] ARITHMETIC_HEAVY: Heavy on arithmetic operations
            [6] HIGH_ENTROPY: High entropy regions present
            [7] LOOP_STRUCTURE: Loop patterns detected
        """
        if not data:
            return torch.zeros(SIGNATURE_FEATURE_DIM, dtype=torch.float32)
        
        features = torch.tensor([
            1.0 if self._detect_custom_sbox(data) else 0.0,
            1.0 if self._detect_permutation_table(data) else 0.0,
            1.0 if self._detect_round_structure(data) else 0.0,
            1.0 if self._detect_key_schedule(data) else 0.0,
            1.0 if self._is_bitwise_heavy(data) else 0.0,
            1.0 if self._is_arithmetic_heavy(data) else 0.0,
            1.0 if self._has_high_entropy_region(data) else 0.0,
            1.0 if self._detect_loop_structure(data) else 0.0,
        ], dtype=torch.float32)
        
        return features
    
    def scan_batch(self, data_list: List[bytes]) -> torch.Tensor:
        """
        Scan multiple binary samples.
        
        Args:
            data_list: List of binary data samples
            
        Returns:
            Feature tensor of shape (batch_size, SIGNATURE_FEATURE_DIM)
        """
        features = [self.scan(data) for data in data_list]
        return torch.stack(features)
    
    def get_feature_names(self) -> List[str]:
        """Get names of signature features."""
        return [
            "HAS_SBOX",
            "HAS_PERMUTATION",
            "HAS_ROUNDS",
            "HAS_KEY_SCHEDULE",
            "BITWISE_HEAVY",
            "ARITHMETIC_HEAVY",
            "HIGH_ENTROPY",
            "LOOP_STRUCTURE",
        ]

