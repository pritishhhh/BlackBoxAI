"""
Feature Extractor for proprietary cryptographic binary analysis.
"""
import numpy as np
from typing import Dict, List, Any, Tuple
import struct

from .entropy_utils import (
    calculate_entropy, 
    get_entropy_features,
    calculate_bit_flip_density,
    calculate_byte_distribution_uniformity
)


class FeatureExtractor:
    """
    Extracts features from binary data for crypto classification.
    
    Features extracted:
    - Entropy statistics
    - Byte frequency patterns
    - Instruction operation counts
    - Structural features
    - Crypto-specific patterns
    """
    
    # Common crypto-related byte patterns
    CRYPTO_PATTERNS = {
        'xor_opcodes': [0x30, 0x31, 0x32, 0x33, 0x34, 0x35],  # XOR opcodes
        'shift_opcodes': [0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3],  # Shift opcodes
        'rotate_opcodes': [0xD0, 0xD1, 0xD2, 0xD3],  # Rotate opcodes
        'mul_opcodes': [0xF6, 0xF7],  # MUL/DIV opcodes
        'add_opcodes': [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],  # ADD opcodes
    }
    
    # S-box detection pattern (high entropy, 256 bytes)
    SBOX_SIZE = 256
    SBOX_ENTROPY_THRESHOLD = 7.0
    
    def __init__(self):
        """Initialize feature extractor."""
        pass
    
    def extract_all_features(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Extract all features from binary data.
        
        Args:
            binary_data: Raw binary data
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Basic features
        features['file_size'] = len(binary_data)
        features['entropy'] = calculate_entropy(binary_data)
        features['bit_flip_density'] = calculate_bit_flip_density(binary_data)
        features['byte_uniformity'] = calculate_byte_distribution_uniformity(binary_data)
        
        # Entropy features
        entropy_features = get_entropy_features(binary_data, num_features=16)
        for i, val in enumerate(entropy_features):
            features[f'entropy_{i}'] = val
        
        # Operation counts
        op_counts = self._count_operations(binary_data)
        features.update(op_counts)
        
        # Structural features
        struct_features = self._extract_structural_features(binary_data)
        features.update(struct_features)
        
        # Crypto pattern detection
        crypto_features = self._detect_crypto_patterns(binary_data)
        features.update(crypto_features)
        
        return features
    
    def _count_operations(self, data: bytes) -> Dict[str, int]:
        """Count operation types in binary data."""
        counts = {
            'xor_ops': 0,
            'shift_ops': 0,
            'add_ops': 0,
            'mul_ops': 0,
            'rotate_ops': 0,
            'bitwise_ops': 0,
            'memory_ops': 0,
            'branch_ops': 0,
        }
        
        for byte in data:
            # XOR operations
            if byte in self.CRYPTO_PATTERNS['xor_opcodes']:
                counts['xor_ops'] += 1
                counts['bitwise_ops'] += 1
            
            # Shift operations
            if byte in self.CRYPTO_PATTERNS['shift_opcodes']:
                counts['shift_ops'] += 1
                counts['bitwise_ops'] += 1
            
            # Rotate operations
            if byte in self.CRYPTO_PATTERNS['rotate_opcodes']:
                counts['rotate_ops'] += 1
                counts['bitwise_ops'] += 1
            
            # MUL/DIV operations
            if byte in self.CRYPTO_PATTERNS['mul_opcodes']:
                counts['mul_ops'] += 1
            
            # ADD operations
            if byte in self.CRYPTO_PATTERNS['add_opcodes']:
                counts['add_ops'] += 1
            
            # Memory operations (MOV, LOAD, STORE patterns)
            if byte in [0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F]:
                counts['memory_ops'] += 1
            
            # Branch operations
            if byte in [0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79]:
                counts['branch_ops'] += 1
        
        return counts
    
    def _extract_structural_features(self, data: bytes) -> Dict[str, Any]:
        """Extract structural features from binary data."""
        features = {}
        
        # Basic block estimation (count branch targets)
        branch_targets = set()
        for i in range(len(data) - 1):
            if data[i] in [0xE9, 0xEB, 0x74, 0x75, 0x0F]:  # JMP/Jcc patterns
                if i + 2 < len(data):
                    offset = data[i + 1]
                    if offset > 0x80:
                        offset = -(256 - offset)
                    target = i + 2 + offset
                    if 0 <= target < len(data):
                        branch_targets.add(target)
        
        features['estimated_blocks'] = max(1, len(branch_targets))
        
        # Loop detection (backward branches)
        loop_count = 0
        for i in range(len(data) - 1):
            if data[i] in [0xE2, 0xE1, 0xE0]:  # LOOP instructions
                loop_count += 1
            elif data[i] in [0x75, 0x74, 0xEB] and i + 1 < len(data):
                if data[i + 1] > 0x80:  # Backward jump
                    loop_count += 1
        
        features['loop_count'] = loop_count
        
        # Constant occurrence (repeated 4-byte patterns)
        if len(data) >= 4:
            dword_counts = {}
            for i in range(0, len(data) - 3, 4):
                dword = struct.unpack('<I', data[i:i+4])[0]
                dword_counts[dword] = dword_counts.get(dword, 0) + 1
            
            features['repeated_constants'] = sum(1 for c in dword_counts.values() if c > 1)
        else:
            features['repeated_constants'] = 0
        
        # Code density (non-zero bytes ratio)
        non_zero = sum(1 for b in data if b != 0)
        features['code_density'] = non_zero / len(data) if len(data) > 0 else 0
        
        return features
    
    def _detect_crypto_patterns(self, data: bytes) -> Dict[str, Any]:
        """Detect cryptographic patterns in binary data."""
        features = {
            'has_sbox': 0,
            'has_permutation': 0,
            'has_round_structure': 0,
            'has_key_schedule': 0,
            'bitwise_heavy': 0,
            'arithmetic_heavy': 0,
        }
        
        # S-box detection (256-byte high entropy region)
        for i in range(0, len(data) - self.SBOX_SIZE, 64):
            chunk = data[i:i + self.SBOX_SIZE]
            if len(set(chunk)) > 200:  # High uniqueness
                chunk_entropy = calculate_entropy(chunk)
                if chunk_entropy >= self.SBOX_ENTROPY_THRESHOLD:
                    features['has_sbox'] = 1
                    break
        
        # Permutation detection (repeated index patterns)
        for i in range(0, len(data) - 64, 32):
            chunk = data[i:i + 64]
            unique_vals = len(set(chunk))
            if unique_vals > 60:  # Near-permutation
                # Check if values are in expected range
                max_val = max(chunk)
                if max_val < 128 and unique_vals > 55:
                    features['has_permutation'] = 1
                    break
        
        # Round structure detection (repeated patterns)
        if len(data) >= 256:
            pattern_length = 32
            patterns = {}
            for i in range(0, len(data) - pattern_length, pattern_length):
                pattern = data[i:i + pattern_length]
                pattern_hash = hash(pattern)
                patterns[pattern_hash] = patterns.get(pattern_hash, 0) + 1
            
            max_repeats = max(patterns.values()) if patterns else 0
            if max_repeats >= 4:
                features['has_round_structure'] = 1
        
        # Key schedule detection (expanding patterns)
        op_counts = self._count_operations(data)
        if op_counts['xor_ops'] > 20 and op_counts['shift_ops'] > 10:
            if features['has_sbox'] or op_counts['xor_ops'] > 40:
                features['has_key_schedule'] = 1
        
        # Bitwise vs arithmetic heavy
        bitwise_total = op_counts.get('bitwise_ops', 0)
        arith_total = op_counts.get('add_ops', 0) + op_counts.get('mul_ops', 0)
        
        if bitwise_total > arith_total * 2:
            features['bitwise_heavy'] = 1
        if arith_total > bitwise_total:
            features['arithmetic_heavy'] = 1
        
        return features
    
    def extract_csv_features(self, row: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from CSV row for model input.
        
        Args:
            row: Dictionary containing CSV row data
            
        Returns:
            Numpy array of normalized features
        """
        features = np.zeros(25, dtype=np.float32)
        
        # Operation counts (normalized)
        features[0] = float(row.get('xor_ops', 0)) / 100.0
        features[1] = float(row.get('shift_ops', 0)) / 100.0
        features[2] = float(row.get('add_ops', 0)) / 100.0
        features[3] = float(row.get('mul_ops', 0)) / 100.0
        features[4] = float(row.get('branch_ops', 0)) / 50.0
        features[5] = float(row.get('loop_ops', 0)) / 50.0
        features[6] = float(row.get('memory_access', 0)) / 100.0
        features[7] = float(row.get('bitwise_ops', 0)) / 200.0
        
        # Entropy and density
        features[8] = float(row.get('entropy', 4.0)) / 8.0
        features[9] = float(row.get('bitFlipDensity', 0.5))
        
        # Structural features
        features[10] = float(row.get('cyclomaticComplexity', 10)) / 50.0
        features[11] = float(row.get('basicBlocks', 20)) / 100.0
        features[12] = float(row.get('constantOccurrence', 10)) / 50.0
        features[13] = float(row.get('stringReferences', 0)) / 20.0
        features[14] = float(row.get('apiCalls', 0)) / 30.0
        
        # Size features
        features[15] = float(row.get('codeSize', 1000)) / 5000.0
        features[16] = float(row.get('dataSegmentSize', 500)) / 2000.0
        features[17] = float(row.get('stackUsage', 500)) / 2000.0
        
        # Binary flags
        features[18] = float(row.get('has_sbox', 0))
        features[19] = float(row.get('has_permutation', 0))
        features[20] = float(row.get('has_rounds', 0))
        features[21] = float(row.get('key_schedule', 0))
        features[22] = float(row.get('bitwise_heavy', 0))
        features[23] = float(row.get('arithmetic_heavy', 0))
        features[24] = float(row.get('is_proprietary', 1))
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names in order."""
        return [
            'xor_ops_norm', 'shift_ops_norm', 'add_ops_norm', 'mul_ops_norm',
            'branch_ops_norm', 'loop_ops_norm', 'memory_access_norm', 'bitwise_ops_norm',
            'entropy_norm', 'bit_flip_density',
            'cyclomatic_complexity_norm', 'basic_blocks_norm', 'constant_occurrence_norm',
            'string_references_norm', 'api_calls_norm',
            'code_size_norm', 'data_segment_size_norm', 'stack_usage_norm',
            'has_sbox', 'has_permutation', 'has_rounds', 'key_schedule',
            'bitwise_heavy', 'arithmetic_heavy', 'is_proprietary'
        ]

