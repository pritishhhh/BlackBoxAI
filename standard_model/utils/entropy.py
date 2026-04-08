"""
Entropy calculation utilities for cryptographic detection
"""
import math
from typing import List, Tuple
import numpy as np


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    
    Args:
        data: Byte sequence to analyze
        
    Returns:
        Entropy value (0-8 for bytes)
        
    Example:
        >>> entropy = calculate_shannon_entropy(b"Hello World")
        >>> print(f"Entropy: {entropy:.2f}")
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_chunk_entropy(data: bytes, chunk_size: int = 256) -> List[float]:
    """
    Calculate entropy for each chunk of data.
    
    Args:
        data: Byte sequence to analyze
        chunk_size: Size of each chunk in bytes
        
    Returns:
        List of entropy values for each chunk
        
    Example:
        >>> entropies = calculate_chunk_entropy(firmware_bytes, chunk_size=512)
        >>> high_entropy_chunks = [i for i, e in enumerate(entropies) if e > 7.0]
    """
    entropies = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        entropy = calculate_shannon_entropy(chunk)
        entropies.append(entropy)
    return entropies


def get_entropy_distribution_vector(data: bytes, num_bins: int = 10) -> np.ndarray:
    """
    Create an entropy distribution vector by analyzing chunks.
    
    Args:
        data: Byte sequence to analyze
        num_bins: Number of bins for distribution
        
    Returns:
        Normalized entropy distribution vector
        
    Example:
        >>> entropy_vec = get_entropy_distribution_vector(firmware_bytes)
        >>> # Returns array of shape (10,) with normalized distribution
    """
    chunk_size = max(256, len(data) // 100)  # Adaptive chunk size
    entropies = calculate_chunk_entropy(data, chunk_size)
    
    if not entropies:
        return np.zeros(num_bins, dtype=np.float32)
    
    # Create histogram of entropy values
    hist, _ = np.histogram(entropies, bins=num_bins, range=(0.0, 8.0))
    
    # Normalize
    if hist.sum() > 0:
        hist = hist.astype(np.float32) / hist.sum()
    
    return hist


def find_high_entropy_regions(data: bytes, threshold: float = 7.0, 
                              chunk_size: int = 256) -> List[Tuple[int, int]]:
    """
    Find regions with high entropy (potential encrypted/compressed data).
    
    Args:
        data: Byte sequence to analyze
        threshold: Entropy threshold (default 7.0)
        chunk_size: Size of chunks to analyze
        
    Returns:
        List of (start_offset, end_offset) tuples for high entropy regions
        
    Example:
        >>> regions = find_high_entropy_regions(firmware_bytes, threshold=7.5)
        >>> for start, end in regions:
        >>>     print(f"High entropy: 0x{start:x}–0x{end:x}")
    """
    regions = []
    entropies = calculate_chunk_entropy(data, chunk_size)
    
    in_region = False
    start_offset = 0
    
    for i, entropy in enumerate(entropies):
        offset = i * chunk_size
        
        if entropy >= threshold:
            if not in_region:
                start_offset = offset
                in_region = True
        else:
            if in_region:
                end_offset = offset
                regions.append((start_offset, end_offset))
                in_region = False
    
    # Handle case where region extends to end
    if in_region:
        regions.append((start_offset, len(data)))
    
    return regions


def has_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """
    Check if data has high entropy (binary indicator).
    
    Args:
        data: Byte sequence to analyze
        threshold: Entropy threshold
        
    Returns:
        True if average entropy exceeds threshold
    """
    if not data:
        return False
    
    entropy = calculate_shannon_entropy(data)
    return entropy >= threshold

