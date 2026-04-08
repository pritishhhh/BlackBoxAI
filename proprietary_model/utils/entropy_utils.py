"""
Entropy calculation utilities for proprietary crypto detection.
"""
import numpy as np
from typing import List, Tuple
import math


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    
    Args:
        data: Binary data bytes
        
    Returns:
        Entropy value (0-8 for byte data)
    """
    if len(data) == 0:
        return 0.0
    
    byte_counts = np.zeros(256)
    for byte in data:
        byte_counts[byte] += 1
    
    probabilities = byte_counts / len(data)
    probabilities = probabilities[probabilities > 0]
    
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy


def get_entropy_distribution(data: bytes, num_chunks: int = 16) -> List[float]:
    """
    Calculate entropy distribution across chunks of data.
    
    Args:
        data: Binary data bytes
        num_chunks: Number of chunks to divide data into
        
    Returns:
        List of entropy values for each chunk
    """
    if len(data) == 0:
        return [0.0] * num_chunks
    
    chunk_size = max(1, len(data) // num_chunks)
    entropies = []
    
    for i in range(num_chunks):
        start = i * chunk_size
        end = start + chunk_size if i < num_chunks - 1 else len(data)
        chunk = data[start:end]
        entropies.append(calculate_entropy(chunk))
    
    return entropies


def get_entropy_features(data: bytes, num_features: int = 16) -> np.ndarray:
    """
    Extract entropy-based features for model input.
    
    Args:
        data: Binary data bytes
        num_features: Number of entropy features to extract
        
    Returns:
        Numpy array of entropy features
    """
    if len(data) == 0:
        return np.zeros(num_features, dtype=np.float32)
    
    # Get chunk entropies
    chunk_entropies = get_entropy_distribution(data, num_features - 4)
    
    # Overall statistics
    overall_entropy = calculate_entropy(data)
    mean_entropy = np.mean(chunk_entropies) if chunk_entropies else 0.0
    std_entropy = np.std(chunk_entropies) if chunk_entropies else 0.0
    max_entropy = max(chunk_entropies) if chunk_entropies else 0.0
    
    features = chunk_entropies + [overall_entropy, mean_entropy, std_entropy, max_entropy]
    
    # Pad or truncate to num_features
    features = features[:num_features]
    while len(features) < num_features:
        features.append(0.0)
    
    return np.array(features, dtype=np.float32)


def has_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """
    Check if data has high entropy (likely encrypted/compressed).
    
    Args:
        data: Binary data bytes
        threshold: Entropy threshold (0-8)
        
    Returns:
        True if entropy is above threshold
    """
    return calculate_entropy(data) >= threshold


def calculate_bit_flip_density(data: bytes) -> float:
    """
    Calculate bit flip density between consecutive bytes.
    
    Args:
        data: Binary data bytes
        
    Returns:
        Bit flip density (0-1)
    """
    if len(data) < 2:
        return 0.0
    
    total_flips = 0
    for i in range(len(data) - 1):
        xor_result = data[i] ^ data[i + 1]
        total_flips += bin(xor_result).count('1')
    
    max_flips = (len(data) - 1) * 8
    return total_flips / max_flips if max_flips > 0 else 0.0


def calculate_byte_distribution_uniformity(data: bytes) -> float:
    """
    Calculate how uniform the byte distribution is (0 = not uniform, 1 = perfectly uniform).
    
    Args:
        data: Binary data bytes
        
    Returns:
        Uniformity score (0-1)
    """
    if len(data) == 0:
        return 0.0
    
    byte_counts = np.zeros(256)
    for byte in data:
        byte_counts[byte] += 1
    
    expected_count = len(data) / 256
    chi_squared = np.sum((byte_counts - expected_count) ** 2 / expected_count)
    
    # Normalize to 0-1 range (inverse)
    max_chi = len(data) * 255  # Maximum possible chi-squared
    uniformity = 1 - min(1, chi_squared / max_chi)
    
    return uniformity

