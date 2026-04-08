"""
Metadata parser for firmware files
"""
from typing import Dict, Optional
import struct
import os


def detect_architecture(data: bytes) -> str:
    """
    Detect CPU architecture from binary data.
    
    Args:
        data: Binary firmware data
        
    Returns:
        Architecture string (ARM, MIPS, x86, etc.)
        
    Example:
        >>> arch = detect_architecture(firmware_bytes)
        >>> # Returns: "ARM", "MIPS", "x86", or "UNKNOWN"
    """
    if len(data) < 4:
        return "UNKNOWN"
    
    # ELF magic number
    if data[:4] == b'\x7fELF':
        # Check ELF class (32-bit vs 64-bit)
        ei_class = data[4]
        # Check machine type
        if ei_class == 1:  # 32-bit
            machine = struct.unpack('<H', data[18:20])[0]
        else:  # 64-bit
            machine = struct.unpack('<H', data[18:20])[0]
        
        # Machine type mappings
        machine_types = {
            0x03: "x86",
            0x3E: "x86_64",
            0x28: "ARM",
            0xB7: "AArch64",
            0x08: "MIPS",
            0x14: "PowerPC",
            0xF3: "RISC-V"
        }
        return machine_types.get(machine, "UNKNOWN")
    
    # PE (Windows) magic
    if data[:2] == b'MZ':
        return "x86"  # Default for PE
    
    # ARM thumb patterns
    if len(data) >= 2:
        # Check for ARM/Thumb instruction patterns
        first_word = struct.unpack('<H', data[:2])[0]
        if (first_word & 0xF800) in [0xE800, 0xF000, 0xF800]:  # Common ARM patterns
            return "ARM"
    
    return "UNKNOWN"


def is_elf_file(data: bytes) -> bool:
    """
    Check if data is an ELF file.
    
    Args:
        data: Binary data
        
    Returns:
        True if ELF format
    """
    return len(data) >= 4 and data[:4] == b'\x7fELF'


def is_bin_file(data: bytes) -> bool:
    """
    Check if data appears to be a raw binary (not ELF/PE).
    
    Args:
        data: Binary data
        
    Returns:
        True if raw binary format
    """
    return not is_elf_file(data) and len(data) > 0


def count_sections_elf(data: bytes) -> int:
    """
    Count sections in ELF file.
    
    Args:
        data: ELF binary data
        
    Returns:
        Number of sections
    """
    if not is_elf_file(data) or len(data) < 64:
        return 0
    
    try:
        ei_class = data[4]
        if ei_class == 1:  # 32-bit ELF
            e_shoff = struct.unpack('<I', data[32:36])[0]
            e_shnum = struct.unpack('<H', data[48:50])[0]
        else:  # 64-bit ELF
            e_shoff = struct.unpack('<Q', data[40:48])[0]
            e_shnum = struct.unpack('<H', data[60:62])[0]
        
        return e_shnum
    except:
        return 0


def extract_metadata(filepath: Optional[str] = None, data: Optional[bytes] = None) -> Dict:
    """
    Extract metadata features from firmware file.
    
    Args:
        filepath: Path to firmware file (optional if data provided)
        data: Binary data (optional if filepath provided)
        
    Returns:
        Dictionary with metadata features
        
    Example:
        >>> metadata = extract_metadata(filepath="firmware.bin")
        >>> # Returns: {
        >>> #     "arch_type": "ARM",
        >>> #     "file_size": 1024000,
        >>> #     "num_sections": 12,
        >>> #     "is_ELF": True,
        >>> #     "is_BIN": False
        >>> # }
    """
    if data is None:
        if filepath is None:
            raise ValueError("Either filepath or data must be provided")
        with open(filepath, 'rb') as f:
            data = f.read()
    
    # Detect architecture
    arch = detect_architecture(data)
    
    # File size
    file_size = len(data)
    
    # Check ELF/BIN
    is_elf = is_elf_file(data)
    is_bin = is_bin_file(data)
    
    # Count sections (if ELF)
    num_sections = count_sections_elf(data) if is_elf else 0
    
    return {
        "arch_type": arch,
        "file_size": file_size,
        "num_sections": num_sections,
        "is_ELF": is_elf,
        "is_BIN": is_bin
    }


def metadata_to_vector(metadata: Dict) -> list:
    """
    Convert metadata dictionary to feature vector.
    
    Args:
        metadata: Metadata dictionary
        
    Returns:
        List of numeric features
        
    Example:
        >>> vec = metadata_to_vector(metadata)
        >>> # Returns: [0.0, 1.0, 0.0, 1024000.0, 12.0]
        >>> # (ARM=0, MIPS=1, x86=0, file_size, num_sections)
    """
    # Architecture encoding (one-hot-like)
    arch_encodings = {
        "ARM": [1.0, 0.0, 0.0],
        "MIPS": [0.0, 1.0, 0.0],
        "x86": [0.0, 0.0, 1.0],
        "x86_64": [0.0, 0.0, 1.0],
        "AArch64": [1.0, 0.0, 0.0],
        "UNKNOWN": [0.0, 0.0, 0.0]
    }
    
    arch_vec = arch_encodings.get(metadata["arch_type"], [0.0, 0.0, 0.0])
    
    # Normalize file size (log scale)
    file_size = metadata["file_size"]
    log_file_size = 0.0 if file_size == 0 else (1.0 + (file_size.bit_length() - 1) / 32.0)
    
    # Normalize section count
    num_sections = min(metadata["num_sections"] / 100.0, 1.0)
    
    # Boolean flags
    is_elf = 1.0 if metadata["is_ELF"] else 0.0
    is_bin = 1.0 if metadata["is_BIN"] else 0.0
    
    # Combine: [arch_3d, log_file_size, num_sections, is_ELF, is_BIN]
    # For config compatibility, we'll use 5 features total
    # Use first arch encoding + file_size + sections + flags
    return [
        arch_vec[0],  # ARM indicator
        arch_vec[1],  # MIPS indicator  
        log_file_size,
        num_sections,
        is_elf
    ]

