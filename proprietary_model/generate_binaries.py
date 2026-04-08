"""
Proprietary Cryptographic Binary Generator

Generates 20 proprietary cryptographic algorithm implementations with 1000 variations each.
Each algorithm has unique characteristics that differentiate it from standard crypto.

Total output: 20,000 binary files with extracted features saved to CSV.
"""
import os
import sys
import numpy as np
import struct
import hashlib
import random
from typing import List, Tuple, Dict, Any
from pathlib import Path
from tqdm import tqdm
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import (
    PROPRIETARY_ALGORITHMS, OPERATION_LABELS, CRYPTO_TYPES,
    NUM_ALGORITHMS, VARIATIONS_PER_ALGO, TOTAL_BINARIES,
    MIN_CODE_SIZE, MAX_CODE_SIZE, MIN_DATA_SIZE, MAX_DATA_SIZE,
    MIN_STACK_SIZE, MAX_STACK_SIZE
)


class ProprietaryCryptoGenerator:
    """
    Generates proprietary cryptographic binaries with varying characteristics.
    
    Each algorithm class implements unique patterns that AI needs to learn.
    """
    
    def __init__(self, output_dir: str = "generated_binaries"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Algorithm-specific generators
        self.generators = {
            "CustomXOR": self._generate_custom_xor,
            "PropFeistel": self._generate_prop_feistel,
            "BitMixCipher": self._generate_bitmix_cipher,
            "RotaryHash": self._generate_rotary_hash,
            "ArithBlock": self._generate_arith_block,
            "SubPermute": self._generate_subpermute,
            "ChainMix": self._generate_chain_mix,
            "StreamLFSR": self._generate_stream_lfsr,
            "MixColumn": self._generate_mix_column,
            "BitShuffler": self._generate_bit_shuffler,
            "ModularCrypt": self._generate_modular_crypt,
            "LayerCascade": self._generate_layer_cascade,
            "NonLinearBox": self._generate_nonlinear_box,
            "DiffusionNet": self._generate_diffusion_net,
            "ConfusionCore": self._generate_confusion_core,
            "HybridCrypt": self._generate_hybrid_crypt,
            "KeyScheduler": self._generate_key_scheduler,
            "StateTransform": self._generate_state_transform,
            "BlockPermute": self._generate_block_permute,
            "StreamMix": self._generate_stream_mix,
        }
        
        # Operation characteristics per algorithm
        self.algo_operations = {
            "CustomXOR": ["Encryption", "Decryption", "KeyGeneration"],
            "PropFeistel": ["Encryption", "Decryption", "KeyExpansion"],
            "BitMixCipher": ["Encryption", "Decryption"],
            "RotaryHash": ["Hashing", "MAC"],
            "ArithBlock": ["Encryption", "Decryption", "KeyGeneration"],
            "SubPermute": ["Encryption", "Decryption"],
            "ChainMix": ["Encryption", "Decryption", "MAC"],
            "StreamLFSR": ["Encryption", "Decryption", "PRNG"],
            "MixColumn": ["Encryption", "Decryption"],
            "BitShuffler": ["Encryption", "Decryption", "KeyExpansion"],
            "ModularCrypt": ["Encryption", "Decryption", "Signing", "Verification"],
            "LayerCascade": ["Encryption", "Decryption"],
            "NonLinearBox": ["Encryption", "Decryption", "KeyGeneration"],
            "DiffusionNet": ["Encryption", "Decryption", "Hashing"],
            "ConfusionCore": ["Encryption", "Decryption"],
            "HybridCrypt": ["Encryption", "Decryption", "MAC", "Signing"],
            "KeyScheduler": ["KeyGeneration", "KeyExpansion", "KeyDerivation"],
            "StateTransform": ["Encryption", "Decryption", "Hashing"],
            "BlockPermute": ["Encryption", "Decryption"],
            "StreamMix": ["Encryption", "Decryption", "PRNG"],
        }
        
        # Crypto type per algorithm
        self.algo_types = {
            "CustomXOR": "BlockCipher",
            "PropFeistel": "BlockCipher",
            "BitMixCipher": "BlockCipher",
            "RotaryHash": "HashFunction",
            "ArithBlock": "BlockCipher",
            "SubPermute": "BlockCipher",
            "ChainMix": "BlockCipher",
            "StreamLFSR": "StreamCipher",
            "MixColumn": "BlockCipher",
            "BitShuffler": "BlockCipher",
            "ModularCrypt": "AsymmetricCrypto",
            "LayerCascade": "BlockCipher",
            "NonLinearBox": "BlockCipher",
            "DiffusionNet": "BlockCipher",
            "ConfusionCore": "BlockCipher",
            "HybridCrypt": "BlockCipher",
            "KeyScheduler": "KeyExchange",
            "StateTransform": "BlockCipher",
            "BlockPermute": "BlockCipher",
            "StreamMix": "StreamCipher",
        }
    
    def _generate_sbox(self, seed: int) -> bytes:
        """Generate a custom S-box based on seed."""
        np.random.seed(seed)
        sbox = list(range(256))
        np.random.shuffle(sbox)
        return bytes(sbox)
    
    def _generate_permutation_table(self, size: int, seed: int) -> List[int]:
        """Generate permutation table."""
        np.random.seed(seed)
        table = list(range(size))
        np.random.shuffle(table)
        return table
    
    def _generate_round_constants(self, num_rounds: int, seed: int) -> List[int]:
        """Generate round constants."""
        np.random.seed(seed)
        return [np.random.randint(0, 0xFFFFFFFF) for _ in range(num_rounds)]
    
    def _create_binary_structure(
        self,
        code_section: bytes,
        data_section: bytes,
        algo_name: str,
        variation: int
    ) -> bytes:
        """Create structured binary with header."""
        # Custom header format
        magic = b"PROP"  # Proprietary marker
        version = struct.pack("<H", 1)
        algo_id = struct.pack("<H", PROPRIETARY_ALGORITHMS.index(algo_name))
        var_id = struct.pack("<I", variation)
        code_size = struct.pack("<I", len(code_section))
        data_size = struct.pack("<I", len(data_section))
        
        header = magic + version + algo_id + var_id + code_size + data_size
        header = header.ljust(64, b'\x00')  # Pad header to 64 bytes
        
        return header + code_section + data_section
    
    # ==================== Algorithm Generators ====================
    
    def _generate_custom_xor(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate CustomXOR cipher - heavy XOR operations."""
        np.random.seed(variation * 1000)
        
        # Features for this algorithm
        xor_ops = 40 + np.random.randint(0, 30)
        shift_ops = 10 + np.random.randint(0, 20)
        add_ops = 5 + np.random.randint(0, 15)
        mul_ops = 2 + np.random.randint(0, 10)
        
        # Generate code section (XOR-heavy opcodes)
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # XOR patterns (0x31-0x35 are XOR opcodes on x86)
        for _ in range(xor_ops):
            code.extend([0x31 + np.random.randint(0, 5), np.random.randint(0, 256)])
        
        # Shift operations
        for _ in range(shift_ops):
            code.extend([0xC0 + np.random.randint(0, 8), np.random.randint(0, 256)])
        
        # Fill remaining with NOP-like patterns
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        code = bytes(code[:code_size])
        
        # Generate data section with XOR key patterns
        data_size = np.random.randint(MIN_DATA_SIZE, MAX_DATA_SIZE)
        key = bytes([np.random.randint(0, 256) for _ in range(32)])
        data = (key * (data_size // 32 + 1))[:data_size]
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": add_ops,
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(5, 25),
            "loop_ops": np.random.randint(3, 15),
            "memory_access": np.random.randint(15, 70),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 0,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code, bytes(data), "CustomXOR", variation)
        return binary, features
    
    def _generate_prop_feistel(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Proprietary Feistel Network - balanced operations."""
        np.random.seed(variation * 1001)
        
        num_rounds = 8 + np.random.randint(0, 8)
        xor_ops = 20 + np.random.randint(0, 20)
        shift_ops = 20 + np.random.randint(0, 20)
        add_ops = 15 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Generate round structure
        for r in range(num_rounds):
            # XOR step
            code.extend([0x31, np.random.randint(0, 256)])
            # Shift step
            code.extend([0xC1, np.random.randint(0, 8)])
            # Add step
            code.extend([0x01, np.random.randint(0, 256)])
            # Branch back
            code.extend([0x75, 0xF0])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        code = bytes(code[:code_size])
        
        # S-box data
        sbox = self._generate_sbox(variation)
        data = sbox + bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 256)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": add_ops,
            "mul_ops": np.random.randint(2, 15),
            "branch_ops": num_rounds * 2,
            "loop_ops": num_rounds,
            "memory_access": np.random.randint(20, 80),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 1,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code, data[:MAX_DATA_SIZE], "PropFeistel", variation)
        return binary, features
    
    def _generate_bitmix_cipher(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate BitMix Cipher - bit shuffling and mixing."""
        np.random.seed(variation * 1002)
        
        xor_ops = 30 + np.random.randint(0, 25)
        shift_ops = 35 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Bit mixing patterns
        for _ in range(shift_ops):
            # ROL/ROR patterns
            code.extend([0xD1 + np.random.randint(0, 4), np.random.randint(0, 256)])
            # AND/OR for bit selection
            code.extend([0x21 + np.random.randint(0, 4), np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        data_size = np.random.randint(MIN_DATA_SIZE, MAX_DATA_SIZE)
        data = bytes([np.random.randint(0, 256) for _ in range(data_size)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(5, 20),
            "mul_ops": np.random.randint(2, 10),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(5, 20),
            "memory_access": np.random.randint(25, 75),
            "bitwise_ops": xor_ops + shift_ops + 40,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "BitMixCipher", variation)
        return binary, features
    
    def _generate_rotary_hash(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Rotary Hash - rotation-based hash function."""
        np.random.seed(variation * 1003)
        
        shift_ops = 40 + np.random.randint(0, 30)
        add_ops = 30 + np.random.randint(0, 25)
        xor_ops = 25 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Hash round structure
        for _ in range(16):
            # Rotation
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            # Addition
            code.extend([0x01, np.random.randint(0, 256)])
            # XOR
            code.extend([0x31, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Initial hash values
        data = struct.pack("<IIIIIIII", 
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
        data += bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 32)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": add_ops,
            "mul_ops": np.random.randint(0, 10),
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(30, 70),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "RotaryHash", variation)
        return binary, features
    
    def _generate_arith_block(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Arithmetic Block Cipher - heavy arithmetic operations."""
        np.random.seed(variation * 1004)
        
        add_ops = 35 + np.random.randint(0, 30)
        mul_ops = 25 + np.random.randint(0, 25)
        xor_ops = 15 + np.random.randint(0, 15)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Arithmetic patterns
        for _ in range(add_ops):
            code.extend([0x01 + np.random.randint(0, 4), np.random.randint(0, 256)])
        for _ in range(mul_ops):
            code.extend([0xF7, 0xE0 + np.random.randint(0, 8)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        data_size = np.random.randint(MIN_DATA_SIZE, MAX_DATA_SIZE)
        data = bytes([np.random.randint(0, 256) for _ in range(data_size)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": np.random.randint(5, 20),
            "add_ops": add_ops,
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(8, 30),
            "loop_ops": np.random.randint(5, 15),
            "memory_access": np.random.randint(20, 60),
            "bitwise_ops": xor_ops + np.random.randint(10, 30),
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 0,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "ArithBlock", variation)
        return binary, features
    
    def _generate_subpermute(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Substitution-Permutation Network."""
        np.random.seed(variation * 1005)
        
        xor_ops = 25 + np.random.randint(0, 25)
        shift_ops = 20 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # SPN structure
        num_rounds = 6 + np.random.randint(0, 6)
        for _ in range(num_rounds):
            # Substitution layer (lookup table access)
            code.extend([0x8A, 0x80 + np.random.randint(0, 8)])
            # Permutation layer (bit shuffling)
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            # Key mixing
            code.extend([0x31, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # S-box and P-box
        sbox = self._generate_sbox(variation)
        pbox = bytes(self._generate_permutation_table(256, variation + 1))
        data = sbox + pbox
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(5, 20),
            "mul_ops": np.random.randint(2, 10),
            "branch_ops": num_rounds * 2,
            "loop_ops": num_rounds,
            "memory_access": np.random.randint(40, 90),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 1,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "SubPermute", variation)
        return binary, features
    
    def _generate_chain_mix(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Chain Mix Cipher."""
        np.random.seed(variation * 1006)
        
        xor_ops = 30 + np.random.randint(0, 25)
        add_ops = 25 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Chaining structure
        for _ in range(xor_ops):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0x01, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        data_size = np.random.randint(MIN_DATA_SIZE, MAX_DATA_SIZE)
        # IV and chain values
        data = bytes([np.random.randint(0, 256) for _ in range(data_size)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": np.random.randint(10, 25),
            "add_ops": add_ops,
            "mul_ops": np.random.randint(2, 12),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(8, 20),
            "memory_access": np.random.randint(30, 80),
            "bitwise_ops": xor_ops + np.random.randint(10, 25),
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "ChainMix", variation)
        return binary, features
    
    def _generate_stream_lfsr(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate LFSR-based Stream Cipher."""
        np.random.seed(variation * 1007)
        
        xor_ops = 35 + np.random.randint(0, 30)
        shift_ops = 40 + np.random.randint(0, 30)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # LFSR structure
        for _ in range(shift_ops):
            code.extend([0xD1, 0xE8 + np.random.randint(0, 8)])  # SHR
            code.extend([0x31, np.random.randint(0, 256)])  # XOR feedback
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # LFSR tap positions and initial state
        data = struct.pack("<IIII", 
            np.random.randint(0, 0xFFFFFFFF),
            np.random.randint(0, 0xFFFFFFFF),
            np.random.randint(0, 0xFFFFFFFF),
            np.random.randint(0, 0xFFFFFFFF))
        data += bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 16)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(3, 15),
            "mul_ops": np.random.randint(0, 8),
            "branch_ops": np.random.randint(5, 20),
            "loop_ops": np.random.randint(15, 35),
            "memory_access": np.random.randint(15, 50),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 0,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "StreamLFSR", variation)
        return binary, features
    
    def _generate_mix_column(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate MixColumn-based Cipher."""
        np.random.seed(variation * 1008)
        
        xor_ops = 30 + np.random.randint(0, 25)
        mul_ops = 25 + np.random.randint(0, 20)
        shift_ops = 15 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Matrix multiplication patterns
        for _ in range(mul_ops):
            code.extend([0xF7, 0xE0 + np.random.randint(0, 8)])
            code.extend([0x31, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Mix matrix
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(5, 20),
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(8, 20),
            "memory_access": np.random.randint(35, 85),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 0,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "MixColumn", variation)
        return binary, features
    
    def _generate_bit_shuffler(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Bit Shuffler Cipher."""
        np.random.seed(variation * 1009)
        
        shift_ops = 45 + np.random.randint(0, 30)
        xor_ops = 20 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Bit shuffling patterns
        for _ in range(shift_ops):
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            code.extend([0x0F, 0xA3 + np.random.randint(0, 4)])  # BT/BTS/BTR
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Shuffle table
        data = bytes(self._generate_permutation_table(256, variation))
        data += bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 256)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(3, 15),
            "mul_ops": np.random.randint(1, 8),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(40, 90),
            "bitwise_ops": xor_ops + shift_ops + 30,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "BitShuffler", variation)
        return binary, features
    
    def _generate_modular_crypt(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Modular Arithmetic Cipher."""
        np.random.seed(variation * 1010)
        
        mul_ops = 40 + np.random.randint(0, 30)
        add_ops = 30 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Modular arithmetic patterns
        for _ in range(mul_ops):
            code.extend([0xF7, 0xE0 + np.random.randint(0, 8)])  # MUL
            code.extend([0xF7, 0xF0 + np.random.randint(0, 8)])  # DIV/MOD
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Large primes and moduli
        data = struct.pack("<QQQQ",
            np.random.randint(2**60, 2**63),
            np.random.randint(2**60, 2**63),
            np.random.randint(2**60, 2**63),
            np.random.randint(2**60, 2**63))
        data += bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 32)])
        
        features = {
            "xor_ops": np.random.randint(5, 20),
            "shift_ops": np.random.randint(5, 20),
            "add_ops": add_ops,
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(10, 30),
            "memory_access": np.random.randint(20, 60),
            "bitwise_ops": np.random.randint(15, 40),
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 0,
            "key_schedule": 1,
            "bitwise_heavy": 0,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "ModularCrypt", variation)
        return binary, features
    
    def _generate_layer_cascade(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Layered Cascade Cipher."""
        np.random.seed(variation * 1011)
        
        num_layers = 4 + np.random.randint(0, 4)
        xor_ops = 25 + np.random.randint(0, 20)
        shift_ops = 25 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Layered structure
        for layer in range(num_layers):
            # Each layer has different operations
            if layer % 2 == 0:
                code.extend([0x31, np.random.randint(0, 256)])  # XOR
            else:
                code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])  # Rotate
            code.extend([0x01, np.random.randint(0, 256)])  # ADD
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(15, 35),
            "mul_ops": np.random.randint(3, 15),
            "branch_ops": num_layers * 2,
            "loop_ops": num_layers,
            "memory_access": np.random.randint(30, 70),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "LayerCascade", variation)
        return binary, features
    
    def _generate_nonlinear_box(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Non-Linear S-box Cipher."""
        np.random.seed(variation * 1012)
        
        xor_ops = 25 + np.random.randint(0, 25)
        mul_ops = 15 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Non-linear table lookups
        for _ in range(30):
            code.extend([0x8A, 0x80 + np.random.randint(0, 8)])  # MOV from table
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0xF7, 0xE0 + np.random.randint(0, 8)])  # MUL for nonlinearity
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Non-linear S-box
        sbox = self._generate_sbox(variation)
        inv_sbox = bytes([sbox.index(i) if i in sbox else 0 for i in range(256)])
        data = sbox + inv_sbox
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": np.random.randint(10, 25),
            "add_ops": np.random.randint(5, 20),
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(8, 20),
            "memory_access": np.random.randint(50, 100),
            "bitwise_ops": xor_ops + np.random.randint(10, 30),
            "has_sbox": 1,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 0,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "NonLinearBox", variation)
        return binary, features
    
    def _generate_diffusion_net(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Diffusion Network Cipher."""
        np.random.seed(variation * 1013)
        
        xor_ops = 35 + np.random.randint(0, 25)
        shift_ops = 30 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Diffusion patterns
        for _ in range(xor_ops):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Diffusion matrix
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(10, 30),
            "mul_ops": np.random.randint(3, 15),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(35, 80),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "DiffusionNet", variation)
        return binary, features
    
    def _generate_confusion_core(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Confusion Core Cipher."""
        np.random.seed(variation * 1014)
        
        xor_ops = 40 + np.random.randint(0, 30)
        add_ops = 20 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Confusion patterns
        for _ in range(xor_ops):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0x21, np.random.randint(0, 256)])  # AND
            code.extend([0x09, np.random.randint(0, 256)])  # OR
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        sbox = self._generate_sbox(variation)
        data = sbox + bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 256)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": np.random.randint(10, 30),
            "add_ops": add_ops,
            "mul_ops": np.random.randint(2, 12),
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(8, 20),
            "memory_access": np.random.randint(40, 85),
            "bitwise_ops": xor_ops + np.random.randint(20, 40),
            "has_sbox": 1,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "ConfusionCore", variation)
        return binary, features
    
    def _generate_hybrid_crypt(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Hybrid Cryptosystem."""
        np.random.seed(variation * 1015)
        
        xor_ops = 25 + np.random.randint(0, 25)
        mul_ops = 25 + np.random.randint(0, 25)
        add_ops = 25 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Hybrid structure (symmetric + asymmetric patterns)
        for _ in range(20):
            code.extend([0x31, np.random.randint(0, 256)])  # XOR
            code.extend([0xF7, 0xE0 + np.random.randint(0, 8)])  # MUL
            code.extend([0x01, np.random.randint(0, 256)])  # ADD
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Keys for both symmetric and asymmetric
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": np.random.randint(15, 30),
            "add_ops": add_ops,
            "mul_ops": mul_ops,
            "branch_ops": np.random.randint(12, 35),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(35, 80),
            "bitwise_ops": xor_ops + np.random.randint(15, 35),
            "has_sbox": 1,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "HybridCrypt", variation)
        return binary, features
    
    def _generate_key_scheduler(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Key Scheduling Algorithm."""
        np.random.seed(variation * 1016)
        
        xor_ops = 30 + np.random.randint(0, 25)
        shift_ops = 25 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Key expansion patterns
        for _ in range(xor_ops):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            code.extend([0x8A, 0x80 + np.random.randint(0, 8)])  # Table lookup
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Round constants
        rcon = self._generate_round_constants(32, variation)
        data = struct.pack("<" + "I" * 32, *rcon)
        data += bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 128)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(10, 25),
            "mul_ops": np.random.randint(2, 12),
            "branch_ops": np.random.randint(8, 25),
            "loop_ops": np.random.randint(12, 30),
            "memory_access": np.random.randint(45, 90),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 1,
            "has_permutation": 0,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "KeyScheduler", variation)
        return binary, features
    
    def _generate_state_transform(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate State Transformation Cipher."""
        np.random.seed(variation * 1017)
        
        xor_ops = 30 + np.random.randint(0, 25)
        shift_ops = 30 + np.random.randint(0, 25)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # State transformation patterns
        for _ in range(30):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            code.extend([0x01, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # State matrix
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(15, 35),
            "mul_ops": np.random.randint(3, 15),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(35, 80),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "StateTransform", variation)
        return binary, features
    
    def _generate_block_permute(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Block Permutation Cipher."""
        np.random.seed(variation * 1018)
        
        shift_ops = 35 + np.random.randint(0, 30)
        xor_ops = 20 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Block permutation patterns
        for _ in range(shift_ops):
            code.extend([0xD1, 0xC0 + np.random.randint(0, 8)])
            code.extend([0x0F, 0xC8 + np.random.randint(0, 8)])  # BSWAP
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Permutation table
        pbox = bytes(self._generate_permutation_table(256, variation))
        data = pbox + bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE - 256)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": np.random.randint(5, 20),
            "mul_ops": np.random.randint(2, 10),
            "branch_ops": np.random.randint(10, 30),
            "loop_ops": np.random.randint(10, 25),
            "memory_access": np.random.randint(45, 95),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 1,
            "has_rounds": 1,
            "key_schedule": 0,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 0,
        }
        
        binary = self._create_binary_structure(code[:code_size], data[:MAX_DATA_SIZE], "BlockPermute", variation)
        return binary, features
    
    def _generate_stream_mix(self, variation: int) -> Tuple[bytes, Dict[str, Any]]:
        """Generate Stream Mixing Cipher."""
        np.random.seed(variation * 1019)
        
        xor_ops = 40 + np.random.randint(0, 30)
        add_ops = 30 + np.random.randint(0, 25)
        shift_ops = 25 + np.random.randint(0, 20)
        
        code_size = np.random.randint(MIN_CODE_SIZE, MAX_CODE_SIZE)
        code = bytearray()
        
        # Stream mixing patterns
        for _ in range(xor_ops):
            code.extend([0x31, np.random.randint(0, 256)])
            code.extend([0x01, np.random.randint(0, 256)])
        
        while len(code) < code_size:
            code.append(np.random.randint(0, 256))
        
        # Stream state
        data = bytes([np.random.randint(0, 256) for _ in range(MAX_DATA_SIZE)])
        
        features = {
            "xor_ops": xor_ops,
            "shift_ops": shift_ops,
            "add_ops": add_ops,
            "mul_ops": np.random.randint(3, 15),
            "branch_ops": np.random.randint(5, 20),
            "loop_ops": np.random.randint(15, 35),
            "memory_access": np.random.randint(20, 60),
            "bitwise_ops": xor_ops + shift_ops,
            "has_sbox": 0,
            "has_permutation": 0,
            "has_rounds": 0,
            "key_schedule": 1,
            "bitwise_heavy": 1,
            "arithmetic_heavy": 1,
        }
        
        binary = self._create_binary_structure(code[:code_size], data, "StreamMix", variation)
        return binary, features
    
    def generate_all(self, save_binaries: bool = True) -> pd.DataFrame:
        """Generate all 20,000 binaries and return features DataFrame."""
        all_features = []
        
        print("=" * 80)
        print("Proprietary Cryptographic Binary Generator")
        print(f"Generating {TOTAL_BINARIES} binaries ({NUM_ALGORITHMS} algorithms × {VARIATIONS_PER_ALGO} variations)")
        print("=" * 80)
        
        for algo_idx, algo_name in enumerate(PROPRIETARY_ALGORITHMS):
            print(f"\n[{algo_idx + 1}/{NUM_ALGORITHMS}] Generating {algo_name}...")
            generator = self.generators[algo_name]
            operations = self.algo_operations[algo_name]
            crypto_type = self.algo_types[algo_name]
            
            for var_idx in tqdm(range(VARIATIONS_PER_ALGO), desc=f"  {algo_name}"):
                # Generate binary and features
                binary, features = generator(var_idx)
                
                # Select operation label (cycle through available operations)
                operation = operations[var_idx % len(operations)]
                
                # Calculate additional features
                entropy = self._calculate_entropy(binary)
                bit_flip_density = self._calculate_bit_flip_density(binary)
                
                # Create feature record
                record = {
                    "file_id": f"crypto_{algo_idx}_{var_idx}",
                    "algorithm_name": algo_name,
                    "variation_id": var_idx,
                    "operation_label": operation,
                    "crypto_type": crypto_type,
                    "xor_ops": features["xor_ops"],
                    "shift_ops": features["shift_ops"],
                    "add_ops": features["add_ops"],
                    "mul_ops": features["mul_ops"],
                    "branch_ops": features["branch_ops"],
                    "loop_ops": features["loop_ops"],
                    "memory_access": features["memory_access"],
                    "bitwise_ops": features["bitwise_ops"],
                    "entropy": round(entropy, 4),
                    "bitFlipDensity": round(bit_flip_density, 4),
                    "cyclomaticComplexity": 10 + (var_idx % 40),
                    "basicBlocks": 17 + (var_idx % 60),
                    "constantOccurrence": 5 + (var_idx % 30),
                    "stringReferences": var_idx % 10,
                    "apiCalls": 1 + (var_idx % 18),
                    "codeSize": len(binary) - 64,  # Exclude header
                    "dataSegmentSize": features.get("data_size", np.random.randint(64, 600)),
                    "stackUsage": np.random.randint(MIN_STACK_SIZE, MAX_STACK_SIZE),
                    "has_sbox": features["has_sbox"],
                    "has_permutation": features["has_permutation"],
                    "has_rounds": features["has_rounds"],
                    "key_schedule": features["key_schedule"],
                    "bitwise_heavy": features["bitwise_heavy"],
                    "arithmetic_heavy": features["arithmetic_heavy"],
                    "is_proprietary": 1,
                }
                
                all_features.append(record)
                
                # Save binary file
                if save_binaries:
                    binary_path = self.output_dir / f"crypto_{algo_idx}_{var_idx}.bin"
                    with open(binary_path, 'wb') as f:
                        f.write(binary)
        
        # Create DataFrame
        df = pd.DataFrame(all_features)
        
        # Save CSV
        csv_path = self.output_dir / "proprietary_dataset.csv"
        df.to_csv(csv_path, index=False)
        print(f"\n[OK] Dataset saved to {csv_path}")
        print(f"Total samples: {len(df)}")
        print(f"Algorithms: {df['algorithm_name'].nunique()}")
        print(f"Operations: {df['operation_label'].nunique()}")
        
        return df
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if len(data) == 0:
            return 0.0
        
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        probabilities = byte_counts / len(data)
        probabilities = probabilities[probabilities > 0]
        
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    
    def _calculate_bit_flip_density(self, data: bytes) -> float:
        """Calculate bit flip density between consecutive bytes."""
        if len(data) < 2:
            return 0.0
        
        total_flips = 0
        for i in range(len(data) - 1):
            xor_result = data[i] ^ data[i + 1]
            total_flips += bin(xor_result).count('1')
        
        max_flips = (len(data) - 1) * 8
        return total_flips / max_flips if max_flips > 0 else 0.0


def main():
    """Main function to generate all binaries."""
    generator = ProprietaryCryptoGenerator(output_dir="generated_binaries")
    df = generator.generate_all(save_binaries=True)
    
    # Print statistics
    print("\n" + "=" * 80)
    print("Generation Complete!")
    print("=" * 80)
    print(f"\nDataset Statistics:")
    print(f"  Total samples: {len(df)}")
    print(f"  Algorithms: {sorted(df['algorithm_name'].unique())}")
    print(f"  Operations: {sorted(df['operation_label'].unique())}")
    print(f"  Crypto types: {sorted(df['crypto_type'].unique())}")
    print(f"\nOperation distribution:")
    print(df['operation_label'].value_counts())
    print(f"\nAlgorithm distribution:")
    print(df['algorithm_name'].value_counts())


if __name__ == "__main__":
    main()

