"""
Proprietary Opcode Tokenizer for firmware binary analysis.
Enhanced for proprietary cryptographic pattern detection.
"""
import re
from typing import List, Dict, Optional, Set
import numpy as np
from collections import Counter


class ProprietaryOpcodeTokenizer:
    """
    Tokenizer for opcode sequences with proprietary crypto focus.
    
    Handles various ISA opcodes and creates embeddings suitable for
    transformer-based analysis of cryptographic primitives.
    """
    
    # Special tokens
    PAD_TOKEN = "<PAD>"
    UNK_TOKEN = "<UNK>"
    CLS_TOKEN = "<CLS>"
    SEP_TOKEN = "<SEP>"
    
    # Crypto-specific opcode groups
    CRYPTO_OPCODES = {
        # Bitwise operations (critical for crypto)
        'xor': ['xor', 'eor', 'xorr', 'xorl'],
        'and': ['and', 'andn', 'andl', 'andr'],
        'or': ['or', 'orr', 'orl', 'orn'],
        'not': ['not', 'notl', 'neg', 'com'],
        
        # Shift/rotate operations (critical for crypto)
        'shift': ['shl', 'shr', 'sal', 'sar', 'shld', 'shrd'],
        'rotate': ['rol', 'ror', 'rcl', 'rcr', 'rotl', 'rotr'],
        
        # Arithmetic operations
        'add': ['add', 'adc', 'addl', 'addr', 'inc'],
        'sub': ['sub', 'sbb', 'subl', 'subr', 'dec'],
        'mul': ['mul', 'imul', 'mull', 'mulr', 'smul'],
        'div': ['div', 'idiv', 'divl', 'mod', 'rem'],
        
        # Memory operations
        'load': ['mov', 'ldr', 'ld', 'ldm', 'ldrb', 'ldrsb', 'ldrh'],
        'store': ['str', 'st', 'stm', 'strb', 'strh', 'push'],
        
        # Control flow
        'branch': ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'b', 'beq', 'bne'],
        'call': ['call', 'bl', 'blx', 'ret', 'retn', 'leave'],
        'loop': ['loop', 'loope', 'loopne', 'rep', 'repz', 'repnz'],
        
        # Bit manipulation
        'bit': ['bt', 'bts', 'btr', 'btc', 'bsf', 'bsr', 'popcnt'],
        
        # SIMD (sometimes used in crypto)
        'simd': ['pxor', 'pand', 'por', 'paddb', 'paddw', 'paddd', 'psllw', 'psrlw'],
    }
    
    def __init__(self, max_vocab_size: int = 15000):
        """
        Initialize tokenizer.
        
        Args:
            max_vocab_size: Maximum vocabulary size
        """
        self.max_vocab_size = max_vocab_size
        self.word2idx: Dict[str, int] = {}
        self.idx2word: Dict[int, str] = {}
        self.word_counts: Counter = Counter()
        self.vocab_built = False
        
        # Initialize special tokens
        self._init_special_tokens()
        
        # Build initial vocabulary from known opcodes
        self._init_opcode_vocab()
    
    def _init_special_tokens(self):
        """Initialize special tokens in vocabulary."""
        special_tokens = [self.PAD_TOKEN, self.UNK_TOKEN, self.CLS_TOKEN, self.SEP_TOKEN]
        for idx, token in enumerate(special_tokens):
            self.word2idx[token] = idx
            self.idx2word[idx] = token
    
    def _init_opcode_vocab(self):
        """Initialize vocabulary with known opcode patterns."""
        idx = len(self.word2idx)
        
        # Add all known opcodes
        for group, opcodes in self.CRYPTO_OPCODES.items():
            for opcode in opcodes:
                if opcode not in self.word2idx:
                    self.word2idx[opcode] = idx
                    self.idx2word[idx] = opcode
                    idx += 1
        
        # Add register tokens
        for i in range(32):
            for reg_type in ['r', 'x', 'w', 'v', 's', 'd']:
                reg = f"{reg_type}{i}"
                if reg not in self.word2idx:
                    self.word2idx[reg] = idx
                    self.idx2word[idx] = reg
                    idx += 1
        
        # Add common constants
        for const in ['0', '1', '2', '4', '8', '16', '32', '64', '128', '256', '#0', '#1', '#8', '#16', '#32']:
            if const not in self.word2idx:
                self.word2idx[const] = idx
                self.idx2word[idx] = const
                idx += 1
    
    def _normalize_token(self, token: str) -> str:
        """Normalize token for consistent vocabulary."""
        token = token.lower().strip()
        
        # Remove common suffixes/prefixes
        token = re.sub(r'^0x', '', token)
        token = re.sub(r'[,\[\]\(\)\{\}]', '', token)
        
        # Normalize register names
        if re.match(r'^[rxwvsdaq]\d+$', token):
            return token
        
        # Normalize hex immediates
        if re.match(r'^[0-9a-f]+h?$', token) and len(token) > 2:
            return '#imm'
        
        # Normalize numeric immediates
        if re.match(r'^#?\d+$', token):
            num = int(re.sub(r'#', '', token))
            if num in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256]:
                return f"#{num}"
            return '#imm'
        
        return token
    
    def _tokenize_instruction(self, instruction: str) -> List[str]:
        """Tokenize a single instruction into components."""
        # Split by spaces and common delimiters
        parts = re.split(r'[\s,\[\]\(\)\{\}]+', instruction.strip())
        tokens = []
        
        for part in parts:
            if not part:
                continue
            normalized = self._normalize_token(part)
            if normalized:
                tokens.append(normalized)
        
        return tokens
    
    def build_vocab(self, sequences: List[List[str]], min_freq: int = 2):
        """
        Build vocabulary from opcode sequences.
        
        Args:
            sequences: List of opcode instruction lists
            min_freq: Minimum frequency for inclusion
        """
        # Count all tokens
        for seq in sequences:
            for instruction in seq:
                tokens = self._tokenize_instruction(instruction)
                self.word_counts.update(tokens)
        
        # Add frequent tokens to vocabulary
        idx = len(self.word2idx)
        for token, count in self.word_counts.most_common():
            if count < min_freq:
                break
            if token not in self.word2idx and idx < self.max_vocab_size:
                self.word2idx[token] = idx
                self.idx2word[idx] = token
                idx += 1
        
        self.vocab_built = True
        print(f"Vocabulary built: {len(self.word2idx)} tokens")
    
    def encode(self, sequence: List[str], max_length: int = 768, add_special: bool = True) -> List[int]:
        """
        Encode opcode sequence to token IDs.
        
        Args:
            sequence: List of opcode instructions
            max_length: Maximum sequence length
            add_special: Whether to add CLS/SEP tokens
            
        Returns:
            List of token IDs
        """
        tokens = []
        
        if add_special:
            tokens.append(self.word2idx[self.CLS_TOKEN])
        
        for instruction in sequence:
            instruction_tokens = self._tokenize_instruction(instruction)
            for token in instruction_tokens:
                if len(tokens) >= max_length - 1:
                    break
                tokens.append(self.word2idx.get(token, self.word2idx[self.UNK_TOKEN]))
        
        if add_special and len(tokens) < max_length:
            tokens.append(self.word2idx[self.SEP_TOKEN])
        
        # Pad to max_length
        while len(tokens) < max_length:
            tokens.append(self.word2idx[self.PAD_TOKEN])
        
        return tokens[:max_length]
    
    def decode(self, token_ids: List[int]) -> List[str]:
        """
        Decode token IDs back to tokens.
        
        Args:
            token_ids: List of token IDs
            
        Returns:
            List of token strings
        """
        tokens = []
        for idx in token_ids:
            token = self.idx2word.get(idx, self.UNK_TOKEN)
            if token not in [self.PAD_TOKEN, self.CLS_TOKEN, self.SEP_TOKEN]:
                tokens.append(token)
        return tokens
    
    def get_vocab_size(self) -> int:
        """Get current vocabulary size."""
        return len(self.word2idx)
    
    def get_crypto_token_ids(self) -> Set[int]:
        """Get set of token IDs that are crypto-related."""
        crypto_ids = set()
        for group, opcodes in self.CRYPTO_OPCODES.items():
            if group in ['xor', 'and', 'or', 'not', 'shift', 'rotate', 'bit']:
                for opcode in opcodes:
                    if opcode in self.word2idx:
                        crypto_ids.add(self.word2idx[opcode])
        return crypto_ids
    
    def save(self, path: str):
        """Save tokenizer to file."""
        import pickle
        with open(path, 'wb') as f:
            pickle.dump({
                'word2idx': self.word2idx,
                'idx2word': self.idx2word,
                'word_counts': self.word_counts,
                'max_vocab_size': self.max_vocab_size,
            }, f)
    
    @classmethod
    def load(cls, path: str) -> 'ProprietaryOpcodeTokenizer':
        """Load tokenizer from file."""
        import pickle
        with open(path, 'rb') as f:
            data = pickle.load(f)
        
        tokenizer = cls(max_vocab_size=data['max_vocab_size'])
        tokenizer.word2idx = data['word2idx']
        tokenizer.idx2word = data['idx2word']
        tokenizer.word_counts = data['word_counts']
        tokenizer.vocab_built = True
        return tokenizer

