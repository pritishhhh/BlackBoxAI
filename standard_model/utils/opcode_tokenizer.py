"""
Opcode tokenizer for converting assembly instructions to token IDs
"""
from typing import List, Dict, Optional
import re
from collections import Counter
import torch


class OpcodeTokenizer:
    """
    Tokenizer for assembly opcode sequences.
    
    Converts assembly instructions to token IDs for transformer input.
    
    Example:
        >>> tokenizer = OpcodeTokenizer()
        >>> tokenizer.build_vocab(opcode_sequences)
        >>> token_ids = tokenizer.encode(["mov r1, r2", "add r3, r1, #5"])
        >>> # Returns: [12, 34, ...]
    """
    
    def __init__(self, vocab_size: int = 10000):
        """
        Initialize tokenizer.
        
        Args:
            vocab_size: Maximum vocabulary size
        """
        self.vocab_size = vocab_size
        self.word_to_id: Dict[str, int] = {}
        self.id_to_word: Dict[int, str] = {}
        self.vocab_built = False
        
        # Special tokens
        self.PAD_TOKEN = "<PAD>"
        self.UNK_TOKEN = "<UNK>"
        self.SOS_TOKEN = "<SOS>"
        self.EOS_TOKEN = "<EOS>"
        
        # Initialize with special tokens
        self._init_special_tokens()
    
    def _init_special_tokens(self):
        """Initialize special token mappings."""
        special_tokens = [self.PAD_TOKEN, self.UNK_TOKEN, self.SOS_TOKEN, self.EOS_TOKEN]
        for i, token in enumerate(special_tokens):
            self.word_to_id[token] = i
            self.id_to_word[i] = token
    
    def _tokenize_instruction(self, instruction: str) -> List[str]:
        """
        Tokenize a single assembly instruction.
        
        Args:
            instruction: Assembly instruction string
            
        Returns:
            List of tokens (opcode, registers, operands, etc.)
            
        Example:
            >>> tokens = tokenizer._tokenize_instruction("mov r1, r2, lsl #2")
            >>> # Returns: ["mov", "r1", "r2", "lsl", "#2"]
        """
        # Normalize whitespace
        instruction = instruction.strip().lower()
        
        # Split by common delimiters
        tokens = re.split(r'[,\s]+', instruction)
        
        # Filter empty tokens
        tokens = [t for t in tokens if t]
        
        return tokens
    
    def build_vocab(self, opcode_sequences: List[List[str]], min_freq: int = 2):
        """
        Build vocabulary from opcode sequences.
        
        Args:
            opcode_sequences: List of instruction sequences
            min_freq: Minimum frequency for a token to be included
            
        Example:
            >>> sequences = [
            >>>     ["mov r1, r2", "add r3, r1"],
            >>>     ["ldr r0, [r1]", "str r2, [r3]"]
            >>> ]
            >>> tokenizer.build_vocab(sequences)
        """
        # Count token frequencies
        token_counter = Counter()
        
        for sequence in opcode_sequences:
            for instruction in sequence:
                tokens = self._tokenize_instruction(instruction)
                token_counter.update(tokens)
        
        # Build vocabulary (reserve space for special tokens)
        next_id = len(self.word_to_id)
        
        # Add tokens by frequency
        for token, freq in token_counter.most_common(self.vocab_size - next_id):
            if freq >= min_freq:
                self.word_to_id[token] = next_id
                self.id_to_word[next_id] = token
                next_id += 1
        
        self.vocab_built = True
        print(f"Built vocabulary with {len(self.word_to_id)} tokens")
    
    def encode(self, opcode_sequence: List[str], max_length: Optional[int] = None) -> List[int]:
        """
        Encode opcode sequence to token IDs.
        
        Args:
            opcode_sequence: List of assembly instructions
            max_length: Maximum sequence length (truncate/pad to this)
            
        Returns:
            List of token IDs
            
        Example:
            >>> opcode_sequence = ["eor r3, r1, r2", "ror r5, r4, #7"]
            >>> token_ids = tokenizer.encode(opcode_sequence, max_length=512)
        """
        if not self.vocab_built:
            raise ValueError("Vocabulary not built. Call build_vocab() first.")
        
        token_ids = []
        
        # Add SOS token
        token_ids.append(self.word_to_id[self.SOS_TOKEN])
        
        # Encode each instruction
        for instruction in opcode_sequence:
            tokens = self._tokenize_instruction(instruction)
            for token in tokens:
                token_id = self.word_to_id.get(token, self.word_to_id[self.UNK_TOKEN])
                token_ids.append(token_id)
        
        # Add EOS token
        token_ids.append(self.word_to_id[self.EOS_TOKEN])
        
        # Truncate or pad
        if max_length:
            if len(token_ids) > max_length:
                token_ids = token_ids[:max_length]
                token_ids[-1] = self.word_to_id[self.EOS_TOKEN]  # Ensure EOS at end
            else:
                # Pad with PAD tokens
                pad_id = self.word_to_id[self.PAD_TOKEN]
                token_ids.extend([pad_id] * (max_length - len(token_ids)))
        
        return token_ids
    
    def decode(self, token_ids: List[int]) -> List[str]:
        """
        Decode token IDs back to tokens (for debugging).
        
        Args:
            token_ids: List of token IDs
            
        Returns:
            List of token strings
        """
        tokens = []
        for token_id in token_ids:
            if token_id in self.id_to_word:
                token = self.id_to_word[token_id]
                if token not in [self.PAD_TOKEN, self.SOS_TOKEN, self.EOS_TOKEN]:
                    tokens.append(token)
        return tokens
    
    def get_vocab_size(self) -> int:
        """Get current vocabulary size."""
        return len(self.word_to_id)
    
    def save(self, filepath: str):
        """Save tokenizer to file."""
        import pickle
        with open(filepath, 'wb') as f:
            pickle.dump({
                'word_to_id': self.word_to_id,
                'id_to_word': self.id_to_word,
                'vocab_size': self.vocab_size,
                'vocab_built': self.vocab_built
            }, f)
    
    def load(self, filepath: str):
        """Load tokenizer from file."""
        import pickle
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.word_to_id = data['word_to_id']
            self.id_to_word = data['id_to_word']
            self.vocab_size = data['vocab_size']
            self.vocab_built = data['vocab_built']

