"""
Layer 2: Transformer Encoder for Opcode Sequences
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    EMBEDDING_DIM, NUM_LAYERS, NUM_HEADS, FEEDFORWARD_DIM,
    DROPOUT, MAX_SEQ_LENGTH, NUM_CLASSES
)


class TransformerEncoder(nn.Module):
    """
    Transformer encoder for processing opcode sequences.
    
    Architecture:
        Embedding → TransformerEncoder → GlobalMaxPool → FC → Sigmoid
    
    Example:
        >>> model = TransformerEncoder(vocab_size=5000, num_classes=18)
        >>> opcode_ids = torch.randint(0, 5000, (32, 512))  # (batch, seq_len)
        >>> output = model(opcode_ids)
        >>> # Returns: (32, 18) tensor with probabilities for each crypto algorithm
    """
    
    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = EMBEDDING_DIM,
        num_layers: int = NUM_LAYERS,
        num_heads: int = NUM_HEADS,
        feedforward_dim: int = FEEDFORWARD_DIM,
        dropout: float = DROPOUT,
        max_seq_length: int = MAX_SEQ_LENGTH,
        num_classes: int = NUM_CLASSES
    ):
        """
        Initialize transformer encoder.
        
        Args:
            vocab_size: Size of opcode vocabulary
            embedding_dim: Embedding dimension (default 256)
            num_layers: Number of transformer layers (default 4)
            num_heads: Number of attention heads (default 8)
            feedforward_dim: Feedforward dimension (default 512)
            dropout: Dropout rate (default 0.1)
            max_seq_length: Maximum sequence length (default 512)
            num_classes: Number of output classes (default 18)
        """
        super(TransformerEncoder, self).__init__()
        
        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.max_seq_length = max_seq_length
        self.num_classes = num_classes
        
        # Token embedding
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        
        # Positional encoding
        self.pos_encoding = nn.Parameter(
            torch.randn(1, max_seq_length, embedding_dim) * 0.02
        )
        
        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embedding_dim,
            nhead=num_heads,
            dim_feedforward=feedforward_dim,
            dropout=dropout,
            activation='relu',
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )
        
        # Global max pooling (alternative to CLS token)
        self.pool = nn.AdaptiveMaxPool1d(1)
        
        # Classification head
        self.fc1 = nn.Linear(embedding_dim, 256)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(256, num_classes)
        
    def forward(self, opcode_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass through transformer.
        
        Args:
            opcode_ids: Token IDs tensor of shape (batch_size, seq_length)
            attention_mask: Optional attention mask (batch_size, seq_length)
            
        Returns:
            Output probabilities of shape (batch_size, num_classes)
            
        Example:
            >>> opcode_sequence = ["eor r3, r1, r2", "ror r5, r4, #7", ...]
            >>> # After tokenization: [12, 34, 56, ...]
            >>> output = model(token_ids)
            >>> # Returns: tensor([[0.98, 0.94, 0.73, 0.09, ...]])  # Probabilities
        """
        batch_size, seq_len = opcode_ids.shape
        
        # Embedding
        x = self.embedding(opcode_ids)  # (batch, seq_len, embedding_dim)
        
        # Add positional encoding
        x = x + self.pos_encoding[:, :seq_len, :]
        
        # Create attention mask if not provided (mask padding tokens)
        if attention_mask is None:
            attention_mask = (opcode_ids != 0).float()  # 0 is PAD token
            # Convert to transformer format: True for valid tokens
            attention_mask = attention_mask.bool()
        
        # Transformer encoder expects mask where True = ignore
        # So we invert it
        src_key_padding_mask = ~attention_mask
        
        # Transformer encoding
        x = self.transformer(x, src_key_padding_mask=src_key_padding_mask)
        # x shape: (batch, seq_len, embedding_dim)
        
        # Global max pooling over sequence dimension
        # Transpose for pooling: (batch, embedding_dim, seq_len)
        x = x.transpose(1, 2)
        x = self.pool(x)  # (batch, embedding_dim, 1)
        x = x.squeeze(-1)  # (batch, embedding_dim)
        
        # Classification head
        x = self.fc1(x)
        x = F.relu(x)
        x = self.dropout(x)
        x = self.fc2(x)
        
        # Return logits (sigmoid applied in loss function for numerical stability)
        return x  # (batch, num_classes) - logits
    
    def get_embeddings(self, opcode_ids: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Get embeddings without classification head (for fusion classifier).
        
        Args:
            opcode_ids: Token IDs tensor of shape (batch_size, seq_length)
            attention_mask: Optional attention mask (batch_size, seq_length)
            
        Returns:
            Pooled embeddings of shape (batch_size, embedding_dim)
        """
        batch_size, seq_len = opcode_ids.shape
        
        # Embedding
        x = self.embedding(opcode_ids)  # (batch, seq_len, embedding_dim)
        
        # Add positional encoding
        x = x + self.pos_encoding[:, :seq_len, :]
        
        # Create attention mask if not provided
        if attention_mask is None:
            attention_mask = (opcode_ids != 0).float()
            attention_mask = attention_mask.bool()
        
        src_key_padding_mask = ~attention_mask
        
        # Transformer encoding
        x = self.transformer(x, src_key_padding_mask=src_key_padding_mask)
        
        # Global max pooling
        x = x.transpose(1, 2)
        x = self.pool(x)
        x = x.squeeze(-1)  # (batch, embedding_dim)
        
        return x


class OpcodeSequenceModel(nn.Module):
    """
    Wrapper model that combines tokenization and transformer.
    
    This is a convenience class that can be used during training.
    """
    
    def __init__(self, vocab_size: int, num_classes: int = NUM_CLASSES):
        """
        Initialize model.
        
        Args:
            vocab_size: Vocabulary size
            num_classes: Number of output classes
        """
        super(OpcodeSequenceModel, self).__init__()
        self.transformer = TransformerEncoder(
            vocab_size=vocab_size,
            num_classes=num_classes
        )
    
    def forward(self, opcode_ids: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            opcode_ids: Token IDs tensor
            
        Returns:
            Output probabilities
        """
        return self.transformer(opcode_ids)

