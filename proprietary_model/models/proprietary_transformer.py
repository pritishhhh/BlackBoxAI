"""
Layer 2: Enhanced Transformer Encoder for Proprietary Crypto Detection
Deep transformer architecture for learning complex crypto patterns.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional
import math

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    EMBEDDING_DIM, NUM_LAYERS, NUM_HEADS, FEEDFORWARD_DIM,
    DROPOUT, MAX_SEQ_LENGTH, NUM_OPERATION_CLASSES
)


class MultiHeadAttentionWithRelativePosition(nn.Module):
    """
    Multi-head attention with relative positional encoding.
    Better for capturing local patterns in opcode sequences.
    """
    
    def __init__(
        self,
        d_model: int,
        num_heads: int,
        dropout: float = 0.1,
        max_len: int = 768
    ):
        super().__init__()
        assert d_model % num_heads == 0
        
        self.d_model = d_model
        self.num_heads = num_heads
        self.d_k = d_model // num_heads
        
        self.w_q = nn.Linear(d_model, d_model)
        self.w_k = nn.Linear(d_model, d_model)
        self.w_v = nn.Linear(d_model, d_model)
        self.w_o = nn.Linear(d_model, d_model)
        
        self.dropout = nn.Dropout(dropout)
        
        # Relative position embeddings
        self.max_len = max_len
        self.rel_pos_embedding = nn.Parameter(
            torch.randn(2 * max_len - 1, self.d_k) * 0.02
        )
    
    def forward(
        self,
        query: torch.Tensor,
        key: torch.Tensor,
        value: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        batch_size, seq_len = query.shape[:2]
        
        # Linear projections
        q = self.w_q(query).view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)
        k = self.w_k(key).view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)
        v = self.w_v(value).view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)
        
        # Attention scores (optimized for GPU)
        scores = torch.matmul(q, k.transpose(-2, -1)) * (1.0 / math.sqrt(self.d_k))
        
        # Add relative position bias (simplified for speed)
        positions = torch.arange(seq_len, device=query.device, dtype=torch.long)
        rel_pos = positions.unsqueeze(0) - positions.unsqueeze(1) + self.max_len - 1
        rel_pos = rel_pos.clamp(0, 2 * self.max_len - 2)
        rel_pos_bias = self.rel_pos_embedding[rel_pos]
        
        # Apply relative position to query (optimized einsum)
        rel_scores = torch.einsum('bhqd,qkd->bhqk', q, rel_pos_bias) * (1.0 / math.sqrt(self.d_k))
        scores = scores + rel_scores
        
        if mask is not None:
            scores = scores.masked_fill(mask.unsqueeze(1).unsqueeze(2), float('-inf'))
        
        attn = F.softmax(scores, dim=-1)
        attn = self.dropout(attn)
        
        output = torch.matmul(attn, v)
        output = output.transpose(1, 2).contiguous().view(batch_size, seq_len, self.d_model)
        
        return self.w_o(output)


class TransformerEncoderBlock(nn.Module):
    """
    Single transformer encoder block with pre-norm architecture.
    """
    
    def __init__(
        self,
        d_model: int,
        num_heads: int,
        d_ff: int,
        dropout: float = 0.1,
        max_len: int = 768
    ):
        super().__init__()
        
        self.attention = MultiHeadAttentionWithRelativePosition(
            d_model, num_heads, dropout, max_len
        )
        self.feed_forward = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout)
        )
        
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        # Pre-norm attention
        normed = self.norm1(x)
        attn_out = self.attention(normed, normed, normed, mask)
        x = x + self.dropout(attn_out)
        
        # Pre-norm feed-forward
        normed = self.norm2(x)
        ff_out = self.feed_forward(normed)
        x = x + ff_out
        
        return x


class ProprietaryTransformerEncoder(nn.Module):
    """
    Enhanced transformer encoder for proprietary crypto detection.
    
    Architecture:
        Token Embedding + Positional Encoding
        → N × TransformerEncoderBlock (with relative position attention)
        → Multi-head pooling
        → Classification heads
    
    Example:
        >>> model = ProprietaryTransformerEncoder(vocab_size=15000)
        >>> opcode_ids = torch.randint(0, 15000, (32, 768))
        >>> output = model(opcode_ids)
        >>> # Returns: (32, NUM_OPERATION_CLASSES) tensor with logits
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
        num_classes: int = NUM_OPERATION_CLASSES
    ):
        """
        Initialize the transformer encoder.
        
        Args:
            vocab_size: Size of opcode vocabulary
            embedding_dim: Embedding dimension (default 384)
            num_layers: Number of transformer layers (default 6)
            num_heads: Number of attention heads (default 12)
            feedforward_dim: Feedforward dimension (default 1024)
            dropout: Dropout rate (default 0.15)
            max_seq_length: Maximum sequence length (default 768)
            num_classes: Number of operation classes (default 10)
        """
        super().__init__()
        
        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.max_seq_length = max_seq_length
        self.num_classes = num_classes
        
        # Token embedding with learned positional encoding
        self.token_embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.pos_encoding = nn.Parameter(
            torch.randn(1, max_seq_length, embedding_dim) * 0.02
        )
        
        # Embedding dropout
        self.embed_dropout = nn.Dropout(dropout)
        
        # Transformer encoder blocks
        self.encoder_blocks = nn.ModuleList([
            TransformerEncoderBlock(
                d_model=embedding_dim,
                num_heads=num_heads,
                d_ff=feedforward_dim,
                dropout=dropout,
                max_len=max_seq_length
            )
            for _ in range(num_layers)
        ])
        
        # Final layer norm
        self.final_norm = nn.LayerNorm(embedding_dim)
        
        # Multi-head pooling for better representation
        self.pool_heads = nn.ModuleList([
            nn.Sequential(
                nn.Linear(embedding_dim, embedding_dim // 4),
                nn.Tanh(),
                nn.Linear(embedding_dim // 4, 1)
            )
            for _ in range(4)
        ])
        
        # Classification head
        pooled_dim = embedding_dim * 4  # 4 pool heads
        self.classifier = nn.Sequential(
            nn.Linear(pooled_dim, embedding_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embedding_dim, embedding_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embedding_dim // 2, num_classes)
        )
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Initialize model weights."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Embedding):
                nn.init.normal_(module.weight, mean=0, std=0.02)
                if module.padding_idx is not None:
                    nn.init.zeros_(module.weight[module.padding_idx])
    
    def forward(
        self,
        opcode_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Forward pass through transformer.
        
        Args:
            opcode_ids: Token IDs tensor of shape (batch_size, seq_length)
            attention_mask: Optional attention mask (batch_size, seq_length)
            
        Returns:
            Logits of shape (batch_size, num_classes)
        """
        batch_size, seq_len = opcode_ids.shape
        
        # Create padding mask if not provided
        if attention_mask is None:
            attention_mask = (opcode_ids == 0)  # True for padding tokens
        
        # Token + positional embedding
        x = self.token_embedding(opcode_ids)
        x = x + self.pos_encoding[:, :seq_len, :]
        x = self.embed_dropout(x)
        
        # Pass through encoder blocks
        for encoder_block in self.encoder_blocks:
            x = encoder_block(x, attention_mask)
        
        # Final normalization
        x = self.final_norm(x)
        
        # Multi-head pooling
        pooled_outputs = []
        for pool_head in self.pool_heads:
            # Compute attention weights
            attn_weights = pool_head(x)  # (batch, seq, 1)
            attn_weights = attn_weights.masked_fill(attention_mask.unsqueeze(-1), float('-inf'))
            attn_weights = F.softmax(attn_weights, dim=1)
            
            # Weighted sum
            pooled = torch.sum(x * attn_weights, dim=1)  # (batch, embedding_dim)
            pooled_outputs.append(pooled)
        
        # Concatenate pooled representations
        pooled = torch.cat(pooled_outputs, dim=-1)  # (batch, embedding_dim * 4)
        
        # Classification
        logits = self.classifier(pooled)
        
        return logits
    
    def get_embeddings(self, opcode_ids: torch.Tensor) -> torch.Tensor:
        """
        Get sequence embeddings without classification.
        
        Args:
            opcode_ids: Token IDs tensor
            
        Returns:
            Embeddings of shape (batch_size, embedding_dim * 4)
        """
        batch_size, seq_len = opcode_ids.shape
        attention_mask = (opcode_ids == 0)
        
        x = self.token_embedding(opcode_ids)
        x = x + self.pos_encoding[:, :seq_len, :]
        x = self.embed_dropout(x)
        
        for encoder_block in self.encoder_blocks:
            x = encoder_block(x, attention_mask)
        
        x = self.final_norm(x)
        
        pooled_outputs = []
        for pool_head in self.pool_heads:
            attn_weights = pool_head(x)
            attn_weights = attn_weights.masked_fill(attention_mask.unsqueeze(-1), float('-inf'))
            attn_weights = F.softmax(attn_weights, dim=1)
            pooled = torch.sum(x * attn_weights, dim=1)
            pooled_outputs.append(pooled)
        
        return torch.cat(pooled_outputs, dim=-1)

