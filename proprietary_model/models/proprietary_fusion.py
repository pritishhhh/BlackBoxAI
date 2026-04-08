"""
Layer 3: Proprietary Feature Fusion Classifier
Combines all detection layers for final classification.
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    SIGNATURE_FEATURE_DIM, FUSION_HIDDEN_DIM_1, FUSION_HIDDEN_DIM_2,
    FUSION_HIDDEN_DIM_3, METADATA_FEATURE_DIM, ENTROPY_VECTOR_DIM,
    NUM_OPERATION_CLASSES, EMBEDDING_DIM, CSV_FEATURE_DIM, DROPOUT
)


class GatedFusionLayer(nn.Module):
    """
    Gated fusion layer for combining different feature modalities.
    Uses learned gates to weight importance of each modality.
    """
    
    def __init__(self, input_dims: list, output_dim: int):
        super().__init__()
        
        self.num_modalities = len(input_dims)
        total_dim = sum(input_dims)
        
        # Projection layers for each modality
        self.projections = nn.ModuleList([
            nn.Linear(dim, output_dim)
            for dim in input_dims
        ])
        
        # Gate network
        self.gate = nn.Sequential(
            nn.Linear(total_dim, output_dim),
            nn.ReLU(),
            nn.Linear(output_dim, self.num_modalities),
            nn.Softmax(dim=-1)
        )
    
    def forward(self, *inputs):
        """
        Forward pass through gated fusion.
        
        Args:
            *inputs: Variable number of input tensors, one per modality
            
        Returns:
            Fused output tensor
        """
        # Project each modality
        projected = [proj(x) for proj, x in zip(self.projections, inputs)]
        
        # Concatenate all inputs for gate computation
        concat = torch.cat(inputs, dim=-1)
        
        # Compute gates
        gates = self.gate(concat)  # (batch, num_modalities)
        
        # Apply gated fusion
        output = sum(
            projected[i] * gates[:, i:i+1]
            for i in range(self.num_modalities)
        )
        
        return output


class ProprietaryFusionClassifier(nn.Module):
    """
    Enhanced feature fusion classifier for proprietary crypto detection.
    
    Architecture:
        1. Gated fusion of all input modalities
        2. Deep residual classification network
        3. Multi-task output heads
    
    Input modalities:
        - Signature features (Layer 1): 8 features
        - Transformer embeddings (Layer 2): embedding_dim * 4
        - Entropy vector: 16 features
        - Metadata vector: 80+ features (base + CSV + label features)
    
    Example:
        >>> classifier = ProprietaryFusionClassifier()
        >>> sig_feat = torch.randn(32, 8)
        >>> trans_out = torch.randn(32, 10)
        >>> entropy = torch.randn(32, 16)
        >>> metadata = torch.randn(32, 80)
        >>> output = classifier(sig_feat, trans_out, entropy, metadata)
    """
    
    def __init__(
        self,
        signature_dim: int = SIGNATURE_FEATURE_DIM,
        transformer_dim: int = EMBEDDING_DIM * 4,  # Transformer outputs pooled embeddings
        entropy_dim: int = ENTROPY_VECTOR_DIM,
        metadata_dim: int = METADATA_FEATURE_DIM,
        hidden_dim_1: int = FUSION_HIDDEN_DIM_1,
        hidden_dim_2: int = FUSION_HIDDEN_DIM_2,
        hidden_dim_3: int = FUSION_HIDDEN_DIM_3,
        num_classes: int = NUM_OPERATION_CLASSES,
        dropout: float = DROPOUT
    ):
        """
        Initialize fusion classifier.
        
        Args:
            signature_dim: Dimension of signature features (default 8)
            transformer_dim: Dimension of transformer output (default 10)
            entropy_dim: Dimension of entropy vector (default 16)
            metadata_dim: Dimension of metadata features (default 80)
            hidden_dim_1: First hidden layer dimension (default 1536)
            hidden_dim_2: Second hidden layer dimension (default 768)
            hidden_dim_3: Third hidden layer dimension (default 384)
            num_classes: Number of output classes (default 10)
            dropout: Dropout rate (default 0.15)
        """
        super().__init__()
        
        self.num_classes = num_classes
        
        # Input dimension is sum of all feature dimensions
        input_dim = signature_dim + transformer_dim + entropy_dim + metadata_dim
        
        # Gated fusion layer
        self.gated_fusion = GatedFusionLayer(
            input_dims=[signature_dim, transformer_dim, entropy_dim, metadata_dim],
            output_dim=hidden_dim_1 // 2
        )
        
        # Also keep direct concatenation path
        self.direct_proj = nn.Linear(input_dim, hidden_dim_1 // 2)
        
        # Combine gated and direct paths
        combined_dim = hidden_dim_1
        
        # Deep classification network with residual connections
        self.layer1 = nn.Sequential(
            nn.Linear(combined_dim, hidden_dim_1),
            nn.BatchNorm1d(hidden_dim_1),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        
        self.residual1 = nn.Linear(combined_dim, hidden_dim_1)
        
        self.layer2 = nn.Sequential(
            nn.Linear(hidden_dim_1, hidden_dim_2),
            nn.BatchNorm1d(hidden_dim_2),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        
        self.residual2 = nn.Linear(hidden_dim_1, hidden_dim_2)
        
        self.layer3 = nn.Sequential(
            nn.Linear(hidden_dim_2, hidden_dim_3),
            nn.BatchNorm1d(hidden_dim_3),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        
        self.residual3 = nn.Linear(hidden_dim_2, hidden_dim_3)
        
        self.layer4 = nn.Sequential(
            nn.Linear(hidden_dim_3, hidden_dim_3 // 2),
            nn.BatchNorm1d(hidden_dim_3 // 2),
            nn.GELU(),
            nn.Dropout(dropout)
        )
        
        # Output head
        self.output_head = nn.Linear(hidden_dim_3 // 2, num_classes)
        
        # Auxiliary head for crypto type classification (multi-task)
        self.crypto_type_head = nn.Linear(hidden_dim_3 // 2, 7)  # 7 crypto types
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Initialize model weights."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, mode='fan_out', nonlinearity='relu')
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)
    
    def forward(
        self,
        signature_features: torch.Tensor,
        transformer_output: torch.Tensor,
        entropy_vector: torch.Tensor,
        metadata_vector: torch.Tensor,
        return_aux: bool = False
    ) -> torch.Tensor:
        """
        Forward pass through fusion classifier.
        
        Args:
            signature_features: Signature scanner output (batch, signature_dim)
            transformer_output: Transformer encoder output (batch, transformer_dim)
            entropy_vector: Entropy distribution vector (batch, entropy_dim)
            metadata_vector: Metadata features (batch, metadata_dim)
            return_aux: Whether to return auxiliary outputs
            
        Returns:
            Operation classification logits (batch, num_classes)
            If return_aux: also returns crypto_type logits
        """
        # Gated fusion path
        gated = self.gated_fusion(
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        )
        
        # Direct concatenation path
        concat = torch.cat([
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        ], dim=1)
        direct = self.direct_proj(concat)
        
        # Combine paths
        x = torch.cat([gated, direct], dim=1)
        
        # Layer 1 with residual
        identity = self.residual1(x)
        x = self.layer1(x)
        x = x + identity
        
        # Layer 2 with residual
        identity = self.residual2(x)
        x = self.layer2(x)
        x = x + identity
        
        # Layer 3 with residual
        identity = self.residual3(x)
        x = self.layer3(x)
        x = x + identity
        
        # Layer 4
        x = self.layer4(x)
        
        # Output heads
        operation_logits = self.output_head(x)
        
        if return_aux:
            crypto_type_logits = self.crypto_type_head(x)
            return operation_logits, crypto_type_logits
        
        return operation_logits


class ProprietaryCompleteModel(nn.Module):
    """
    Complete 3-layer model that combines all components.
    
    This is the end-to-end model used during inference.
    """
    
    def __init__(
        self,
        signature_scanner,
        transformer_encoder,
        fusion_classifier
    ):
        """
        Initialize complete model.
        
        Args:
            signature_scanner: ProprietarySignatureScanner instance
            transformer_encoder: ProprietaryTransformerEncoder model
            fusion_classifier: ProprietaryFusionClassifier model
        """
        super().__init__()
        self.signature_scanner = signature_scanner
        self.transformer_encoder = transformer_encoder
        self.fusion_classifier = fusion_classifier
    
    def forward(
        self,
        binary_data: bytes,
        opcode_ids: torch.Tensor,
        entropy_vector: torch.Tensor,
        metadata_vector: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass through complete pipeline.
        
        Args:
            binary_data: Raw binary firmware data
            opcode_ids: Tokenized opcode sequence
            entropy_vector: Entropy distribution vector
            metadata_vector: Metadata features
            
        Returns:
            Final classification logits
        """
        # Layer 1: Signature scanning
        signature_features = self.signature_scanner.scan(binary_data)
        signature_features = signature_features.unsqueeze(0)
        
        # Layer 2: Transformer encoding
        transformer_output = self.transformer_encoder(opcode_ids)
        
        # Layer 3: Feature fusion
        output = self.fusion_classifier(
            signature_features,
            transformer_output,
            entropy_vector.unsqueeze(0) if entropy_vector.dim() == 1 else entropy_vector,
            metadata_vector.unsqueeze(0) if metadata_vector.dim() == 1 else metadata_vector
        )
        
        return output
    
    def forward_batch(
        self,
        opcode_ids: torch.Tensor,
        signature_features: torch.Tensor,
        entropy_vector: torch.Tensor,
        metadata_vector: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass for batched training (signature features pre-computed).
        
        Args:
            opcode_ids: Tokenized opcode sequences (batch, seq_len)
            signature_features: Pre-computed signature features (batch, sig_dim)
            entropy_vector: Entropy vectors (batch, entropy_dim)
            metadata_vector: Metadata features (batch, metadata_dim)
            
        Returns:
            Classification logits (batch, num_classes)
        """
        # Layer 2: Transformer encoding
        transformer_output = self.transformer_encoder(opcode_ids)
        
        # Layer 3: Feature fusion
        output = self.fusion_classifier(
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        )
        
        return output

