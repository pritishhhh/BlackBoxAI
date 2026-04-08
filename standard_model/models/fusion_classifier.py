"""
Layer 3: Feature Fusion Classifier
Combines signature features, transformer outputs, entropy, and metadata
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
    METADATA_FEATURE_DIM, ENTROPY_VECTOR_DIM, NUM_CLASSES, EMBEDDING_DIM
)


class FusionClassifier(nn.Module):
    """
    Feature fusion classifier that combines all detection layers.
    
    Architecture:
        concat(signature_features, transformer_output, entropy_vec, metadata_vec)
        → FC(512) → ReLU → FC(256) → ReLU → FC(num_classes) → Sigmoid
    
    Example:
        >>> classifier = FusionClassifier()
        >>> signature_feat = torch.randn(32, 6)  # Layer 1 output
        >>> transformer_out = torch.randn(32, 18)  # Layer 2 output
        >>> entropy_vec = torch.randn(32, 10)  # Entropy features
        >>> metadata_vec = torch.randn(32, 5)  # Metadata features
        >>> output = classifier(signature_feat, transformer_out, entropy_vec, metadata_vec)
        >>> # Returns: (32, 18) tensor with final probabilities
    """
    
    def __init__(
        self,
        signature_dim: int = SIGNATURE_FEATURE_DIM,
        transformer_dim: int = NUM_CLASSES,  # Transformer outputs logits (NUM_CLASSES)
        entropy_dim: int = ENTROPY_VECTOR_DIM,
        metadata_dim: int = METADATA_FEATURE_DIM,
        hidden_dim_1: int = FUSION_HIDDEN_DIM_1,
        hidden_dim_2: int = FUSION_HIDDEN_DIM_2,
        num_classes: int = NUM_CLASSES,
        dropout: float = 0.1
    ):
        """
        Initialize fusion classifier.
        
        Args:
            signature_dim: Dimension of signature features (default 6)
            transformer_dim: Dimension of transformer output (default 18)
            entropy_dim: Dimension of entropy vector (default 10)
            metadata_dim: Dimension of metadata features (default 5)
            hidden_dim_1: First hidden layer dimension (default 512)
            hidden_dim_2: Second hidden layer dimension (default 256)
            num_classes: Number of output classes (default 18)
            dropout: Dropout rate (default 0.1)
        """
        super(FusionClassifier, self).__init__()
        
        # Input dimension is sum of all feature dimensions
        input_dim = signature_dim + transformer_dim + entropy_dim + metadata_dim
        
        # Enhanced fusion layers with more capacity
        self.fc1 = nn.Linear(input_dim, hidden_dim_1)
        self.bn1 = nn.BatchNorm1d(hidden_dim_1)
        self.dropout1 = nn.Dropout(dropout)
        
        self.fc2 = nn.Linear(hidden_dim_1, hidden_dim_2)
        self.bn2 = nn.BatchNorm1d(hidden_dim_2)
        self.dropout2 = nn.Dropout(dropout)
        
        self.fc3 = nn.Linear(hidden_dim_2, hidden_dim_2 // 2)
        self.bn3 = nn.BatchNorm1d(hidden_dim_2 // 2)
        self.dropout3 = nn.Dropout(dropout)
        
        self.fc4 = nn.Linear(hidden_dim_2 // 2, num_classes)
        
    def forward(
        self,
        signature_features: torch.Tensor,
        transformer_output: torch.Tensor,
        entropy_vector: torch.Tensor,
        metadata_vector: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass through fusion classifier.
        
        Args:
            signature_features: Signature scanner output (batch, signature_dim)
            transformer_output: Transformer encoder output (batch, transformer_dim)
            entropy_vector: Entropy distribution vector (batch, entropy_dim)
            metadata_vector: Metadata features (batch, metadata_dim)
            
        Returns:
            Final classification probabilities (batch, num_classes)
            
        Example:
            >>> # All inputs should have same batch size
            >>> sig_feat = torch.tensor([[1., 1., 0., 0., 0., 1.]])  # Layer 1
            >>> trans_out = torch.tensor([[0.98, 0.94, 0.73, 0.09, ...]])  # Layer 2
            >>> entropy = torch.randn(1, 10)  # Entropy features
            >>> metadata = torch.tensor([[1., 0., 0., 1024000., 12.]])  # Metadata
            >>> output = classifier(sig_feat, trans_out, entropy, metadata)
            >>> # Returns: Final probabilities for each crypto algorithm
        """
        # Concatenate all features
        fused = torch.cat([
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        ], dim=1)  # (batch, input_dim)
        
        # Layer 1
        x = self.fc1(fused)
        x = self.bn1(x)
        x = F.relu(x)
        x = self.dropout1(x)
        
        # Layer 2
        x = self.fc2(x)
        x = self.bn2(x)
        x = F.relu(x)
        x = self.dropout2(x)
        
        # Layer 3
        x = self.fc3(x)
        x = self.bn3(x)
        x = F.relu(x)
        x = self.dropout3(x)
        
        # Output layer
        x = self.fc4(x)
        
        # Return logits (sigmoid applied in loss function for numerical stability)
        return x  # (batch, num_classes) - logits


class CompleteModel(nn.Module):
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
            signature_scanner: SignatureScanner instance
            transformer_encoder: TransformerEncoder model
            fusion_classifier: FusionClassifier model
        """
        super(CompleteModel, self).__init__()
        self.signature_scanner = signature_scanner
        self.transformer_encoder = transformer_encoder
        self.fusion_classifier = fusion_classifier
    
    def forward(
        self,
        data: bytes,
        opcode_ids: torch.Tensor,
        entropy_vector: torch.Tensor,
        metadata_vector: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass through complete pipeline.
        
        Args:
            data: Binary firmware data
            opcode_ids: Tokenized opcode sequence
            entropy_vector: Entropy distribution vector
            metadata_vector: Metadata features
            
        Returns:
            Final classification probabilities
        """
        # Layer 1: Signature scanning
        signature_features = self.signature_scanner.scan(data)
        signature_features = signature_features.unsqueeze(0)  # Add batch dimension
        
        # Layer 2: Transformer encoding
        transformer_output = self.transformer_encoder(opcode_ids)
        
        # Layer 3: Feature fusion
        output = self.fusion_classifier(
            signature_features,
            transformer_output,
            entropy_vector.unsqueeze(0),
            metadata_vector.unsqueeze(0)
        )
        
        return output

