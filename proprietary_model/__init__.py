"""
Proprietary Firmware Cryptographic Primitive Detection Model

A 3-layer transformer-based architecture for detecting and classifying
proprietary/custom cryptographic implementations in firmware binaries.

Architecture:
    Layer 1: Proprietary Signature Scanner - Detects custom crypto patterns
    Layer 2: Enhanced Transformer Encoder - Processes opcode sequences
    Layer 3: Multi-Feature Fusion Classifier - Combines all signals

Components:
    - Binary Generator: Creates synthetic proprietary crypto binaries
    - Feature Extractor: Extracts essential features from binaries
    - Model: 3-layer architecture for classification
"""

__version__ = "1.0.0"
__author__ = "BlackBoxAI"

