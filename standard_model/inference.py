"""
Inference pipeline for Standard Firmware Cryptographic Primitive Detection Model
"""
import argparse
import os
import sys
from typing import Dict, List, Tuple

import torch

if __package__:
    from .config import (
        DEVICE,
        CHECKPOINT_PATH,
        CRYPTO_LABELS,
        NUM_CLASSES,
        MAX_SEQ_LENGTH,
        ENTROPY_THRESHOLD,
        SIGNATURE_FEATURE_DIM,
        ENTROPY_VECTOR_DIM,
    )
    from .models.signature_scanner import SignatureScanner
    from .models.transformer_encoder import TransformerEncoder
    from .models.fusion_classifier import FusionClassifier
    from .utils.opcode_tokenizer import OpcodeTokenizer
    from .utils.entropy import get_entropy_distribution_vector, find_high_entropy_regions
    from .utils.metadata_parser import extract_metadata, metadata_to_vector
else:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import (  # type: ignore
        DEVICE,
        CHECKPOINT_PATH,
        CRYPTO_LABELS,
        NUM_CLASSES,
        MAX_SEQ_LENGTH,
        ENTROPY_THRESHOLD,
        SIGNATURE_FEATURE_DIM,
        ENTROPY_VECTOR_DIM,
    )
    from models.signature_scanner import SignatureScanner  # type: ignore
    from models.transformer_encoder import TransformerEncoder  # type: ignore
    from models.fusion_classifier import FusionClassifier  # type: ignore
    from utils.opcode_tokenizer import OpcodeTokenizer  # type: ignore
    from utils.entropy import get_entropy_distribution_vector, find_high_entropy_regions  # type: ignore
    from utils.metadata_parser import extract_metadata, metadata_to_vector  # type: ignore


class CryptoDetector:
    """
    Complete inference pipeline for cryptographic detection.
    
    Example:
        >>> detector = CryptoDetector(checkpoint_path="checkpoints/standard_model.pt")
        >>> results = detector.detect("firmware.bin")
        >>> detector.print_results(results)
    """
    
    def __init__(self, checkpoint_path: str = CHECKPOINT_PATH):
        """
        Initialize detector with trained model.
        
        Args:
            checkpoint_path: Path to model checkpoint
        """
        print(f"Loading model from {checkpoint_path}...")
        
        # Load checkpoint
        checkpoint = torch.load(checkpoint_path, map_location=DEVICE, weights_only=False)
        
        # Load tokenizer
        self.tokenizer = checkpoint.get('tokenizer')
        if self.tokenizer is None:
            raise ValueError("Tokenizer not found in checkpoint")
        
        vocab_size = checkpoint.get('vocab_size', self.tokenizer.get_vocab_size())
        
        # Initialize models
        self.signature_scanner = SignatureScanner()
        
        # Get actual num_classes and labels from checkpoint
        checkpoint_config = checkpoint.get('config', {})
        checkpoint_num_classes = checkpoint_config.get('num_classes', NUM_CLASSES)
        checkpoint_labels = checkpoint_config.get('crypto_labels', CRYPTO_LABELS)
        
        # Use checkpoint labels if available, otherwise use config
        if len(checkpoint_labels) == checkpoint_num_classes:
            self.crypto_labels = checkpoint_labels
            print(f"Using {checkpoint_num_classes} labels from checkpoint: {checkpoint_labels}")
        else:
            self.crypto_labels = CRYPTO_LABELS[:checkpoint_num_classes] if checkpoint_num_classes <= len(CRYPTO_LABELS) else CRYPTO_LABELS
            print(f"Warning: Checkpoint labels mismatch, using config labels")
        
        if checkpoint_num_classes != NUM_CLASSES:
            print(f"Warning: Checkpoint has {checkpoint_num_classes} classes, config has {NUM_CLASSES}")
        
        self.transformer_encoder = TransformerEncoder(
            vocab_size=vocab_size,
            num_classes=checkpoint_num_classes  # Use checkpoint's actual num_classes
        ).to(DEVICE)
        self.transformer_encoder.load_state_dict(
            checkpoint['model_state_dict']['transformer']
        )
        self.transformer_encoder.eval()
        
        # Get actual dimensions from checkpoint's fusion classifier state dict
        fusion_state = checkpoint['model_state_dict']['fusion']
        fc1_input_dim = fusion_state['fc1.weight'].shape[1]  # (hidden_dim, input_dim)
        
        # Calculate metadata_dim from the checkpoint
        # input_dim = signature_dim + transformer_dim + entropy_dim + metadata_dim
        # metadata_dim = input_dim - signature_dim - transformer_dim - entropy_dim
        self._checkpoint_metadata_dim = fc1_input_dim - SIGNATURE_FEATURE_DIM - checkpoint_num_classes - ENTROPY_VECTOR_DIM
        print(f"Checkpoint dimensions: transformer={checkpoint_num_classes}, metadata={self._checkpoint_metadata_dim}, input={fc1_input_dim}")
        
        self.fusion_classifier = FusionClassifier(
            transformer_dim=checkpoint_num_classes,  # Use checkpoint's actual num_classes
            metadata_dim=self._checkpoint_metadata_dim,  # Use checkpoint's actual metadata_dim
            num_classes=checkpoint_num_classes
        ).to(DEVICE)
        self.fusion_classifier.load_state_dict(fusion_state)
        self.fusion_classifier.eval()
        
        # Load threshold from checkpoint (default to 0.35 as used in training)
        self.threshold = checkpoint.get('threshold', 0.35)
        print(f"Using detection threshold: {self.threshold}")
        
        print("[OK] Model loaded successfully!")
    
    def disassemble_to_opcodes(self, binary_data: bytes) -> List[str]:
        """
        Disassemble binary to opcode sequence.
        
        In production, this would use a real disassembler (capstone, radare2, etc.).
        For now, we create a synthetic sequence.
        
        Args:
            binary_data: Binary firmware data
            
        Returns:
            List of opcode strings
            
        Example:
            >>> opcodes = detector.disassemble_to_opcodes(firmware_bytes)
            >>> # Returns: ["mov r1, r2", "add r3, r1, #5", ...]
        """
        # TODO: Integrate with real disassembler (capstone, radare2, etc.)
        # For now, create synthetic opcode sequence
        
        # Common opcodes
        opcodes = [
            "mov", "add", "sub", "mul", "div",
            "ldr", "str", "ldrb", "strb",
            "cmp", "test", "beq", "bne", "bgt", "blt",
            "push", "pop", "call", "ret",
            "xor", "and", "or", "not", "shl", "shr",
            "eor", "ror", "rol", "lsl", "lsr"
        ]
        
        # Generate sequence based on binary size
        sequence = []
        num_instructions = min(len(binary_data) // 4, 200)  # Approximate
        
        import numpy as np
        for i in range(num_instructions):
            opcode = opcodes[i % len(opcodes)]
            reg1 = f"r{np.random.randint(0, 16)}"
            reg2 = f"r{np.random.randint(0, 16)}"
            sequence.append(f"{opcode} {reg1}, {reg2}")
        
        return sequence
    
    def detect(self, filepath: str = None, binary_data: bytes = None) -> Dict:
        """
        Detect cryptographic primitives in firmware.
        
        Args:
            filepath: Path to firmware file (optional if binary_data provided)
            binary_data: Binary data (optional if filepath provided)
            
        Returns:
            Dictionary with detection results
            
        Example:
            >>> results = detector.detect(filepath="firmware.bin")
            >>> # Returns: {
            >>> #     "probabilities": {...},
            >>> #     "detections": {...},
            >>> #     "entropy_regions": [...],
            >>> #     "metadata": {...}
            >>> # }
        """
        if binary_data is None:
            if filepath is None:
                raise ValueError("Either filepath or binary_data must be provided")
            with open(filepath, 'rb') as f:
                binary_data = f.read()
            filepath = filepath
        else:
            filepath = filepath or "memory_buffer"
        
        print(f"\nAnalyzing: {filepath}")
        print(f"File size: {len(binary_data):,} bytes")
        
        # Layer 1: Signature scanning
        print("\n[Layer 1] Running signature scanner...")
        signature_features = self.signature_scanner.scan(binary_data)
        signature_features = signature_features.unsqueeze(0).to(DEVICE)
        
        # Disassemble to opcodes
        print("[Layer 2] Disassembling to opcodes...")
        opcode_sequence = self.disassemble_to_opcodes(binary_data)
        print(f"  Extracted {len(opcode_sequence)} instructions")
        
        # Tokenize
        opcode_ids = self.tokenizer.encode(opcode_sequence, max_length=MAX_SEQ_LENGTH)
        opcode_ids = torch.tensor([opcode_ids], dtype=torch.long).to(DEVICE)
        
        # Transformer encoding
        print("[Layer 2] Running transformer encoder...")
        with torch.no_grad():
            transformer_output = self.transformer_encoder(opcode_ids)  # Returns logits (NUM_CLASSES)
        
        # Entropy analysis
        print("[Feature Extraction] Computing entropy...")
        entropy_vector = get_entropy_distribution_vector(binary_data)
        entropy_vector = torch.tensor([entropy_vector], dtype=torch.float32).to(DEVICE)
        entropy_regions = find_high_entropy_regions(binary_data, threshold=ENTROPY_THRESHOLD)
        
        # Metadata extraction
        print("[Feature Extraction] Extracting metadata...")
        metadata = extract_metadata(data=binary_data)
        metadata_vec = metadata_to_vector(metadata)
        
        # Pad or truncate to match checkpoint's expected size
        if len(metadata_vec) < self._checkpoint_metadata_dim:
            metadata_vec = metadata_vec + [0.0] * (self._checkpoint_metadata_dim - len(metadata_vec))
        elif len(metadata_vec) > self._checkpoint_metadata_dim:
            metadata_vec = metadata_vec[:self._checkpoint_metadata_dim]
        
        metadata_vector = torch.tensor([metadata_vec], dtype=torch.float32).to(DEVICE)
        
        # Layer 3: Feature fusion
        print("[Layer 3] Running fusion classifier...")
        with torch.no_grad():
            output = self.fusion_classifier(
                signature_features,
                transformer_output,
                entropy_vector,
                metadata_vector
            )
        
        # Apply sigmoid to convert logits to probabilities
        probabilities = torch.sigmoid(output[0]).cpu().numpy()
        
        # Ensure we have the right number of probabilities
        num_probs = len(probabilities)
        num_labels = len(self.crypto_labels)
        if num_probs != num_labels:
            print(f"Warning: Mismatch - {num_probs} probabilities but {num_labels} labels")
            # Truncate or pad as needed
            if num_probs > num_labels:
                probabilities = probabilities[:num_labels]
            else:
                probabilities = list(probabilities) + [0.0] * (num_labels - num_probs)
        
        # Create results dictionary
        results = {
            'probabilities': {
                self.crypto_labels[i]: float(prob) 
                for i, prob in enumerate(probabilities)
            },
            'detections': {
                self.crypto_labels[i]: {
                    'present': prob > self.threshold,
                    'confidence': float(prob)
                }
                for i, prob in enumerate(probabilities)
            },
            'entropy_regions': entropy_regions,
            'metadata': metadata,
            'signature_features': {
                'AES_SBOX_FOUND': bool(signature_features[0, 0].item()),
                'SHA256_CONST_FOUND': bool(signature_features[0, 1].item()),
                'MD5_CONST_FOUND': bool(signature_features[0, 2].item()),
                'ECC_PARAM_FOUND': bool(signature_features[0, 3].item()),
                'RSA_ASN1_FOUND': bool(signature_features[0, 4].item()),
                'ENTROPY_HIGH': bool(signature_features[0, 5].item())
            }
        }
        
        return results
    
    def print_results(self, results: Dict):
        """
        Print detection results in formatted output.
        
        Args:
            results: Results dictionary from detect()
        """
        print("\n" + "=" * 80)
        print("Detected Cryptographic Primitives:")
        print("=" * 80)
        
        # Sort by confidence
        sorted_detections = sorted(
            results['detections'].items(),
            key=lambda x: x[1]['confidence'],
            reverse=True
        )
        
        for label, detection in sorted_detections:
            if detection['present']:
                status = "Present"
                confidence = detection['confidence'] * 100
                print(f"{label:20s}: {status:10s} ({confidence:5.1f}%)")
            else:
                confidence = detection['confidence'] * 100
                if confidence > 1.0:  # Only show if > 1%
                    print(f"{label:20s}: Not Found    ({confidence:5.1f}%)")
        
        # Entropy hotspots
        if results['entropy_regions']:
            print("\n" + "-" * 80)
            print("Entropy Hotspots (potential encrypted/compressed regions):")
            for start, end in results['entropy_regions']:
                print(f"  Region: 0x{start:08x}–0x{end:08x} ({end-start:,} bytes)")
        else:
            print("\n" + "-" * 80)
            print("No high-entropy regions detected.")
        
        # Metadata
        print("\n" + "-" * 80)
        print("File Metadata:")
        metadata = results['metadata']
        print(f"  Architecture: {metadata['arch_type']}")
        print(f"  File Size: {metadata['file_size']:,} bytes")
        print(f"  Sections: {metadata['num_sections']}")
        print(f"  Format: {'ELF' if metadata['is_ELF'] else 'BIN' if metadata['is_BIN'] else 'UNKNOWN'}")
        
        # Signature features
        print("\n" + "-" * 80)
        print("Signature Scanner Results:")
        sig = results['signature_features']
        for key, value in sig.items():
            status = "[OK] Found" if value else "[ ] Not Found"
            print(f"  {key:20s}: {status}")
        
        print("=" * 80)


def main():
    """Main inference function."""
    parser = argparse.ArgumentParser(
        description="Detect cryptographic primitives in firmware"
    )
    parser.add_argument(
        'filepath',
        type=str,
        help='Path to firmware file to analyze'
    )
    parser.add_argument(
        '--checkpoint',
        type=str,
        default=CHECKPOINT_PATH,
        help='Path to model checkpoint (default: checkpoints/standard_model.pt)'
    )
    
    args = parser.parse_args()
    
    # Check if file exists
    if not os.path.exists(args.filepath):
        print(f"Error: File not found: {args.filepath}")
        return
    
    # Check if checkpoint exists
    if not os.path.exists(args.checkpoint):
        print(f"Error: Checkpoint not found: {args.checkpoint}")
        print("Please train the model first using train.py")
        return
    
    # Initialize detector
    detector = CryptoDetector(checkpoint_path=args.checkpoint)
    
    # Run detection
    results = detector.detect(filepath=args.filepath)
    
    # Print results
    detector.print_results(results)


if __name__ == "__main__":
    main()
