"""
Inference script for Proprietary Firmware Cryptographic Primitive Detection Model
"""
import os
import sys
from typing import Dict, List

import torch
import torch.nn.functional as F
import numpy as np

if __package__:
    from .config import (
        DEVICE,
        CHECKPOINT_PATH,
        NUM_OPERATION_CLASSES,
        OPERATION_LABELS,
        MAX_SEQ_LENGTH,
        ENTROPY_VECTOR_DIM,
        METADATA_FEATURE_DIM,
        PROPRIETARY_ALGORITHMS,
    )
    from .models.proprietary_signature_scanner import ProprietarySignatureScanner
    from .models.proprietary_transformer import ProprietaryTransformerEncoder
    from .models.proprietary_fusion import ProprietaryFusionClassifier
    from .utils.proprietary_tokenizer import ProprietaryOpcodeTokenizer
    from .utils.entropy_utils import get_entropy_features
    from .utils.feature_extractor import FeatureExtractor
else:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import (  # type: ignore
        DEVICE,
        CHECKPOINT_PATH,
        NUM_OPERATION_CLASSES,
        OPERATION_LABELS,
        MAX_SEQ_LENGTH,
        ENTROPY_VECTOR_DIM,
        METADATA_FEATURE_DIM,
        PROPRIETARY_ALGORITHMS,
    )
    from models.proprietary_signature_scanner import ProprietarySignatureScanner  # type: ignore
    from models.proprietary_transformer import ProprietaryTransformerEncoder  # type: ignore
    from models.proprietary_fusion import ProprietaryFusionClassifier  # type: ignore
    from utils.proprietary_tokenizer import ProprietaryOpcodeTokenizer  # type: ignore
    from utils.entropy_utils import get_entropy_features  # type: ignore
    from utils.feature_extractor import FeatureExtractor  # type: ignore


class ProprietaryInference:
    """
    Inference engine for proprietary cryptographic detection.
    
    Provides methods for:
    - Single binary analysis
    - Batch analysis
    - Detailed reports with confidence scores
    
    Example:
        >>> engine = ProprietaryInference()
        >>> result = engine.analyze_binary(firmware_bytes)
        >>> print(result['operation'])  # 'Encryption'
        >>> print(result['confidence'])  # 0.95
    """
    
    def __init__(self, checkpoint_path: str = CHECKPOINT_PATH, device: torch.device = DEVICE):
        """
        Initialize inference engine.
        
        Args:
            checkpoint_path: Path to model checkpoint
            device: Device to run inference on
        """
        self.device = device
        self.checkpoint_path = checkpoint_path
        
        # Initialize components
        self.signature_scanner = ProprietarySignatureScanner()
        self.feature_extractor = FeatureExtractor()
        
        # Load model
        self._load_model()
    
    def _load_model(self):
        """Load model from checkpoint."""
        import sys
        sys.stdout.flush()
        
        if not os.path.exists(self.checkpoint_path):
            raise FileNotFoundError(f"Checkpoint not found: {self.checkpoint_path}")
        
        print(f"Loading model from {self.checkpoint_path}...", flush=True)
        print("  - Reading checkpoint file (this may take 10-30 seconds)...", flush=True)
        checkpoint = torch.load(self.checkpoint_path, map_location=self.device, weights_only=False)
        print("  - Checkpoint loaded, parsing config...", flush=True)
        
        # Get config
        config = checkpoint.get('config', {})
        vocab_size = checkpoint.get('vocab_size', 15000)
        num_classes = config.get('num_classes', NUM_OPERATION_CLASSES)
        print(f"  - Config: vocab_size={vocab_size}, num_classes={num_classes}", flush=True)
        
        # Initialize models
        print("  - Initializing transformer...", flush=True)
        self.transformer = ProprietaryTransformerEncoder(
            vocab_size=vocab_size,
            num_classes=num_classes
        ).to(self.device)
        print("  - Initializing fusion classifier...", flush=True)
        self.fusion = ProprietaryFusionClassifier(
            num_classes=num_classes
        ).to(self.device)
        
        # Load weights
        print("  - Loading model weights...", flush=True)
        state_dict = checkpoint['model_state_dict']
        self.transformer.load_state_dict(state_dict['transformer'])
        self.fusion.load_state_dict(state_dict['fusion'])
        print("  - Weights loaded", flush=True)
        
        # Load tokenizer
        print("  - Loading tokenizer...", flush=True)
        self.tokenizer = checkpoint.get('tokenizer')
        if self.tokenizer is None:
            self.tokenizer = ProprietaryOpcodeTokenizer()
        
        # Set to evaluation mode
        self.transformer.eval()
        self.fusion.eval()
        
        # Get labels - use new labels from config (override old checkpoint labels)
        # This ensures we use the new algorithm names (CustomXOR, RotaryHash, KeyScheduler)
        # instead of old operation types (Encryption, Hashing, KeyGeneration)
        self.operation_labels = OPERATION_LABELS  # Always use current config labels
        
        print(f"Model loaded successfully!", flush=True)
        print(f"  Vocabulary size: {vocab_size}", flush=True)
        print(f"  Number of classes: {num_classes}", flush=True)
    
    def _extract_opcodes(self, binary_data: bytes) -> List[str]:
        """
        Extract opcode-like sequences from binary data.
        
        This is a simplified extraction - in production, use a proper disassembler.
        """
        # Map common x86/ARM opcodes
        opcode_map = {
            0x31: 'xor', 0x32: 'xor', 0x33: 'xor',
            0x01: 'add', 0x03: 'add', 0x05: 'add',
            0x29: 'sub', 0x2B: 'sub', 0x2D: 'sub',
            0xC1: 'shr', 0xD1: 'ror', 0xD3: 'rol',
            0x21: 'and', 0x23: 'and', 0x25: 'and',
            0x09: 'or', 0x0B: 'or', 0x0D: 'or',
            0x8B: 'mov', 0x89: 'mov', 0x8A: 'mov',
            0xF7: 'mul', 0xF6: 'div',
            0xE8: 'call', 0xE9: 'jmp', 0xC3: 'ret',
        }
        
        opcodes = []
        for i, byte in enumerate(binary_data):
            if byte in opcode_map:
                opcode = opcode_map[byte]
                # Create synthetic instruction
                reg1 = f"r{(i + binary_data[(i+1) % len(binary_data)]) % 16}"
                reg2 = f"r{(i + binary_data[(i+2) % len(binary_data)]) % 16}"
                opcodes.append(f"{opcode} {reg1}, {reg2}")
        
        # Ensure minimum length
        if len(opcodes) < 10:
            opcodes = ['mov r0, r1'] * 10 + opcodes
        
        return opcodes[:MAX_SEQ_LENGTH // 2]
    
    def _prepare_features(self, binary_data: bytes) -> Dict[str, torch.Tensor]:
        """Prepare all features for model input."""
        # Signature features
        signature_features = self.signature_scanner.scan(binary_data)
        
        # Extract opcodes and tokenize
        opcodes = self._extract_opcodes(binary_data)
        opcode_ids = self.tokenizer.encode(opcodes, max_length=MAX_SEQ_LENGTH)
        opcode_ids = torch.tensor(opcode_ids, dtype=torch.long).unsqueeze(0)
        
        # Entropy features
        entropy_features = get_entropy_features(binary_data, num_features=ENTROPY_VECTOR_DIM)
        entropy_vector = torch.tensor(entropy_features, dtype=torch.float32).unsqueeze(0)
        
        # Extract binary features
        extracted_features = self.feature_extractor.extract_all_features(binary_data)
        
        # Store operation counts for algorithm prediction
        self._temp_features = {
            'xor_ops': extracted_features.get('xor_ops', 0),
            'shift_ops': extracted_features.get('shift_ops', 0),
            'add_ops': extracted_features.get('add_ops', 0),
            'mul_ops': extracted_features.get('mul_ops', 0),
        }
        
        # Create metadata vector (simplified - use zeros for label-specific features)
        csv_features = np.zeros(25, dtype=np.float32)
        csv_features[0] = extracted_features.get('xor_ops', 0) / 100.0
        csv_features[1] = extracted_features.get('shift_ops', 0) / 100.0
        csv_features[2] = extracted_features.get('add_ops', 0) / 100.0
        csv_features[3] = extracted_features.get('mul_ops', 0) / 100.0
        csv_features[8] = extracted_features.get('entropy', 4.0) / 8.0
        
        # Pad to expected metadata size (METADATA_FEATURE_DIM = 25)
        if len(csv_features) < METADATA_FEATURE_DIM:
            padding = np.zeros(METADATA_FEATURE_DIM - len(csv_features), dtype=np.float32)
            metadata = np.concatenate([csv_features, padding])
        else:
            metadata = csv_features[:METADATA_FEATURE_DIM]
        metadata_vector = torch.tensor(metadata, dtype=torch.float32).unsqueeze(0)
        
        return {
            'opcode_ids': opcode_ids.to(self.device),
            'signature_features': signature_features.unsqueeze(0).to(self.device),
            'entropy_vector': entropy_vector.to(self.device),
            'metadata_vector': metadata_vector.to(self.device),
        }
    
    @torch.no_grad()
    def analyze_binary(self, binary_data: bytes, threshold: float = 0.5) -> Dict:
        """
        Analyze a single binary for cryptographic operations.
        
        Args:
            binary_data: Raw binary data
            threshold: Confidence threshold for predictions
            
        Returns:
            Dictionary with analysis results
        """
        if len(binary_data) < 16:
            return {
                'error': 'Binary data too small (minimum 16 bytes)',
                'operation': None,
                'confidence': 0.0,
            }
        
        # Prepare features
        features = self._prepare_features(binary_data)
        
        # Forward pass
        # Use get_embeddings to get transformer features (not logits)
        transformer_output = self.transformer.get_embeddings(features['opcode_ids'])
        logits = self.fusion(
            features['signature_features'],
            transformer_output,
            features['entropy_vector'],
            features['metadata_vector']
        )
        
        # Get probabilities
        probs = F.softmax(logits, dim=-1).cpu().numpy()[0]
        
        # Get top prediction
        top_idx = np.argmax(probs)
        top_prob = probs[top_idx]
        top_operation = self.operation_labels[top_idx]
        
        # Get signature features for interpretation
        sig_features = features['signature_features'].cpu().numpy()[0]
        sig_names = self.signature_scanner.get_feature_names()
        
        # Map signature features to dataset format (binary 0/1)
        # Dataset columns: has_sbox, has_permutation, has_rounds, key_schedule, bitwise_heavy, arithmetic_heavy, proprietary
        binary_features = {
            'has_sbox': int(sig_features[0] > 0.5),           # HAS_SBOX
            'has_permutation': int(sig_features[1] > 0.5),     # HAS_PERMUTATION
            'has_rounds': int(sig_features[2] > 0.5),         # HAS_ROUNDS
            'key_schedule': int(sig_features[3] > 0.5),       # HAS_KEY_SCHEDULE
            'bitwise_heavy': int(sig_features[4] > 0.5),     # BITWISE_HEAVY
            'arithmetic_heavy': int(sig_features[5] > 0.5),  # ARITHMETIC_HEAVY
            'proprietary': 1,  # Always 1 for proprietary model
        }
        
        # Predict algorithm name from features (not operation label)
        temp_features = getattr(self, '_temp_features', {})
        algorithm_name = self._predict_algorithm_name(
            binary_features,
            temp_features.get('xor_ops', 0),
            temp_features.get('shift_ops', 0),
            temp_features.get('add_ops', 0),
            temp_features.get('mul_ops', 0),
            top_operation
        )
        
        # Build result in dataset format (algorithm name + binary features only)
        result = {
            # Algorithm name (not operation label)
            'algorithm_name': algorithm_name,
            # Binary features matching dataset format
            **binary_features,
        }
        
        return result
    
    @torch.no_grad()
    def analyze_batch(self, binaries: List[bytes]) -> List[Dict]:
        """Analyze multiple binaries in batch."""
        return [self.analyze_binary(b) for b in binaries]
    
    def _get_recommendations(
        self, 
        operation: str, 
        confidence: float, 
        sig_features: np.ndarray
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if confidence < 0.7:
            recommendations.append("Low confidence - consider manual analysis")
        
        if operation in ['Encryption', 'Decryption']:
            if sig_features[0] > 0.5:  # Has S-box
                recommendations.append("Custom S-box detected - potential proprietary block cipher")
            if sig_features[2] > 0.5:  # Has rounds
                recommendations.append("Round-based structure detected - typical of iterative ciphers")
        
        if operation in ['Signing', 'Verification']:
            if sig_features[5] > 0.5:  # Arithmetic heavy
                recommendations.append("Heavy arithmetic operations - typical of asymmetric crypto")
        
        if operation == 'PRNG':
            if sig_features[4] > 0.5:  # Bitwise heavy
                recommendations.append("LFSR-like patterns detected")
        
        if sig_features[6] > 0.5:  # High entropy
            recommendations.append("High entropy regions detected - may contain encrypted data or keys")
        
        if not recommendations:
            recommendations.append("Analysis complete - standard proprietary crypto patterns detected")
        
        return recommendations
    
    def _predict_algorithm_name(
        self,
        binary_features: Dict[str, int],
        xor_ops: int,
        shift_ops: int,
        add_ops: int,
        mul_ops: int,
        top_operation: str
    ) -> str:
        """
        Heuristically predict the specific algorithm name based on operation label and features.
        Maps the 3 operation classes to specific proprietary algorithms.
        """
        # Extract binary features
        has_sbox = binary_features.get('has_sbox', 0) > 0
        has_permutation = binary_features.get('has_permutation', 0) > 0
        has_rounds = binary_features.get('has_rounds', 0) > 0
        key_schedule = binary_features.get('key_schedule', 0) > 0
        bitwise_heavy = binary_features.get('bitwise_heavy', 0) > 0
        arithmetic_heavy = binary_features.get('arithmetic_heavy', 0) > 0
        
        # Heuristic mapping based on characteristics
        if top_operation == "CustomXOR":  # Mapped from "Encryption"
            if xor_ops > 50 and not has_sbox and not has_rounds:
                return "CustomXOR"
            if has_rounds and bitwise_heavy:
                return "PropFeistel"
            if has_permutation and shift_ops > 30:
                return "BitMixCipher"
            if key_schedule and bitwise_heavy:
                return "LayerCascade"
            return "CustomXOR"  # Default for encryption-like
        
        elif top_operation == "RotaryHash":  # Mapped from "Hashing"
            if shift_ops > 40 and add_ops > 30:
                return "RotaryHash"
            if has_rounds and bitwise_heavy:
                return "DiffusionNet"
            if arithmetic_heavy and mul_ops > 15:
                return "ModularCrypt"
            if has_permutation:
                return "StateTransform"
            return "RotaryHash"  # Default for hashing-like
        
        elif top_operation == "KeyScheduler":  # Mapped from "KeyGeneration"
            if key_schedule and (xor_ops > 30 or mul_ops > 20):
                return "KeyScheduler"
            if has_sbox and has_rounds:
                return "NonLinearBox"
            if arithmetic_heavy and mul_ops > 15:
                return "ArithBlock"
            if bitwise_heavy:
                return "StreamLFSR"
            return "KeyScheduler"  # Default for key gen-like
        
        return "CustomXOR"  # Fallback
    
    def generate_report(self, binary_data: bytes) -> str:
        """Generate a detailed analysis report."""
        result = self.analyze_binary(binary_data)
        
        report = []
        report.append("=" * 60)
        report.append("PROPRIETARY CRYPTOGRAPHIC ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")
        
        report.append("")
        
        report.append("DETECTED ALGORITHM")
        report.append("-" * 40)
        report.append(f"  Algorithm: {result['algorithm_name']}")
        report.append("")
        
        report.append("BINARY FEATURES (Dataset Format)")
        report.append("-" * 40)
        report.append(f"  has_sbox:        {result['has_sbox']}")
        report.append(f"  has_permutation: {result['has_permutation']}")
        report.append(f"  has_rounds:      {result['has_rounds']}")
        report.append(f"  key_schedule:    {result['key_schedule']}")
        report.append(f"  bitwise_heavy:   {result['bitwise_heavy']}")
        report.append(f"  arithmetic_heavy: {result['arithmetic_heavy']}")
        report.append(f"  proprietary:     {result['proprietary']}")
        report.append("")
        
        report.append("RECOMMENDATIONS")
        report.append("-" * 40)
        for rec in result['recommendations']:
            report.append(f"  • {rec}")
        report.append("")
        
        report.append("=" * 60)
        
        return "\n".join(report)


def main():
    """Main inference function for testing."""
    print("Proprietary Cryptographic Inference Engine")
    print("=" * 50)
    
    try:
        engine = ProprietaryInference()
        
        # Generate test binary
        import struct
        np.random.seed(42)
        test_binary = bytes([
            0x31, 0xC0,  # XOR
            0xD1, 0xC8,  # ROR
            0x01, 0xD8,  # ADD
            0x31, 0xDB,  # XOR
        ] * 100 + [np.random.randint(0, 256) for _ in range(500)])
        
        print("\nAnalyzing test binary...")
        result = engine.analyze_binary(test_binary)
        
        print(f"\nResult:")
        print(f"  Operation: {result['operation']}")
        print(f"  Confidence: {result['confidence']*100:.1f}%")
        
        print("\nFull Report:")
        print(engine.generate_report(test_binary))
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please train the model first using: python train.py")


if __name__ == "__main__":
    main()
