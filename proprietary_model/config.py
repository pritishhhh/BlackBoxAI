"""
Configuration file for Proprietary Firmware Cryptographic Primitive Detection Model
Designed for detecting proprietary/custom cryptographic implementations
"""
import torch
import os

# Device configuration - Force CUDA usage if possible
# PyTorch 3.13 on Windows might not detect CUDA correctly, so we try harder
if torch.cuda.is_available():
    DEVICE = torch.device("cuda")
    print(f"[CONFIG] Using GPU: {torch.cuda.get_device_name(0)}")
else:
    # Try to force CUDA anyway by setting environment variable
    os.environ['CUDA_VISIBLE_DEVICES'] = '0'
    try:
        # Try creating a tensor on CUDA to verify it works
        test = torch.zeros(1)
        test = test.cuda()
        DEVICE = torch.device("cuda")
        print(f"[CONFIG] CUDA forced successfully: {torch.cuda.get_device_name(0)}")
    except Exception as e:
        DEVICE = torch.device("cpu")
        print(f"[CONFIG] Using CPU - CUDA not available: {e}")

# Dataset paths - use absolute paths based on this file's location
_CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_CONFIG_DIR)

DATASET_PATH = os.path.join(_PROJECT_ROOT, "datasets", "Proprietary", "proprietary_crypto_dataset.csv")
CHECKPOINT_DIR = os.path.join(_CONFIG_DIR, "checkpoints")
CHECKPOINT_PATH = os.path.join(CHECKPOINT_DIR, "proprietary_model.pt")

# Binary generation configuration
NUM_ALGORITHMS = 20
VARIATIONS_PER_ALGO = 1000
TOTAL_BINARIES = NUM_ALGORITHMS * VARIATIONS_PER_ALGO  # 20,000

# Proprietary Algorithm Names (20 custom algorithms)
PROPRIETARY_ALGORITHMS = [
    "CustomXOR",           # XOR-based block cipher
    "PropFeistel",         # Custom Feistel network
    "BitMixCipher",        # Bit mixing encryption
    "RotaryHash",          # Rotation-based hash
    "ArithBlock",          # Arithmetic block cipher
    "SubPermute",          # Substitution-permutation network
    "ChainMix",            # Chain mixing cipher
    "StreamLFSR",          # LFSR-based stream cipher
    "MixColumn",           # Mix-column based cipher
    "BitShuffler",         # Bit shuffling cipher
    "ModularCrypt",        # Modular arithmetic cipher
    "LayerCascade",        # Cascaded layer encryption
    "NonLinearBox",        # Non-linear S-box cipher
    "DiffusionNet",        # Diffusion network cipher
    "ConfusionCore",       # Confusion-based cipher
    "HybridCrypt",         # Hybrid cipher system
    "KeyScheduler",        # Custom key scheduling
    "StateTransform",      # State transformation cipher
    "BlockPermute",        # Block permutation cipher
    "StreamMix",           # Stream mixing cipher
]

# Operation Labels (what the crypto operation does)
# Matches the existing proprietary_crypto_dataset.csv
# Using algorithm names as display labels instead of operation types
OPERATION_LABELS = [
    "CustomXOR",      # Encryption operations (renamed from "Encryption")
    "RotaryHash",     # Hashing operations (renamed from "Hashing")
    "KeyScheduler",   # Key generation operations (renamed from "KeyGeneration")
]
NUM_OPERATION_CLASSES = len(OPERATION_LABELS)

# Crypto Type Categories (kept for reference, not actively used in current model)
CRYPTO_TYPES = [
    "BlockCipher",
    "StreamCipher",
    "HashFunction",
    "MAC",
    "AsymmetricCrypto",
    "KeyExchange",
    "PRNG",
]

# Layer 1 - Proprietary Signature Scanner Configuration
PROPRIETARY_SIGNATURE_FEATURES = {
    "HAS_SBOX": 0,
    "HAS_PERMUTATION": 0,
    "HAS_ROUNDS": 0,
    "HAS_KEY_SCHEDULE": 0,
    "BITWISE_HEAVY": 0,
    "ARITHMETIC_HEAVY": 0,
    "HIGH_ENTROPY": 0,
    "LOOP_STRUCTURE": 0,
}
SIGNATURE_FEATURE_DIM = len(PROPRIETARY_SIGNATURE_FEATURES)

# Layer 2 - Transformer Configuration (Optimized for GPU speed and accuracy)
EMBEDDING_DIM = 256  # Optimal balance of speed and capacity
NUM_LAYERS = 6       # More layers for better accuracy (GPU can handle it)
NUM_HEADS = 8        # Balanced for speed
FEEDFORWARD_DIM = 1024  # Larger for better representation
DROPOUT = 0.2  # Reduced dropout for better learning
MAX_SEQ_LENGTH = 128  # Optimized length for GPU efficiency
VOCAB_SIZE = 5000     # Reasonable vocab size

# Layer 3 - Fusion Classifier Configuration (Optimized for GPU and accuracy)
FUSION_HIDDEN_DIM_1 = 768   # Larger for better fusion
FUSION_HIDDEN_DIM_2 = 384   # Balanced
FUSION_HIDDEN_DIM_3 = 192   # Adequate for final classification
# Metadata = CSV(25) only - removed all label-specific features and one-hot encodings
# This prevents data leakage and forces model to learn from actual code patterns
METADATA_FEATURE_DIM = 25   # Only CSV features (no label leakage)
ENTROPY_VECTOR_DIM = 16     # Entropy features
CSV_FEATURE_DIM = 25        # CSV-derived features

# Training Configuration (Optimized for GPU)
BATCH_SIZE = 128  # Large batch for GPU efficiency
LEARNING_RATE = 3e-4  # Slightly higher for faster convergence
NUM_EPOCHS = 100  # More epochs with early stopping
WEIGHT_DECAY = 1e-4  # Regularization
TRAIN_SPLIT = 0.8
VAL_SPLIT = 0.1
TEST_SPLIT = 0.1
WARMUP_EPOCHS = 3  # Reduced warmup

# Feature extraction thresholds
ENTROPY_THRESHOLD = 6.5
HIGH_XOR_THRESHOLD = 30
HIGH_SHIFT_THRESHOLD = 20
HIGH_ARITHMETIC_THRESHOLD = 25

# Binary generation parameters
MIN_CODE_SIZE = 256
MAX_CODE_SIZE = 4096
MIN_DATA_SIZE = 64
MAX_DATA_SIZE = 1024
MIN_STACK_SIZE = 128
MAX_STACK_SIZE = 1024

