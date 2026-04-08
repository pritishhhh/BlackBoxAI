"""
Training script for Proprietary Firmware Cryptographic Primitive Detection Model
Optimized for 96-98% accuracy with GPU acceleration, Focal Loss, and advanced training techniques

Key optimizations:
- GPU-optimized batch processing with mixed precision training
- Per-batch learning rate scheduling (OneCycleLR)
- Optimized dataloaders with prefetching and multi-worker support
- Fixed transformer-fusion integration for proper embedding flow
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts, OneCycleLR
from torch.cuda.amp import autocast, GradScaler
import os
import sys
from tqdm import tqdm
import numpy as np
import math
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import (
    DEVICE, CHECKPOINT_DIR, CHECKPOINT_PATH, DATASET_PATH,
    BATCH_SIZE, LEARNING_RATE, NUM_EPOCHS, WEIGHT_DECAY, WARMUP_EPOCHS,
    NUM_OPERATION_CLASSES, OPERATION_LABELS
)
from data.proprietary_dataset import create_proprietary_dataloaders
from models.proprietary_signature_scanner import ProprietarySignatureScanner
from models.proprietary_transformer import ProprietaryTransformerEncoder
from models.proprietary_fusion import ProprietaryFusionClassifier


class FocalLoss(nn.Module):
    """
    Focal Loss for multi-class classification.
    Focuses on hard examples for better handling of imbalanced classes.
    
    FL(p_t) = -alpha * (1 - p_t)^gamma * log(p_t)
    """
    def __init__(self, alpha: float = 0.25, gamma: float = 2.0, weight: torch.Tensor = None):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.weight = weight
        
    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # For multi-class: targets are one-hot or class indices
        if targets.dim() == 1:
            # Class indices to one-hot
            targets_one_hot = torch.zeros_like(logits)
            targets_one_hot.scatter_(1, targets.unsqueeze(1), 1)
            targets = targets_one_hot
        
        # Apply softmax to get probabilities
        probs = torch.softmax(logits, dim=-1)
        
        # Compute focal weights
        pt = (probs * targets).sum(dim=-1)  # Probability of true class
        focal_weight = (1 - pt) ** self.gamma
        
        # Cross entropy loss
        ce_loss = -torch.sum(targets * torch.log(probs + 1e-10), dim=-1)
        
        # Apply focal weight and alpha
        loss = self.alpha * focal_weight * ce_loss
        
        return loss.mean()


class LabelSmoothingCrossEntropy(nn.Module):
    """Cross entropy with label smoothing for better generalization."""
    def __init__(self, smoothing: float = 0.1):
        super().__init__()
        self.smoothing = smoothing
        
    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        n_classes = logits.size(-1)
        
        if targets.dim() == 1:
            # Class indices
            targets_one_hot = torch.zeros_like(logits)
            targets_one_hot.scatter_(1, targets.unsqueeze(1), 1)
            targets = targets_one_hot
        
        # Smooth labels
        targets = targets * (1 - self.smoothing) + self.smoothing / n_classes
        
        log_probs = torch.log_softmax(logits, dim=-1)
        loss = -torch.sum(targets * log_probs, dim=-1)
        
        return loss.mean()


class ProprietaryModel(nn.Module):
    """Complete proprietary detection model for training."""
    
    def __init__(self, transformer, fusion):
        super().__init__()
        self.transformer_encoder = transformer
        self.fusion_classifier = fusion
    
    def forward(self, opcode_ids, signature_features, entropy_vector, metadata_vector):
        # Layer 2: Transformer encoding - get embeddings, not logits
        transformer_output = self.transformer_encoder.get_embeddings(opcode_ids)
        
        # Layer 3: Feature fusion
        output = self.fusion_classifier(
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        )
        
        return output


def train_epoch(
    model: nn.Module,
    train_loader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: torch.device,
    scaler: GradScaler,
    scheduler: optim.lr_scheduler._LRScheduler,
    use_amp: bool = True
) -> float:
    """Train for one epoch with mixed precision and per-batch scheduler."""
    model.train()
    total_loss = 0.0
    total_correct = 0
    total_samples = 0
    
    pbar = tqdm(train_loader, desc="Training")
    for batch_idx, batch in enumerate(pbar):
        # Get batch data - use non_blocking for faster GPU transfer
        opcode_ids = batch['opcode_ids'].to(device, non_blocking=True)
        labels = batch['labels'].to(device, non_blocking=True)
        signature_features = batch['signature_features'].to(device, non_blocking=True)
        entropy_vector = batch['entropy_vector'].to(device, non_blocking=True)
        metadata_vector = batch['metadata_vector'].to(device, non_blocking=True)
        
        optimizer.zero_grad(set_to_none=True)  # Faster than zero_grad()
        
        # Forward pass with mixed precision
        if use_amp and device.type == 'cuda':
            with autocast():
                output = model(opcode_ids, signature_features, entropy_vector, metadata_vector)
                loss = criterion(output, labels)
            
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            scaler.step(optimizer)
            scaler.update()
        else:
            output = model(opcode_ids, signature_features, entropy_vector, metadata_vector)
            loss = criterion(output, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
        
        # Step scheduler per batch (OneCycleLR requires this)
        scheduler.step()
        
        # Calculate accuracy
        predictions = torch.argmax(output, dim=-1)
        targets = torch.argmax(labels, dim=-1)
        correct = (predictions == targets).sum().item()
        
        total_loss += loss.item()
        total_correct += correct
        total_samples += labels.size(0)
        
        pbar.set_postfix({
            'loss': f'{loss.item():.4f}',
            'acc': f'{total_correct/total_samples*100:.1f}%',
            'lr': f'{scheduler.get_last_lr()[0]:.2e}'
        })
    
    avg_loss = total_loss / len(train_loader)
    accuracy = total_correct / total_samples
    
    return avg_loss, accuracy


def validate(
    model: nn.Module,
    val_loader,
    criterion: nn.Module,
    device: torch.device
) -> tuple:
    """Validate model and compute per-class metrics."""
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total_samples = 0
    
    # Per-class tracking
    class_correct = torch.zeros(NUM_OPERATION_CLASSES)
    class_total = torch.zeros(NUM_OPERATION_CLASSES)
    
    # Confusion matrix
    confusion_matrix = torch.zeros(NUM_OPERATION_CLASSES, NUM_OPERATION_CLASSES)
    
    with torch.no_grad():
        for batch in tqdm(val_loader, desc="Validating"):
            opcode_ids = batch['opcode_ids'].to(device)
            labels = batch['labels'].to(device)
            signature_features = batch['signature_features'].to(device)
            entropy_vector = batch['entropy_vector'].to(device)
            metadata_vector = batch['metadata_vector'].to(device)
            
            # Forward pass
            output = model(opcode_ids, signature_features, entropy_vector, metadata_vector)
            loss = criterion(output, labels)
            
            # Predictions
            predictions = torch.argmax(output, dim=-1)
            targets = torch.argmax(labels, dim=-1)
            
            # Update totals
            total_loss += loss.item()
            total_correct += (predictions == targets).sum().item()
            total_samples += labels.size(0)
            
            # Per-class accuracy
            for i in range(NUM_OPERATION_CLASSES):
                class_mask = (targets == i)
                class_total[i] += class_mask.sum().item()
                class_correct[i] += ((predictions == i) & class_mask).sum().item()
            
            # Update confusion matrix
            for t, p in zip(targets.cpu(), predictions.cpu()):
                confusion_matrix[t.long(), p.long()] += 1
    
    avg_loss = total_loss / len(val_loader)
    accuracy = total_correct / total_samples
    
    # Per-class accuracy
    per_class_acc = {}
    for i in range(NUM_OPERATION_CLASSES):
        if class_total[i] > 0:
            per_class_acc[OPERATION_LABELS[i]] = (class_correct[i] / class_total[i]).item()
        else:
            per_class_acc[OPERATION_LABELS[i]] = 0.0
    
    return avg_loss, accuracy, per_class_acc, confusion_matrix


def main():
    """Main training function."""
    print("=" * 80)
    print("Proprietary Firmware Cryptographic Primitive Detection Model - Training")
    print("OPTIMIZED FOR 96-98% ACCURACY WITH GPU ACCELERATION")
    print(f"Device: {DEVICE}")
    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"CUDA Version: {torch.version.cuda}")
        torch.backends.cudnn.benchmark = True  # Optimize for consistent input sizes
        torch.backends.cudnn.deterministic = False  # Allow non-deterministic for speed
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Create checkpoint directory
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    
    # Hyperparameters
    num_epochs = NUM_EPOCHS
    learning_rate = LEARNING_RATE
    warmup_epochs = WARMUP_EPOCHS
    use_amp = DEVICE.type == 'cuda'
    
    # Use the configured dataset path for training.
    dataset_path = DATASET_PATH
    if not os.path.exists(dataset_path):
        dataset_path = DATASET_PATH
        if not os.path.exists(dataset_path):
            print(f"Dataset not found at {dataset_path}")
            print("Please run generate_binaries.py first or provide a valid dataset path")
            return
    
    print(f"\n[1/5] Loading dataset from {dataset_path}...")
    train_loader, val_loader, test_loader, tokenizer = create_proprietary_dataloaders(
        dataset_path,
        batch_size=BATCH_SIZE
    )
    vocab_size = tokenizer.get_vocab_size()
    print(f"Vocabulary size: {vocab_size}")
    print(f"Training batches: {len(train_loader)}")
    
    # Initialize models
    print("\n[2/5] Initializing models...")
    signature_scanner = ProprietarySignatureScanner()
    
    transformer_encoder = ProprietaryTransformerEncoder(
        vocab_size=vocab_size,
        num_classes=NUM_OPERATION_CLASSES
    ).to(DEVICE)
    
    fusion_classifier = ProprietaryFusionClassifier(
        num_classes=NUM_OPERATION_CLASSES
    ).to(DEVICE)
    
    # Create complete model
    model = ProprietaryModel(transformer_encoder, fusion_classifier)
    model = model.to(DEVICE)
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    
    # Calculate class weights
    print("\n[3/5] Setting up optimizer and loss function...")
    label_counts = torch.zeros(NUM_OPERATION_CLASSES)
    for batch in train_loader:
        batch_labels = batch['labels']
        targets = torch.argmax(batch_labels, dim=-1)
        for t in targets:
            label_counts[t] += 1
    
    # Inverse frequency weights
    total_samples = label_counts.sum()
    class_weights = total_samples / (NUM_OPERATION_CLASSES * label_counts + 1e-6)
    class_weights = class_weights / class_weights.min()
    class_weights = torch.clamp(class_weights, min=1.0, max=5.0)
    class_weights = class_weights.to(DEVICE)
    
    print(f"Class weights: {dict(zip(OPERATION_LABELS, [f'{w:.2f}' for w in class_weights.cpu().tolist()]))}")
    
    # Loss function - Focal Loss with label smoothing
    criterion = FocalLoss(alpha=0.25, gamma=2.0, weight=class_weights)
    
    # Optimizer with different learning rates
    optimizer = optim.AdamW([
        {'params': transformer_encoder.parameters(), 'lr': learning_rate},
        {'params': fusion_classifier.parameters(), 'lr': learning_rate * 1.5},  # Slightly higher LR for classifier
    ], weight_decay=WEIGHT_DECAY, betas=(0.9, 0.999), eps=1e-8)
    
    # Learning rate scheduler - OneCycleLR steps per batch
    total_steps = len(train_loader) * num_epochs
    scheduler = OneCycleLR(
        optimizer,
        max_lr=[learning_rate * 5, learning_rate * 7.5],  # More reasonable max LR
        total_steps=total_steps,
        pct_start=0.15,  # 15% warmup
        anneal_strategy='cos',
        div_factor=10,  # Start 10x lower
        final_div_factor=100  # End 100x lower
    )
    
    # Mixed precision scaler
    scaler = GradScaler() if use_amp else None
    
    # Training loop
    print(f"\n[4/5] Starting training for {num_epochs} epochs...")
    print(f"Using AMP: {use_amp}")
    
    best_val_acc = 0.0
    best_val_loss = float('inf')
    patience_counter = 0
    max_patience = 30  # More patience for reaching 96-98%
    
    for epoch in range(num_epochs):
        print(f"\n{'='*80}")
        print(f"Epoch {epoch+1}/{num_epochs}")
        print(f"{'='*80}")
        
        # Train
        train_loss, train_acc = train_epoch(
            model,
            train_loader,
            criterion,
            optimizer,
            DEVICE,
            scaler,
            scheduler,
            use_amp
        )
        
        # Validate
        val_loss, val_acc, per_class_acc, _ = validate(
            model,
            val_loader,
            criterion,
            DEVICE
        )
        
        # Print results
        print(f"\nTrain Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}%")
        print(f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc*100:.2f}%")
        print("\nPer-Class Validation Accuracy:")
        for label, acc in per_class_acc.items():
            status = "[OK]" if acc >= 0.9 else "[  ]"
            print(f"  {status} {label:15s}: {acc*100:.2f}%")
        
        labels_above_90 = sum(1 for acc in per_class_acc.values() if acc >= 0.9)
        print(f"\nLabels >= 90%: {labels_above_90}/{NUM_OPERATION_CLASSES}")
        
        # Save best model
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_val_loss = val_loss
            patience_counter = 0
            
            print(f"\n[OK] New best accuracy: {val_acc*100:.2f}%")
            print(f"Saving model to {CHECKPOINT_PATH}...")
            
            torch.save({
                'epoch': epoch,
                'model_state_dict': {
                    'transformer': transformer_encoder.state_dict(),
                    'fusion': fusion_classifier.state_dict()
                },
                'tokenizer': tokenizer,
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': val_loss,
                'train_loss': train_loss,
                'val_accuracy': val_acc,
                'per_class_acc': per_class_acc,
                'vocab_size': vocab_size,
                'config': {
                    'num_classes': NUM_OPERATION_CLASSES,
                    'operation_labels': OPERATION_LABELS
                }
            }, CHECKPOINT_PATH)
            print("[OK] Model saved!")
        else:
            patience_counter += 1
        
        # Early stopping
        if patience_counter >= max_patience:
            print(f"\nEarly stopping after {patience_counter} epochs without improvement")
            break
        
        # Check for target accuracy (96-98% range)
        if val_acc >= 0.96:
            print(f"\n[SUCCESS] Reached target accuracy of {val_acc*100:.2f}%!")
            if val_acc >= 0.98:
                print(f"[SUCCESS] Maximum target accuracy of 98% achieved!")
                break
    
    # Final evaluation
    print("\n[5/5] Evaluating on test set...")
    test_loss, test_acc, test_per_class, confusion = validate(
        model,
        test_loader,
        criterion,
        DEVICE
    )
    
    print(f"\n{'='*80}")
    print("Training Complete!")
    print(f"{'='*80}")
    print(f"Test Loss: {test_loss:.4f}")
    print(f"Test Accuracy: {test_acc*100:.2f}%")
    print("\nPer-Class Test Accuracy:")
    for label, acc in test_per_class.items():
        status = "[OK]" if acc >= 0.9 else "[  ]"
        print(f"  {status} {label:15s}: {acc*100:.2f}%")
    
    labels_above_90_test = sum(1 for acc in test_per_class.values() if acc >= 0.9)
    print(f"\nLabels >= 90%: {labels_above_90_test}/{NUM_OPERATION_CLASSES}")
    print(f"\nBest validation accuracy: {best_val_acc*100:.2f}%")
    print(f"Model saved to: {CHECKPOINT_PATH}")


if __name__ == "__main__":
    main()

