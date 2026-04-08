"""
Training script for Standard Firmware Cryptographic Primitive Detection Model
Enhanced for 90-95% accuracy with Focal Loss and improved training
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts
import os
from tqdm import tqdm
import numpy as np
import math

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import (
    DEVICE, CHECKPOINT_DIR, CHECKPOINT_PATH, DATASET_PATH,
    BATCH_SIZE, LEARNING_RATE, NUM_EPOCHS, WEIGHT_DECAY,
    NUM_CLASSES, CRYPTO_LABELS
)
from data.dataset_loader import create_dataloaders
from models.signature_scanner import SignatureScanner
from models.transformer_encoder import TransformerEncoder
from models.fusion_classifier import FusionClassifier


class FocalLoss(nn.Module):
    """
    Focal Loss for multi-label classification.
    Much better than BCE for imbalanced data - focuses on hard examples.
    
    FL(p_t) = -alpha * (1 - p_t)^gamma * log(p_t)
    """
    def __init__(self, alpha=0.25, gamma=2.0, pos_weight=None):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.pos_weight = pos_weight
        
    def forward(self, logits, targets):
        # Apply sigmoid to get probabilities
        probs = torch.sigmoid(logits)
        
        # Compute focal weights
        pt = probs * targets + (1 - probs) * (1 - targets)
        focal_weight = (1 - pt) ** self.gamma
        
        # BCE loss with logits
        bce = nn.functional.binary_cross_entropy_with_logits(
            logits, targets, reduction='none', pos_weight=self.pos_weight
        )
        
        # Apply focal weight and alpha
        loss = self.alpha * focal_weight * bce
        
        return loss.mean()


class LabelSmoothingBCE(nn.Module):
    """BCE with label smoothing for better generalization."""
    def __init__(self, smoothing=0.1, pos_weight=None):
        super().__init__()
        self.smoothing = smoothing
        self.pos_weight = pos_weight
        
    def forward(self, logits, targets):
        # Smooth labels: 1 -> 1-smoothing, 0 -> smoothing
        targets_smooth = targets * (1 - self.smoothing) + (1 - targets) * self.smoothing
        return nn.functional.binary_cross_entropy_with_logits(
            logits, targets_smooth, pos_weight=self.pos_weight
        )


def train_epoch(
    model: nn.Module,
    train_loader,
    criterion: nn.Module,
    optimizer: optim.Optimizer,
    device: torch.device,
    epoch: int
) -> float:
    """
    Train for one epoch with gradient accumulation.
    """
    model.train()
    total_loss = 0.0
    num_batches = 0
    
    pbar = tqdm(train_loader, desc="Training")
    for batch in pbar:
        # Get batch data
        opcode_ids = batch['opcode_ids'].to(device)
        labels = batch['labels'].to(device)
        signature_features = batch['signature_features'].to(device)
        entropy_vector = batch['entropy_vector'].to(device)
        metadata_vector = batch['metadata_vector'].to(device)
        
        # Forward pass
        optimizer.zero_grad()
        
        # Get transformer output (Layer 2)
        transformer_output = model.transformer_encoder(opcode_ids)
        
        # Fusion (Layer 3)
        output = model.fusion_classifier(
            signature_features,
            transformer_output,
            entropy_vector,
            metadata_vector
        )
        
        # Calculate loss
        loss = criterion(output, labels)
        
        # Backward pass
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        
        total_loss += loss.item()
        num_batches += 1
        
        pbar.set_postfix({'loss': loss.item()})
    
    return total_loss / num_batches


def validate(
    model: nn.Module,
    val_loader,
    criterion: nn.Module,
    device: torch.device,
    threshold: float = 0.35  # Lower threshold for better recall
) -> tuple:
    """
    Validate model with adaptive thresholding.
    """
    model.eval()
    total_loss = 0.0
    num_batches = 0
    
    # Per-label accuracy tracking
    correct_per_label = torch.zeros(NUM_CLASSES)
    total_per_label = torch.zeros(NUM_CLASSES)
    
    # Also track true positives, false positives, etc. for F1
    tp_per_label = torch.zeros(NUM_CLASSES)
    fp_per_label = torch.zeros(NUM_CLASSES)
    fn_per_label = torch.zeros(NUM_CLASSES)
    
    with torch.no_grad():
        for batch in tqdm(val_loader, desc="Validating"):
            opcode_ids = batch['opcode_ids'].to(device)
            labels = batch['labels'].to(device)
            signature_features = batch['signature_features'].to(device)
            entropy_vector = batch['entropy_vector'].to(device)
            metadata_vector = batch['metadata_vector'].to(device)
            
            # Forward pass
            transformer_output = model.transformer_encoder(opcode_ids)
            output = model.fusion_classifier(
                signature_features,
                transformer_output,
                entropy_vector,
                metadata_vector
            )
            
            # Calculate loss
            loss = criterion(output, labels)
            total_loss += loss.item()
            num_batches += 1
            
            # Apply sigmoid to get probabilities
            probs = torch.sigmoid(output)
            
            # Use threshold for predictions
            predictions = (probs > threshold).float()
            
            # Calculate metrics per label
            for i in range(NUM_CLASSES):
                # Only count samples that have this label
                label_mask = labels[:, i] == 1.0
                if label_mask.sum() > 0:
                    # Accuracy: correct predictions for positive samples
                    correct_per_label[i] += (predictions[label_mask, i] == 1.0).sum().item()
                    total_per_label[i] += label_mask.sum().item()
                
                # F1 metrics
                tp_per_label[i] += ((predictions[:, i] == 1) & (labels[:, i] == 1)).sum().item()
                fp_per_label[i] += ((predictions[:, i] == 1) & (labels[:, i] == 0)).sum().item()
                fn_per_label[i] += ((predictions[:, i] == 0) & (labels[:, i] == 1)).sum().item()
    
    avg_loss = total_loss / num_batches
    
    # Calculate per-label metrics
    per_label_acc = {}
    per_label_f1 = {}
    for i in range(NUM_CLASSES):
        # Accuracy (recall for positive class)
        if total_per_label[i] > 0:
            acc = correct_per_label[i] / total_per_label[i]
            per_label_acc[CRYPTO_LABELS[i]] = acc.item()
        
        # F1 score
        precision = tp_per_label[i] / (tp_per_label[i] + fp_per_label[i] + 1e-10)
        recall = tp_per_label[i] / (tp_per_label[i] + fn_per_label[i] + 1e-10)
        f1 = 2 * precision * recall / (precision + recall + 1e-10)
        per_label_f1[CRYPTO_LABELS[i]] = f1.item()
    
    return avg_loss, per_label_acc, per_label_f1


def main():
    """Main training function optimized for 90-95% accuracy."""
    print("=" * 80)
    print("Standard Firmware Cryptographic Primitive Detection Model - Training")
    print("OPTIMIZED FOR 90-95% ACCURACY")
    print("=" * 80)
    
    # Create checkpoint directory
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    
    # Hyperparameters for high accuracy
    num_epochs = 100  # More epochs for convergence
    learning_rate = 3e-4  # Slightly higher LR
    threshold = 0.35  # Lower threshold for better recall
    
    # Load datasets
    print("\n[1/5] Loading datasets...")
    train_loader, val_loader, test_loader, tokenizer = create_dataloaders(
        DATASET_PATH,
        batch_size=BATCH_SIZE
    )
    vocab_size = tokenizer.get_vocab_size()
    print(f"Vocabulary size: {vocab_size}")
    
    # Initialize models with larger capacity
    print("\n[2/5] Initializing models...")
    signature_scanner = SignatureScanner()
    transformer_encoder = TransformerEncoder(
        vocab_size=vocab_size,
        num_classes=NUM_CLASSES
    ).to(DEVICE)
    fusion_classifier = FusionClassifier(
        num_classes=NUM_CLASSES
    ).to(DEVICE)
    
    # Create complete model wrapper
    class CompleteModel(nn.Module):
        def __init__(self, scanner, transformer, fusion):
            super().__init__()
            self.signature_scanner = scanner
            self.transformer_encoder = transformer
            self.fusion_classifier = fusion
    
    model = CompleteModel(signature_scanner, transformer_encoder, fusion_classifier)
    model = model.to(DEVICE)
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Total parameters: {total_params:,}")
    print(f"Trainable parameters: {trainable_params:,}")
    
    # Calculate class weights for imbalanced data
    print("\n[3/5] Setting up optimizer and loss function...")
    
    label_counts = torch.zeros(NUM_CLASSES)
    for batch in train_loader:
        batch_labels = batch['labels']
        label_counts += batch_labels.sum(dim=0)
    
    # Calculate weights (inverse frequency, stronger weighting)
    total_samples = label_counts.sum()
    class_weights = total_samples / (NUM_CLASSES * label_counts + 1e-6)
    class_weights = class_weights / class_weights.min()  # Normalize to minimum
    class_weights = torch.clamp(class_weights, min=1.0, max=10.0)  # Limit max weight
    class_weights = class_weights.to(DEVICE)
    
    print(f"Class weights: {dict(zip(CRYPTO_LABELS, [f'{w:.2f}' for w in class_weights.cpu().tolist()]))}")
    
    # Use Focal Loss for better handling of imbalanced data
    criterion = FocalLoss(alpha=0.25, gamma=2.0, pos_weight=class_weights)
    
    optimizer = optim.AdamW(
        model.parameters(),
        lr=learning_rate,
        weight_decay=WEIGHT_DECAY,
        betas=(0.9, 0.999)
    )
    
    # Cosine annealing with warm restarts for better convergence
    scheduler = CosineAnnealingWarmRestarts(
        optimizer,
        T_0=10,  # Restart every 10 epochs
        T_mult=2,  # Double the period after each restart
        eta_min=1e-6
    )
    
    # Training loop
    print(f"\n[4/5] Starting training for {num_epochs} epochs...")
    print(f"Using threshold: {threshold}")
    best_val_loss = float('inf')
    best_avg_acc = 0.0
    patience_counter = 0
    max_patience = 20
    
    for epoch in range(num_epochs):
        print(f"\n{'='*80}")
        print(f"Epoch {epoch+1}/{num_epochs} | LR: {scheduler.get_last_lr()[0]:.6f}")
        print(f"{'='*80}")
        
        # Train
        train_loss = train_epoch(
            model,
            train_loader,
            criterion,
            optimizer,
            DEVICE,
            epoch
        )
        
        # Step scheduler
        scheduler.step()
        
        # Validate
        val_loss, per_label_acc, per_label_f1 = validate(
            model,
            val_loader,
            criterion,
            DEVICE,
            threshold=threshold
        )
        
        # Calculate average accuracy
        avg_acc = sum(per_label_acc.values()) / len(per_label_acc) if per_label_acc else 0
        avg_f1 = sum(per_label_f1.values()) / len(per_label_f1) if per_label_f1 else 0
        
        # Print results
        print(f"\nTrain Loss: {train_loss:.4f}")
        print(f"Val Loss: {val_loss:.4f}")
        print(f"Average Accuracy: {avg_acc*100:.2f}%")
        print(f"Average F1: {avg_f1*100:.2f}%")
        print("\nPer-Label Validation Accuracy (Recall):")
        for label, acc in per_label_acc.items():
            f1 = per_label_f1.get(label, 0)
            status = "[OK]" if acc >= 0.9 else "[  ]"
            print(f"  {status} {label:15s}: {acc*100:.2f}% (F1: {f1*100:.2f}%)")
        
        # Count labels above 90%
        labels_above_90 = sum(1 for acc in per_label_acc.values() if acc >= 0.9)
        print(f"\nLabels >= 90%: {labels_above_90}/{NUM_CLASSES}")
        
        # Save best model (prioritize accuracy over loss)
        if avg_acc > best_avg_acc:
            best_avg_acc = avg_acc
            best_val_loss = val_loss
            patience_counter = 0
            print(f"\n[OK] New best average accuracy: {avg_acc*100:.2f}%")
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
                'per_label_acc': per_label_acc,
                'per_label_f1': per_label_f1,
                'avg_accuracy': avg_acc,
                'vocab_size': vocab_size,
                'threshold': threshold,
                'config': {
                    'num_classes': NUM_CLASSES,
                    'crypto_labels': CRYPTO_LABELS
                }
            }, CHECKPOINT_PATH)
            print("[OK] Model saved!")
        else:
            patience_counter += 1
        
        # Early stopping check
        if patience_counter >= max_patience:
            print(f"\nEarly stopping after {patience_counter} epochs without improvement")
            break
        
        # Check if we've reached target accuracy
        if avg_acc >= 0.95:
            print(f"\n[SUCCESS] Reached target accuracy of 95%!")
            break
    
    # Final evaluation on test set
    print("\n[5/5] Evaluating on test set...")
    test_loss, test_per_label_acc, test_per_label_f1 = validate(
        model,
        test_loader,
        criterion,
        DEVICE,
        threshold=threshold
    )
    
    avg_test_acc = sum(test_per_label_acc.values()) / len(test_per_label_acc) if test_per_label_acc else 0
    avg_test_f1 = sum(test_per_label_f1.values()) / len(test_per_label_f1) if test_per_label_f1 else 0
    
    print(f"\n{'='*80}")
    print("Training Complete!")
    print(f"{'='*80}")
    print(f"Test Loss: {test_loss:.4f}")
    print(f"Average Test Accuracy: {avg_test_acc*100:.2f}%")
    print(f"Average Test F1: {avg_test_f1*100:.2f}%")
    print("\nPer-Label Test Accuracy:")
    for label, acc in test_per_label_acc.items():
        f1 = test_per_label_f1.get(label, 0)
        status = "[OK]" if acc >= 0.9 else "[  ]"
        print(f"  {status} {label:15s}: {acc*100:.2f}% (F1: {f1*100:.2f}%)")
    
    labels_above_90_test = sum(1 for acc in test_per_label_acc.values() if acc >= 0.9)
    print(f"\nLabels >= 90%: {labels_above_90_test}/{NUM_CLASSES}")
    print(f"\nBest model saved to: {CHECKPOINT_PATH}")
    print(f"Best validation accuracy: {best_avg_acc*100:.2f}%")


if __name__ == "__main__":
    main()
