#!/usr/bin/env python3
"""
Train Trajectory Classifier: QLoRA fine-tuning for deception detection.

Self-contained training script designed to run on RunPod (A100 80GB).
Fine-tunes a small LLM to classify agent trajectories as honest or
deceptive, and identify the deception type.

Usage (on RunPod):
    # 1. Prepare data (run locally first, upload the splits)
    python -m trajectoryshield.trajectory_shield.classifier --dataset data/deceptive_comply_bench/dataset.json

    # 2. Train (on RunPod with A100)
    python -m trajectoryshield.trajectory_shield.train_classifier \
        --train-data data/classifier_splits/train.jsonl \
        --val-data data/classifier_splits/val.jsonl \
        --model Qwen/Qwen2.5-7B-Instruct \
        --output-dir models/trajectory_classifier \
        --epochs 5

    # 3. Evaluate (on RunPod or locally)
    python -m trajectoryshield.trajectory_shield.train_classifier \
        --eval-only \
        --test-data data/classifier_splits/test.jsonl \
        --model Qwen/Qwen2.5-7B-Instruct \
        --adapter-path models/trajectory_classifier \
        --output-dir results/classifier_eval
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


def train(args):
    """Run QLoRA fine-tuning."""
    import torch
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
    from trl import SFTTrainer, SFTConfig
    from datasets import load_dataset

    print("=" * 60)
    print("Trajectory Classifier Training")
    print("=" * 60)
    print(f"  Base model:  {args.model}")
    print(f"  Train data:  {args.train_data}")
    print(f"  Val data:    {args.val_data}")
    print(f"  Output:      {args.output_dir}")
    print(f"  Epochs:      {args.epochs}")
    print(f"  LoRA rank:   {args.lora_rank}")
    print(f"  LR:          {args.lr}")
    print(f"  Batch size:  {args.batch_size} (grad accum: {args.grad_accum})")
    print(f"  Max seq len: {args.max_seq_length}")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    use_4bit = device == "cuda" and args.use_4bit
    print(f"  Device:      {device}")
    print(f"  4-bit:       {use_4bit}")
    print("=" * 60)

    # --- Load tokenizer ---
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # --- Load model ---
    model_kwargs = {"trust_remote_code": True}

    if use_4bit:
        from transformers import BitsAndBytesConfig
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model_kwargs["quantization_config"] = bnb_config
        model_kwargs["device_map"] = "auto"
    else:
        model_kwargs["torch_dtype"] = torch.float16
        model_kwargs["device_map"] = "auto"

    print(f"\nLoading model: {args.model}...")
    model = AutoModelForCausalLM.from_pretrained(args.model, **model_kwargs)

    if use_4bit:
        model = prepare_model_for_kbit_training(model)

    # --- LoRA config ---
    lora_config = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )

    model = get_peft_model(model, lora_config)
    trainable, total = model.get_nb_trainable_parameters()
    print(f"\nTrainable parameters: {trainable:,} / {total:,} ({100 * trainable / total:.2f}%)")

    # --- Load datasets ---
    print(f"\nLoading training data from {args.train_data}...")
    train_dataset = load_dataset("json", data_files=args.train_data, split="train")
    print(f"  Train examples: {len(train_dataset)}")

    val_dataset = None
    if args.val_data and os.path.exists(args.val_data):
        val_dataset = load_dataset("json", data_files=args.val_data, split="train")
        print(f"  Val examples: {len(val_dataset)}")

    # --- Training config ---
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    training_args = SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        weight_decay=0.01,
        logging_steps=10,
        save_strategy="epoch",
        eval_strategy="epoch" if val_dataset else "no",
        save_total_limit=2,
        load_best_model_at_end=True if val_dataset else False,
        metric_for_best_model="eval_loss" if val_dataset else None,
        greater_is_better=False if val_dataset else None,
        bf16=torch.cuda.is_available(),
        fp16=False,
        max_seq_length=args.max_seq_length,
        packing=False,  # Don't pack -- each example is one trajectory
        report_to="none",  # No wandb
        seed=int(os.environ.get("ABLATION_SEED", args.seed if hasattr(args, 'seed') else 42)),
    )

    # --- Formatting function: convert "messages" -> text via chat template ---
    def formatting_func(example):
        """Apply tokenizer chat template to convert messages to text."""
        return tokenizer.apply_chat_template(
            example["messages"], tokenize=False, add_generation_prompt=False
        )

    # --- Train ---
    print("\nStarting training...")
    start_time = time.time()

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        processing_class=tokenizer,
        formatting_func=formatting_func,
    )

    trainer.train()
    elapsed = time.time() - start_time
    print(f"\nTraining complete in {elapsed:.1f}s ({elapsed / 60:.1f} min)")

    # --- Save adapter ---
    adapter_dir = output_dir / "final_adapter"
    model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    print(f"\nAdapter saved to: {adapter_dir}")

    # Save training config
    config = {
        "base_model": args.model,
        "lora_rank": args.lora_rank,
        "lora_alpha": args.lora_alpha,
        "lora_dropout": args.lora_dropout,
        "epochs": args.epochs,
        "learning_rate": args.lr,
        "batch_size": args.batch_size,
        "grad_accum": args.grad_accum,
        "max_seq_length": args.max_seq_length,
        "use_4bit": use_4bit,
        "training_time_s": elapsed,
        "trainable_params": trainable,
        "total_params": total,
    }
    config_path = output_dir / "training_config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"Config saved to: {config_path}")

    return str(adapter_dir)


def evaluate(args):
    """Evaluate the trained classifier on test data."""
    import torch
    from collections import defaultdict

    print("=" * 60)
    print("Trajectory Classifier Evaluation")
    print("=" * 60)
    print(f"  Base model:    {args.model}")
    print(f"  Adapter:       {args.adapter_path}")
    print(f"  Test data:     {args.test_data}")
    print("=" * 60)

    # Load the classifier
    from trajectoryshield.trajectory_shield.classifier import TrajectoryClassifier
    classifier = TrajectoryClassifier(
        base_model=args.model,
        adapter_path=args.adapter_path,
        load_in_4bit=args.use_4bit and torch.cuda.is_available(),
    )

    # Load test trajectories
    from trajectoryshield.benchmark.trajectory_schema import BenchmarkDataset
    test_jsonl = Path(args.test_data)

    # We need the actual Trajectory objects for evaluation.
    # Load from the full dataset and match by the test split.
    dataset = BenchmarkDataset.load(args.dataset)

    # Load test manifest to know which trajectories are in test split
    manifest_path = test_jsonl.parent / "test_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as f:
            test_manifest = json.load(f)
        test_ids = {item["trajectory_id"] for item in test_manifest}
        test_trajectories = [t for t in dataset.trajectories if t.trajectory_id in test_ids]
    else:
        # Fallback: load from JSONL (won't have Trajectory objects, just re-split)
        import random
        random.seed(42)
        _, _, test_trajectories = dataset.split(train_ratio=0.70, val_ratio=0.15)

    print(f"\nTest trajectories: {len(test_trajectories)}")
    n_deceptive = sum(1 for t in test_trajectories if t.is_deceptive)
    n_honest = len(test_trajectories) - n_deceptive
    print(f"  Honest: {n_honest}, Deceptive: {n_deceptive}")

    # Run evaluation
    print("\nRunning evaluation...")
    results = []
    latencies = []

    for i, trajectory in enumerate(test_trajectories):
        result = classifier.evaluate(trajectory)
        results.append({
            "trajectory_id": trajectory.trajectory_id,
            "ground_truth": trajectory.label.deception_type,
            "is_deceptive_gt": trajectory.is_deceptive,
            "predicted_block": not result["passed"],
            "predicted_type": result.get("deception_type", "none"),
            "confidence": result.get("confidence", 0.0),
            "latency_ms": result.get("latency_ms", 0.0),
        })
        latencies.append(result.get("latency_ms", 0.0))

        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(test_trajectories)}...")

    # Compute metrics
    tp = sum(1 for r in results if r["is_deceptive_gt"] and r["predicted_block"])
    fp = sum(1 for r in results if not r["is_deceptive_gt"] and r["predicted_block"])
    tn = sum(1 for r in results if not r["is_deceptive_gt"] and not r["predicted_block"])
    fn = sum(1 for r in results if r["is_deceptive_gt"] and not r["predicted_block"])

    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0  # Recall on deceptive
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * detection_rate / (precision + detection_rate) if (precision + detection_rate) > 0 else 0
    accuracy = (tp + tn) / len(results) if results else 0

    # Per deception type
    by_type = defaultdict(lambda: {"total": 0, "detected": 0})
    for r in results:
        gt = r["ground_truth"]
        if gt != "honest":
            by_type[gt]["total"] += 1
            if r["predicted_block"]:
                by_type[gt]["detected"] += 1

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Detection Rate (Recall): {detection_rate:.1%} ({tp}/{tp + fn})")
    print(f"  False Positive Rate:     {fpr:.2%} ({fp}/{fp + tn})")
    print(f"  Precision:               {precision:.1%}")
    print(f"  F1 Score:                {f1:.3f}")
    print(f"  Accuracy:                {accuracy:.1%}")
    print(f"  Avg Latency:             {sum(latencies) / len(latencies):.0f}ms")

    print("\nConfusion Matrix:")
    print(f"  TP: {tp}  FP: {fp}")
    print(f"  FN: {fn}  TN: {tn}")

    print("\nPer Deception Type:")
    for dtype, counts in sorted(by_type.items()):
        rate = counts["detected"] / counts["total"] if counts["total"] > 0 else 0
        print(f"  {dtype}: {rate:.1%} ({counts['detected']}/{counts['total']})")

    # GPT-5.2 comparison
    print("\n--- vs GPT-5.2 LLM Judge ---")
    print(f"  {'Metric':<25} {'Ours':>10} {'GPT-5.2':>10}")
    print(f"  {'Detection Rate':<25} {detection_rate:>9.1%} {'85.0%':>10}")
    print(f"  {'FPR':<25} {fpr:>9.2%} {'0.93%':>10}")
    print(f"  {'Precision':<25} {precision:>9.1%} {'97.7%':>10}")
    print(f"  {'F1':<25} {f1:>9.3f} {'0.909':>10}")
    print(f"  {'Avg Latency':<25} {sum(latencies) / len(latencies):>8.0f}ms {'~2000ms':>10}")

    # Save results
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    eval_results = {
        "model": args.model,
        "adapter": args.adapter_path,
        "metrics": {
            "detection_rate": detection_rate,
            "fpr": fpr,
            "precision": precision,
            "f1": f1,
            "accuracy": accuracy,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0,
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "by_deception_type": {
            dtype: {
                "detection_rate": counts["detected"] / counts["total"] if counts["total"] > 0 else 0,
                **counts,
            }
            for dtype, counts in by_type.items()
        },
        "per_trajectory": results,
    }

    results_path = output_dir / "classifier_eval.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(eval_results, f, indent=2)
    print(f"\nResults saved to: {results_path}")

    return eval_results


def main():
    parser = argparse.ArgumentParser(description="Train/evaluate trajectory classifier")

    # Mode
    parser.add_argument("--eval-only", action="store_true",
                        help="Skip training, only evaluate")

    # Data
    parser.add_argument("--train-data", default="data/classifier_splits/train.jsonl")
    parser.add_argument("--val-data", default="data/classifier_splits/val.jsonl")
    parser.add_argument("--test-data", default="data/classifier_splits/test.jsonl")
    parser.add_argument("--dataset", default="data/deceptive_comply_bench/dataset.json",
                        help="Full dataset (for evaluation with Trajectory objects)")

    # Model
    parser.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct",
                        help="Base model HuggingFace ID")
    parser.add_argument("--adapter-path", default=None,
                        help="Path to trained adapter (for eval or resuming)")

    # LoRA hyperparameters
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)

    # Training hyperparameters
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--grad-accum", type=int, default=4)
    parser.add_argument("--max-seq-length", type=int, default=2048)
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for training")
    parser.add_argument("--use-4bit", action="store_true", default=True,
                        help="Use 4-bit QLoRA (requires CUDA + bitsandbytes)")
    parser.add_argument("--no-4bit", action="store_false", dest="use_4bit")

    # Output
    parser.add_argument("--output-dir", default="models/trajectory_classifier")

    args = parser.parse_args()

    if args.eval_only:
        if not args.adapter_path:
            # Try default location
            default_adapter = Path(args.output_dir) / "final_adapter"
            if default_adapter.exists():
                args.adapter_path = str(default_adapter)
            else:
                parser.error("--adapter-path required for evaluation (or train first)")
        evaluate(args)
    else:
        adapter_path = train(args)
        print(f"\n{'=' * 60}")
        print("Training complete! Next steps:")
        print(f"  1. Evaluate: python -m trajectoryshield.trajectory_shield.train_classifier --eval-only --adapter-path {adapter_path}")
        print(f"  2. Download adapter (~50MB): scp -r runpod:{adapter_path} models/")
        print(f"{'=' * 60}")

        # Auto-evaluate if test data exists
        if os.path.exists(args.test_data) and os.path.exists(args.dataset):
            print("\nAuto-running evaluation on test set...")
            args.adapter_path = adapter_path
            args.output_dir = str(Path(args.output_dir) / "eval_results")
            evaluate(args)


if __name__ == "__main__":
    main()
