from __future__ import annotations
import os
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from transformers import (AutoConfig, AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments,)

logger = logging.getLogger(__name__)

def set_seed(seed: int = 42) -> None:
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed) 
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


@dataclass
class BertPredictorConfig:
    model_dir: str = "core/ai_core/models/bert_model"
    base_model: str = "bert-base-uncased" 
    labels: Tuple[str, ...] = ("blocked", "bypass_possible", "error", "success")
    max_length: int = 256
    seed: int = 42
    temperature: float = 1.0
    epochs: int = 3
    batch_size: int = 16
    weight_decay: float = 0.01
    warmup_steps: int = 500
    learning_rate: float = 5e-5
    fp16: Optional[bool] = None 

class HTTPResponseDataset(torch.utils.data.Dataset):
    def __init__(self, encodings: Dict[str, List[int]], labels: List[int]) -> None:
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx])
        return item

    def __len__(self) -> int:
        return len(self.labels)


class BERTPredictor:

    def __init__(self, model_dir: str = "core/ai_core/models/bert_model", config: Optional[BertPredictorConfig] = None):
        self.cfg = config or BertPredictorConfig(model_dir=model_dir)
        self.model_dir = self.cfg.model_dir
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        set_seed(self.cfg.seed)
        self.labels: List[str] = list(self.cfg.labels)
        self.id2label: Dict[int, str] = {i: label for i, label in enumerate(self.labels)}
        self.label2id: Dict[str, int] = {label: i for i, label in enumerate(self.labels)}
        self.tokenizer = None
        self.model = None

        self._load_or_init_model()

    def _load_or_init_model(self) -> None:
        try:
            local_ok = os.path.isdir(self.model_dir) and any(
                os.path.isfile(os.path.join(self.model_dir, f)) for f in ("config.json", "pytorch_model.bin")
            )

            load_source = self.model_dir if local_ok else self.cfg.base_model
            self.tokenizer = AutoTokenizer.from_pretrained(load_source)
            config = AutoConfig.from_pretrained(load_source)
            config.num_labels = len(self.labels)
            config.id2label = self.id2label
            config.label2id = self.label2id
            self.model = AutoModelForSequenceClassification.from_pretrained(load_source, config=config)
            self.model.to(self.device)
            self.model.eval()
            
            calib_path = os.path.join(self.model_dir, "calibration.json")
            if os.path.exists(calib_path):
                with open(calib_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                t = float(data.get("temperature", 1.0))
                if t > 0:
                    self.cfg.temperature = t

            logger.info(
                f"[BERTPredictor] Loaded model from {'local dir' if local_ok else self.cfg.base_model}, "
                f"device={self.device}, temperature={self.cfg.temperature}"
            )
        except Exception as e:
            logger.error(f"[BERTPredictor] failed to load model/tokenizer: {e}")
            raise

    @staticmethod
    def _normalize_headers(headers: Any) -> Dict[str, str]:
        try:
            return {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        except Exception:
            return {}

    def preprocess_response(self, response: Dict[str, Any], *, body_max: int = 200) -> str:
        parts: List[str] = []
        sc = int(response.get("status_code", 0))
        parts.append(f"status: {sc}")

        headers = self._normalize_headers(response.get("headers"))
        relevant_keys = [
            "server",
            "x-powered-by",
            "via",
            "x-cache",
            "content-type",
            "www-authenticate",
            "x-frame-options",
            "content-security-policy",
            "cf-ray",
            "x-akamai-transformed",
            "x-aws-waf",
        ]
        for k in relevant_keys:
            if k in headers:
                parts.append(f"{k}: {headers[k]}")
                
        url = str(response.get("url", ""))[:128]
        if url:
            parts.append(f"url: {url}")
        body = response.get("body", "")
        if not isinstance(body, str):
            try:
                body = str(body)
            except Exception:
                body = ""
        body = " ".join(body.split())
        parts.append(f"body: {body[:body_max]}")

        return " ".join(parts)

    @torch.inference_mode()
    def predict(self, response: Dict[str, Any]) -> Tuple[str, float]:
        try:
            text = self.preprocess_response(response)
            enc = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=self.cfg.max_length,
            )
            enc = {k: v.to(self.device) for k, v in enc.items()}

            out = self.model(**enc)
            logits = out.logits / max(self.cfg.temperature, 1e-6)
            probs = torch.softmax(logits, dim=-1).squeeze(0) 
            idx = int(torch.argmax(probs).item())
            conf = float(probs[idx].item())
            return self.id2label[idx], conf
        except Exception as e:
            logger.error(f"[BERTPredictor] prediction failed: {e}")
            return self.fallback_prediction(response)

    @torch.inference_mode()
    def predict_topk(self, response: Dict[str, Any], k: int = 3) -> List[Tuple[str, float]]:
        try:
            text = self.preprocess_response(response)
            enc = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=self.cfg.max_length,
            )
            enc = {k: v.to(self.device) for k, v in enc.items()}
            out = self.model(**enc)
            logits = out.logits / max(self.cfg.temperature, 1e-6)
            probs = torch.softmax(logits, dim=-1).squeeze(0).cpu().numpy()
            order = np.argsort(-probs)[:max(1, min(k, len(probs)))]
            return [(self.id2label[int(i)], float(probs[int(i)])) for i in order]
        except Exception as e:
            logger.error(f"[BERTPredictor] top-k prediction failed: {e}")
            label, conf = self.fallback_prediction(response)
            return [(label, conf)]

    def fallback_prediction(self, response: Dict[str, Any]) -> Tuple[str, float]:
        try:
            sc = int(response.get("status_code", 0))
        except Exception:
            sc = 0

        headers = self._normalize_headers(response.get("headers"))
        body = (response.get("body", "") or "")
        if not isinstance(body, str):
            body = str(body)
        body_l = body.lower()

        if 200 <= sc < 300:
            return "success", 0.85

        if sc in (401, 403):
            waf_markers = (
                "cloudflare" in body_l or "cloudflare" in str(headers),
                "waf" in body_l or "x-aws-waf" in headers or "awselb" in str(headers),
                "akamai" in body_l or "x-akamai" in str(headers),
                "access denied" in body_l,
                "forbidden" in body_l,
            )
            backend_hints = any(x in (body_l + " " + str(headers)) for x in ("nginx", "apache", "spring", "express"))
            if any(waf_markers) and not backend_hints:
                return "blocked", 0.80
            if backend_hints:
                return "bypass_possible", 0.60
            return "blocked", 0.70

        if sc >= 500:
            return "error", 0.90
        return "blocked", 0.60

    def train(self, dataset_path: str, epochs: Optional[int] = None, batch_size: Optional[int] = None) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(dataset_path):
                logger.error(f"[BERTPredictor] dataset not found: {dataset_path}")
                return None

            df = pd.read_csv(dataset_path)
            if "text" not in df.columns or "label" not in df.columns:
                logger.error("[BERTPredictor] dataset must contain 'text' and 'label' columns")
                return None

            texts = df["text"].astype(str).tolist()
            labels_text = df["label"].astype(str).tolist()
            y = [self.label2id.get(lbl, self.label2id["blocked"]) for lbl in labels_text]

            X_train, X_val, y_train, y_val = train_test_split(
                texts, y, test_size=0.2, random_state=self.cfg.seed, stratify=y if len(set(y)) > 1 else None
            )
            
            train_enc = self.tokenizer(X_train, truncation=True, padding=True, max_length=self.cfg.max_length)
            val_enc = self.tokenizer(X_val, truncation=True, padding=True, max_length=self.cfg.max_length)
            train_ds = HTTPResponseDataset(train_enc, y_train)
            val_ds = HTTPResponseDataset(val_enc, y_val)

            fp16 = (torch.cuda.is_available() if self.cfg.fp16 is None else bool(self.cfg.fp16))
            args = TrainingArguments(
                output_dir=os.path.join(self.model_dir, "training"),
                num_train_epochs=epochs or self.cfg.epochs,
                per_device_train_batch_size=batch_size or self.cfg.batch_size,
                per_device_eval_batch_size=batch_size or self.cfg.batch_size,
                learning_rate=self.cfg.learning_rate,
                warmup_steps=self.cfg.warmup_steps,
                weight_decay=self.cfg.weight_decay,
                logging_dir=os.path.join(self.model_dir, "logs"),
                logging_steps=25,
                evaluation_strategy="epoch",
                save_strategy="epoch",
                save_total_limit=2,
                load_best_model_at_end=True,
                metric_for_best_model="f1",
                greater_is_better=True,
                seed=self.cfg.seed,
                fp16=fp16,
            )

            def compute_metrics(pred) -> Dict[str, float]:
                labels = pred.label_ids
                preds = pred.predictions.argmax(-1)
                precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="weighted", zero_division=0)
                acc = accuracy_score(labels, preds)
                return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}

            trainer = Trainer(
                model=self.model,
                args=args,
                train_dataset=train_ds,
                eval_dataset=val_ds,
                compute_metrics=compute_metrics,
                tokenizer=self.tokenizer,
            )

            set_seed(self.cfg.seed)
            trainer.train()
            os.makedirs(self.model_dir, exist_ok=True)
            self.model.save_pretrained(self.model_dir)
            self.tokenizer.save_pretrained(self.model_dir)
            eval_metrics = trainer.evaluate()
            metrics_path = os.path.join(self.model_dir, "metrics.json")
            with open(metrics_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "metrics": eval_metrics,
                        "config": asdict(self.cfg),
                    },
                    f,
                    indent=2,
                )

            calib_path = os.path.join(self.model_dir, "calibration.json")
            if not os.path.exists(calib_path):
                with open(calib_path, "w", encoding="utf-8") as f:
                    json.dump({"temperature": self.cfg.temperature}, f, indent=2)

            logger.info(f"[BERTPredictor] fine-tune complete. Metrics -> {metrics_path}")
            return {"metrics": eval_metrics, "metrics_path": metrics_path}

        except Exception as e:
            logger.error(f"[BERTPredictor] training failed: {e}")
            raise

    def prepare_dataset(self, responses: List[Dict[str, Any]], labels: List[str], output_path: str) -> None:
        try:
            rows = []
            for resp, lab in zip(responses, labels):
                rows.append({"text": self.preprocess_response(resp), "label": str(lab)})
            df = pd.DataFrame(rows)
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            df.to_csv(output_path, index=False)
            logger.info(f"[BERTPredictor] dataset saved -> {output_path} (rows={len(df)})")
        except Exception as e:
            logger.error(f"[BERTPredictor] dataset preparation failed: {e}")
            raise
