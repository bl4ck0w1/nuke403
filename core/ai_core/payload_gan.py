from __future__ import annotations
import os
import math
import json
import random
import logging
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
logger = logging.getLogger(__name__)

def set_seed(seed: int = 1337) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed) 
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

DEFAULT_CHARS = (
    list("abcdefghijklmnopqrstuvwxyz")
    + list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    + list("0123456789")
    + list("-._~:/?#[]@!$&'()*+,;=%") 
    + ["\\"]  
)

SPECIAL_TOKENS = ["<pad>", "<bos>", "<eos>"]

class PayloadVocab:
    def __init__(self, extra_tokens: Optional[List[str]] = None) -> None:
        charset = list(dict.fromkeys(DEFAULT_CHARS + (extra_tokens or []))) 
        self.tokens = SPECIAL_TOKENS + charset
        self.stoi = {t: i for i, t in enumerate(self.tokens)}
        self.itos = {i: t for t, i in self.stoi.items()}
        self.pad_id = self.stoi["<pad>"]
        self.bos_id = self.stoi["<bos>"]
        self.eos_id = self.stoi["<eos>"]

    def encode(self, s: str, add_special: bool = True, max_len: int = 96) -> List[int]:
        ids = [self.bos_id] if add_special else []
        for ch in s:
            ids.append(self.stoi.get(ch, self.stoi["-"])) 
            if len(ids) >= max_len - 1: 
                break
        if add_special:
            ids.append(self.eos_id)
        return ids

    def decode(self, ids: Iterable[int]) -> str:
        return "".join(self.itos.get(i, "") for i in ids if i not in (self.pad_id, self.bos_id, self.eos_id))

class GRUGenerator(nn.Module):
    def __init__(self, vocab_size: int, emb: int = 128, hid: int = 256, num_layers: int = 2):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, emb, padding_idx=0)
        self.gru = nn.GRU(emb, hid, num_layers=num_layers, batch_first=True)
        self.proj = nn.Linear(hid, vocab_size)

    def forward(self, x: torch.Tensor, h: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        e = self.emb(x)
        out, h = self.gru(e, h)
        logits = self.proj(out)  
        return logits, h

    def step(self, x_t: torch.Tensor, h: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        e = self.emb(x_t).unsqueeze(1)
        out, h = self.gru(e, h)
        logits = self.proj(out.squeeze(1))  
        return logits, h


class TextCNNDiscriminator(nn.Module):
    def __init__(self, vocab_size: int, num_classes: int = 2, emb: int = 128, channels: int = 128):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, emb, padding_idx=0)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, channels, k) for k in (3, 4, 5)]
        )
        self.dropout = nn.Dropout(0.2)
        self.out = nn.Linear(channels * len(self.convs), num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        e = self.emb(x).transpose(1, 2) 
        feats = []
        for conv in self.convs:
            c = F.relu(conv(e))
            p = F.max_pool1d(c, kernel_size=c.size(2)).squeeze(2)
            feats.append(p)
        h = torch.cat(feats, dim=1)
        h = self.dropout(h)
        return self.out(h)  

@dataclass
class PayloadGANConfig:
    model_dir: str = "core/ai_core/models/payload_gan"
    max_len: int = 96
    seed: int = 1337
    gen_emb: int = 128
    gen_hid: int = 256
    gen_layers: int = 2
    dis_emb: int = 128
    dis_channels: int = 128
    lr_gen: float = 2e-4
    lr_dis: float = 1e-4
    clip_norm: float = 1.0
    top_k: int = 50
    top_p: float = 0.95
    temperature: float = 1.0
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


def apply_persona_bias(logits: torch.Tensor, vocab: PayloadVocab, persona: Dict[str, str]) -> torch.Tensor:

    waf = (persona.get("waf") or "").lower()
    be = (persona.get("backend") or "").lower()

    def boost(token: str, val: float):
        tid = vocab.stoi.get(token)
        if tid is not None:
            logits[..., tid] += val

    if "spring" in be:
        boost(";", 0.8) 
        boost("%", 0.3)
        boost("/", 0.2)
    if "node" in be:
        boost("\\", 0.5)
        boost("%", 0.4)
        boost(";", 0.2)
    if "flask" in be or "python" in be:
        boost("%", 0.4)
        boost(".", 0.2)
    if "iis" in be or "windows" in be:
        boost("\\", 0.8)

    if "cloudflare" in waf:
        boost("%", 0.4)  
        boost("?", 0.2)
    if "akamai" in waf:
        boost(";", 0.3)
        boost("%", 0.2)
    if "aws" in waf:
        boost("%", 0.3)
        boost("@", 0.2)  

    return logits


def top_k_top_p_filtering(logits: torch.Tensor, top_k: int = 0, top_p: float = 1.0) -> torch.Tensor:
    if top_k > 0:
        kth_vals, _ = torch.topk(logits, min(top_k, logits.size(-1)))
        thresh = kth_vals[..., -1, None]
        logits = torch.where(logits < thresh, torch.full_like(logits, -1e10), logits)

    if 0 < top_p < 1.0:
        sorted_logits, sorted_indices = torch.sort(logits, descending=True)
        probs = F.softmax(sorted_logits, dim=-1)
        cumprobs = torch.cumsum(probs, dim=-1)
        mask = cumprobs > top_p
        mask[..., 1:] = mask[..., :-1].clone()
        mask[..., 0] = False
        sorted_logits = torch.where(mask, torch.full_like(sorted_logits, -1e10), sorted_logits)
        logits = torch.full_like(logits, -1e10)
        logits.scatter_(dim=-1, index=sorted_indices, src=sorted_logits)
    return logits


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[-1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def diverse_append(pool: List[str], cand: str, min_edit: int = 6) -> None:
    for p in pool:
        if levenshtein(p, cand) < min_edit:
            return
    pool.append(cand)

class PayloadGAN:
    def __init__(self, cfg: Optional[PayloadGANConfig] = None, vocab: Optional[PayloadVocab] = None) -> None:
        self.cfg = cfg or PayloadGANConfig()
        set_seed(self.cfg.seed)

        self.vocab = vocab or PayloadVocab()
        V = len(self.vocab.tokens)

        self.device = torch.device(self.cfg.device)
        self.gen = GRUGenerator(V, self.cfg.gen_emb, self.cfg.gen_hid, self.cfg.gen_layers).to(self.device)
        self.dis = TextCNNDiscriminator(V, 2, self.cfg.dis_emb, self.cfg.dis_channels).to(self.device)

        self.opt_g = torch.optim.Adam(self.gen.parameters(), lr=self.cfg.lr_gen, betas=(0.5, 0.999))
        self.opt_d = torch.optim.Adam(self.dis.parameters(), lr=self.cfg.lr_dis)

        self.ckpt_dir = self.cfg.model_dir
        os.makedirs(self.ckpt_dir, exist_ok=True)
        self._maybe_load()

    def _ckpt_paths(self) -> Dict[str, str]:
        return {
            "gen": os.path.join(self.ckpt_dir, "generator.pt"),
            "dis": os.path.join(self.ckpt_dir, "discriminator.pt"),
            "cfg": os.path.join(self.ckpt_dir, "config.json"),
            "vocab": os.path.join(self.ckpt_dir, "vocab.json"),
        }

    def _maybe_load(self) -> None:
        paths = self._ckpt_paths()
        try:
            if os.path.exists(paths["gen"]):
                self.gen.load_state_dict(torch.load(paths["gen"], map_location=self.device))
            if os.path.exists(paths["dis"]):
                self.dis.load_state_dict(torch.load(paths["dis"], map_location=self.device))
            if os.path.exists(paths["cfg"]):
                with open(paths["cfg"], "r", encoding="utf-8") as f:
                    disk_cfg = json.load(f)
                for k, v in disk_cfg.items():
                    if hasattr(self.cfg, k) and k != "device":
                        setattr(self.cfg, k, v)
            if os.path.exists(paths["vocab"]):
                with open(paths["vocab"], "r", encoding="utf-8") as f:
                    data = json.load(f)
                logger.info(f"[PayloadGAN] loaded vocab snapshot with {len(data.get('tokens', []))} tokens")
            logger.info("[PayloadGAN] models loaded (if present)")
        except Exception as e:
            logger.warning(f"[PayloadGAN] failed to load checkpoints: {e}")

    def save(self) -> None:
        paths = self._ckpt_paths()
        torch.save(self.gen.state_dict(), paths["gen"])
        torch.save(self.dis.state_dict(), paths["dis"])
        with open(paths["cfg"], "w", encoding="utf-8") as f:
            json.dump(asdict(self.cfg), f, indent=2)
        with open(paths["vocab"], "w", encoding="utf-8") as f:
            json.dump({"tokens": self.vocab.tokens}, f, indent=2)
        logger.info(f"[PayloadGAN] saved models → {self.ckpt_dir}")

    @torch.no_grad()
    def generate(
        self,
        n: int = 32,
        persona: Optional[Dict[str, str]] = None,
        min_len: int = 4,
        max_len: Optional[int] = None,
        temperature: Optional[float] = None,
        top_k: Optional[int] = None,
        top_p: Optional[float] = None,
    ) -> List[str]:
        self.gen.eval()
        V = len(self.vocab.tokens)
        max_len = max_len or self.cfg.max_len
        temp = max(temperature or self.cfg.temperature, 1e-6)
        k = top_k if top_k is not None else self.cfg.top_k
        p = top_p if top_p is not None else self.cfg.top_p

        batch = 64 
        out: List[str] = []
        tried = 0
        while len(out) < n and tried < n * 8:
            B = min(batch, (n - len(out)) * 4)
            x_t = torch.full((B,), self.vocab.bos_id, dtype=torch.long, device=self.device)
            h = None
            seqs: List[List[int]] = [[] for _ in range(B)]
            finished = [False] * B

            for _ in range(max_len):
                logits, h = self.gen.step(x_t, h) 
                logits = logits / temp
                if persona:
                    logits = apply_persona_bias(logits, self.vocab, persona)

                logits = top_k_top_p_filtering(logits, top_k=k, top_p=p)
                probs = F.softmax(logits, dim=-1)
                x_t = torch.multinomial(probs, num_samples=1).squeeze(1) 

                for i, token_id in enumerate(x_t.tolist()):
                    if not finished[i]:
                        if token_id == self.vocab.eos_id:
                            finished[i] = True
                        else:
                            seqs[i].append(token_id)

                if all(finished):
                    break

            for s in seqs:
                txt = self.vocab.decode(s)
                if self._is_valid_candidate(txt, min_len=min_len):
                    diverse_append(out, txt, min_edit=6)
                    if len(out) >= n:
                        break
            tried += B

        return out

    def _is_valid_candidate(self, s: str, min_len: int = 4) -> bool:
        if len(s) < min_len:
            return False
        if any(ord(c) < 0x20 and c not in ("\t", "\n", "\r") for c in s):
            return False
        trivial = ("aaaa", "////", ";;;;", "----", "%%%%")
        if any(t in s for t in trivial):
            return False
        if not any(c in s for c in ("%", "/", ";", "?", "=", "\\")):
            return False
        return True

    def update_from_feedback(self, feedback: List[Tuple[str, bool]], epochs: int = 1) -> Dict[str, Any]:
        self.gen.train()
        self.dis.train()

        pos = [p for p, ok in feedback if ok]
        neg = [p for p, ok in feedback if not ok]
        if not pos and not neg:
            return {"updated": False}

        pad_id = self.vocab.pad_id
        max_len = min(self.cfg.max_len, max((len(p) for p in pos + neg), default=8) + 2)

        def batchify(strings: List[str]) -> Tuple[torch.Tensor, torch.Tensor]:
            if not strings:
                return torch.empty(0, dtype=torch.long), torch.empty(0, dtype=torch.long)
            toks = [self.vocab.encode(s, add_special=True, max_len=max_len) for s in strings]
            T = max(len(t) for t in toks)
            x = np.full((len(toks), T), pad_id, dtype=np.int64)
            y = np.full((len(toks), T), pad_id, dtype=np.int64)
            for i, t in enumerate(toks):
                x[i, : len(t) - 1] = t[:-1]
                y[i, : len(t) - 1] = t[1:]
            return torch.from_numpy(x).to(self.device), torch.from_numpy(y).to(self.device)

        x_pos, y_pos = batchify(pos)
        x_neg, _ = batchify(neg)

        stats = {"gen_loss": None, "dis_loss": None, "pos": len(pos), "neg": len(neg)}

        for _ in range(epochs):
            if x_pos.numel() > 0:
                self.opt_g.zero_grad()
                logits, _ = self.gen(x_pos)
                loss = F.cross_entropy(logits.view(-1, logits.size(-1)), y_pos.view(-1), ignore_index=pad_id)
                loss.backward()
                nn.utils.clip_grad_norm_(self.gen.parameters(), self.cfg.clip_norm)
                self.opt_g.step()
                stats["gen_loss"] = float(loss.item())

            if x_pos.numel() > 0 or x_neg.numel() > 0:
                self.opt_d.zero_grad()
                xs = []
                ys = []
                if x_pos.numel() > 0:
                    xs.append(x_pos)
                    ys.append(torch.ones(x_pos.size(0), dtype=torch.long, device=self.device))  
                if x_neg.numel() > 0:
                    xs.append(x_neg)
                    ys.append(torch.zeros(x_neg.size(0), dtype=torch.long, device=self.device)) 
                X = torch.cat(xs, dim=0) if xs else None
                Y = torch.cat(ys, dim=0) if ys else None
                if X is not None:
                    logits_d = self.dis(X)
                    loss_d = F.cross_entropy(logits_d, Y)
                    loss_d.backward()
                    nn.utils.clip_grad_norm_(self.dis.parameters(), self.cfg.clip_norm)
                    self.opt_d.step()
                    stats["dis_loss"] = float(loss_d.item())

        self.save()
        return stats

    def train_supervised(self, positives: List[str], negatives: Optional[List[str]] = None, epochs: int = 3, batch_size: int = 64) -> Dict[str, Any]:
        self.gen.train()
        self.dis.train()

        pad_id = self.vocab.pad_id
        max_len = min(self.cfg.max_len, max((len(p) for p in positives + (negatives or [])), default=16) + 2)

        def make_batches(data: List[str]) -> List[Tuple[torch.Tensor, torch.Tensor]]:
            out = []
            for i in range(0, len(data), batch_size):
                batch = data[i : i + batch_size]
                toks = [self.vocab.encode(s, add_special=True, max_len=max_len) for s in batch]
                T = max(len(t) for t in toks)
                x = np.full((len(toks), T), pad_id, dtype=np.int64)
                y = np.full((len(toks), T), pad_id, dtype=np.int64)
                for bi, t in enumerate(toks):
                    x[bi, : len(t) - 1] = t[:-1]
                    y[bi, : len(t) - 1] = t[1:]
                out.append(
                    (torch.from_numpy(x).to(self.device), torch.from_numpy(y).to(self.device))
                )
            return out

        pos_batches = make_batches(positives)
        neg_batches = make_batches(negatives or [])
        
        for ep in range(epochs):
            g_losses = []
            for x, y in pos_batches:
                self.opt_g.zero_grad()
                logits, _ = self.gen(x)
                loss = F.cross_entropy(logits.view(-1, logits.size(-1)), y.view(-1), ignore_index=pad_id)
                loss.backward()
                nn.utils.clip_grad_norm_(self.gen.parameters(), self.cfg.clip_norm)
                self.opt_g.step()
                g_losses.append(loss.item())
            logger.info(f"[PayloadGAN][sup] epoch {ep+1}/{epochs} gen_loss={np.mean(g_losses):.4f}")

            if neg_batches:
                d_losses = []
                for (x_pos, _), (x_neg, _) in zip(pos_batches, neg_batches[: len(pos_batches)]):
                    self.opt_d.zero_grad()
                    xs = torch.cat([x_pos, x_neg], dim=0)
                    ys = torch.cat(
                        [
                            torch.ones(x_pos.size(0), dtype=torch.long, device=self.device),
                            torch.zeros(x_neg.size(0), dtype=torch.long, device=self.device),
                        ],
                        dim=0,
                    )
                    logits_d = self.dis(xs)
                    loss_d = F.cross_entropy(logits_d, ys)
                    loss_d.backward()
                    nn.utils.clip_grad_norm_(self.dis.parameters(), self.cfg.clip_norm)
                    self.opt_d.step()
                    d_losses.append(loss_d.item())
                logger.info(f"[PayloadGAN][sup] epoch {ep+1}/{epochs} dis_loss={np.mean(d_losses):.4f}")

        self.save()
        return {"done": True}

    def train_gan(self, positives: List[str], steps: int = 500, batch_size: int = 64, adv_weight: float = 0.3) -> Dict[str, Any]:
        self.gen.train()
        self.dis.train()

        pad_id = self.vocab.pad_id
        max_len = min(self.cfg.max_len, max((len(p) for p in positives), default=16) + 2)

        def tf_batch(batch: List[str]) -> Tuple[torch.Tensor, torch.Tensor]:
            toks = [self.vocab.encode(s, add_special=True, max_len=max_len) for s in batch]
            T = max(len(t) for t in toks)
            x = np.full((len(toks), T), pad_id, dtype=np.int64)
            y = np.full((len(toks), T), pad_id, dtype=np.int64)
            for bi, t in enumerate(toks):
                x[bi, : len(t) - 1] = t[:-1]
                y[bi, : len(t) - 1] = t[1:]
            return torch.from_numpy(x).to(self.device), torch.from_numpy(y).to(self.device)

        for step in range(1, steps + 1):
            batch = random.sample(positives, k=min(batch_size, len(positives)))
            x, y = tf_batch(batch)
            self.opt_g.zero_grad()
            logits, _ = self.gen(x)
            mle = F.cross_entropy(logits.view(-1, logits.size(-1)), y.view(-1), ignore_index=pad_id)
            
            with torch.no_grad():
                samples = self.generate(n=len(batch), min_len=4)
            if samples:
                xs, _ = tf_batch(samples)
                logits_d_fake = self.dis(xs)
                fake_scores = F.log_softmax(logits_d_fake, dim=-1)[:, 1]  
                adv_loss = -adv_weight * fake_scores.mean()
            else:
                adv_loss = torch.tensor(0.0, device=self.device)

            loss = mle + adv_loss
            loss.backward()
            nn.utils.clip_grad_norm_(self.gen.parameters(), self.cfg.clip_norm)
            self.opt_g.step()

            if step % 5 == 0:
                self.opt_d.zero_grad()
                xr, _ = tf_batch(random.sample(positives, k=min(batch_size, len(positives))))
                logits_r = self.dis(xr)
                yr = torch.ones(xr.size(0), dtype=torch.long, device=self.device)
                loss_r = F.cross_entropy(logits_r, yr)
                fakes = self.generate(n=xr.size(0), min_len=4)
                if fakes:
                    xf, _ = tf_batch(fakes)
                    logits_f = self.dis(xf)
                    yf = torch.zeros(xf.size(0), dtype=torch.long, device=self.device)
                    loss_f = F.cross_entropy(logits_f, yf)
                else:
                    loss_f = torch.tensor(0.0, device=self.device)
                dloss = loss_r + loss_f
                dloss.backward()
                nn.utils.clip_grad_norm_(self.dis.parameters(), self.cfg.clip_norm)
                self.opt_d.step()

            if step % 50 == 0:
                logger.info(f"[PayloadGAN][gan] step {step}/{steps} mle={float(mle):.4f} adv={float(adv_loss):.4f}")

        self.save()
        return {"done": True}
