from __future__ import annotations
import os
import json
import math
import pickle
import random
import logging
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

logger = logging.getLogger(__name__)

def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed) 
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

@dataclass
class AgentConfig:
    state_size: int
    action_size: int
    model_dir: str = "core/ai_core/models"
    gamma: float = 0.99
    epsilon_start: float = 1.0
    epsilon_min: float = 0.01
    epsilon_decay: float = 0.999 
    learning_rate: float = 2.5e-4
    batch_size: int = 128
    memory_capacity: int = 50_000
    target_update_freq: int = 1_000 
    soft_update_tau: Optional[float] = None 
    grad_clip_norm: float = 1.0
    hidden_size: int = 256
    dropout: float = 0.2
    use_amp: bool = True 
    seed: int = 1337


class MLPDuelingDQN(nn.Module):
    def __init__(self, state_size: int, action_size: int, hidden_size: int = 256, dropout: float = 0.2):
        super().__init__()
        h2 = hidden_size
        h3 = max(hidden_size // 2, 64)
        
        self.trunk = nn.Sequential(
            nn.Linear(state_size, hidden_size),
            nn.LayerNorm(hidden_size),
            nn.SiLU(),
            nn.Dropout(dropout),

            nn.Linear(hidden_size, h2),
            nn.LayerNorm(h2),
            nn.SiLU(),
            nn.Dropout(dropout),

            nn.Linear(h2, h3),
            nn.LayerNorm(h3),
            nn.SiLU(),
        )

        self.value = nn.Sequential(
            nn.Linear(h3, h3),
            nn.SiLU(),
            nn.Linear(h3, 1),
        )
        self.advantage = nn.Sequential(
            nn.Linear(h3, h3),
            nn.SiLU(),
            nn.Linear(h3, action_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.trunk(x)
        v = self.value(z)          
        a = self.advantage(z)                  
        q = v + a - a.mean(dim=1, keepdim=True) 
        return q

class RLAgent:
    def __init__(self, state_size: int, action_size: int, model_dir: str = "core/ai_core/models") -> None:
        cfg = AgentConfig(state_size=state_size, action_size=action_size, model_dir=model_dir)
        self.cfg = cfg
        os.makedirs(self.cfg.model_dir, exist_ok=True)
        set_seed(self.cfg.seed)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"[RLAgent] device={self.device.type} amp={self.cfg.use_amp and self.device.type=='cuda'}")

        self.model = MLPDuelingDQN(cfg.state_size, cfg.action_size, cfg.hidden_size, cfg.dropout).to(self.device)
        self.target_model = MLPDuelingDQN(cfg.state_size, cfg.action_size, cfg.hidden_size, cfg.dropout).to(self.device)
        self.target_model.load_state_dict(self.model.state_dict())
        self.target_model.eval()
        self.optimizer = optim.Adam(self.model.parameters(), lr=cfg.learning_rate, weight_decay=1e-5)
        self.criterion = nn.SmoothL1Loss() 
        self.memory: Deque[Tuple[np.ndarray, int, float, np.ndarray, bool]] = deque(maxlen=cfg.memory_capacity)
        self.gamma = cfg.gamma
        self.epsilon = cfg.epsilon_start
        self.steps = 0
        self._scaler = torch.cuda.amp.GradScaler(enabled=self.cfg.use_amp and self.device.type == "cuda")
        self.ckpt_path = os.path.join(self.cfg.model_dir, "rl_agent_model.pth")
        self.memory_path = os.path.join(self.cfg.model_dir, "rl_memory.pkl")
        self._load_checkpoint()
        self._load_memory()

    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool) -> None:
        self.memory.append((state.astype(np.float32), int(action), float(reward), next_state.astype(np.float32), bool(done)))

    @torch.inference_mode()
    def act(self, state: np.ndarray, training: bool = True) -> int:
        if training and np.random.rand() <= self.epsilon:
            return random.randrange(self.cfg.action_size)
        s = torch.as_tensor(state, dtype=torch.float32, device=self.device).unsqueeze(0)
        q = self.model(s)  # [1, A]
        return int(q.argmax(dim=1).item())

    def replay(self) -> Optional[float]:
        if len(self.memory) < self.cfg.batch_size:
            return None

        batch = random.sample(self.memory, self.cfg.batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)

        states_t = torch.as_tensor(np.stack(states), dtype=torch.float32, device=self.device)
        actions_t = torch.as_tensor(actions, dtype=torch.long, device=self.device).unsqueeze(1) 
        rewards_t = torch.as_tensor(rewards, dtype=torch.float32, device=self.device)       
        next_states_t = torch.as_tensor(np.stack(next_states), dtype=torch.float32, device=self.device)
        dones_t = torch.as_tensor(dones, dtype=torch.bool, device=self.device)       
        q_pred = self.model(states_t).gather(1, actions_t).squeeze(1) 

        with torch.no_grad():
            next_q_online = self.model(next_states_t)                       
            next_actions = next_q_online.argmax(dim=1, keepdim=True)          
            next_q_target = self.target_model(next_states_t).gather(1, next_actions).squeeze(1) 
            not_done = (~dones_t).float()
            q_target = rewards_t + self.gamma * next_q_target * not_done

        loss: torch.Tensor
        self.optimizer.zero_grad(set_to_none=True)
        if self._scaler.is_enabled():
            with torch.cuda.amp.autocast():
                loss = self.criterion(q_pred, q_target)
            self._scaler.scale(loss).backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.grad_clip_norm)
            self._scaler.step(self.optimizer)
            self._scaler.update()
        else:
            loss = self.criterion(q_pred, q_target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.cfg.grad_clip_norm)
            self.optimizer.step()

        if self.epsilon > self.cfg.epsilon_min:
            self.epsilon = max(self.cfg.epsilon_min, self.epsilon * self.cfg.epsilon_decay)

        self.steps += 1
        if self.cfg.soft_update_tau:
            self._soft_update(self.cfg.soft_update_tau)
        elif self.steps % self.cfg.target_update_freq == 0:
            self.target_model.load_state_dict(self.model.state_dict())

        return float(loss.item())

    def get_stats(self) -> Dict[str, Any]:
        return {
            "epsilon": float(self.epsilon),
            "memory_size": int(len(self.memory)),
            "steps": int(self.steps),
            "device": self.device.type,
            "time": datetime.utcnow().isoformat() + "Z",
        }

    def save(self) -> None:
        try:
            meta = {
                "config": asdict(self.cfg),
                "epsilon": self.epsilon,
                "steps": self.steps,
                "rng": {
                    "python": random.getstate(),
                    "numpy": np.random.get_state(),
                    "torch": torch.get_rng_state(),
                    "torch_cuda": torch.cuda.get_rng_state_all() if torch.cuda.is_available() else [],
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            ckpt = {
                "model": self.model.state_dict(),
                "target_model": self.target_model.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "meta": meta,
            }
            torch.save(ckpt, self.ckpt_path)
            with open(self.memory_path, "wb") as f:
                pickle.dump(self.memory, f, protocol=pickle.HIGHEST_PROTOCOL)

            logger.info(f"[RLAgent] checkpoint saved -> {self.ckpt_path} (mem: {len(self.memory)})")
        except Exception as e:
            logger.error(f"[RLAgent] save failed: {e}")

    def save_model(self) -> None:
        self.save()

    def load_model(self) -> None:
        pass

    def _soft_update(self, tau: float) -> None:
        with torch.no_grad():
            for tp, p in zip(self.target_model.parameters(), self.model.parameters()):
                tp.data.lerp_(p.data, tau)

    def _load_checkpoint(self) -> None:
        if not os.path.exists(self.ckpt_path):
            return
        try:
            ckpt = torch.load(self.ckpt_path, map_location=self.device)
            self.model.load_state_dict(ckpt.get("model", {}))
            self.target_model.load_state_dict(ckpt.get("target_model", ckpt.get("model", {})))
            if "optimizer" in ckpt:
                self.optimizer.load_state_dict(ckpt["optimizer"])
            meta = ckpt.get("meta", {})
            self.epsilon = float(meta.get("epsilon", self.cfg.epsilon_start))
            self.steps = int(meta.get("steps", 0))
            rng = meta.get("rng", {})
            try:
                if "python" in rng:
                    random.setstate(rng["python"])
                if "numpy" in rng:
                    np.random.set_state(rng["numpy"])
                if "torch" in rng:
                    torch.set_rng_state(rng["torch"])
                if torch.cuda.is_available() and "torch_cuda" in rng and rng["torch_cuda"]:
                    for i, st in enumerate(rng["torch_cuda"]):
                        try:
                            torch.cuda.set_rng_state(st, device=i)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"[RLAgent] partial RNG restore: {e}")

            logger.info(f"[RLAgent] checkpoint loaded <- {self.ckpt_path}")
        except Exception as e:
            logger.error(f"[RLAgent] load failed: {e}")

    def _load_memory(self) -> None:
        if not os.path.exists(self.memory_path):
            return
        try:
            with open(self.memory_path, "rb") as f:
                mem = pickle.load(f)
            if isinstance(mem, deque):
                self.memory = mem
            elif isinstance(mem, list):
                self.memory = deque(mem, maxlen=self.cfg.memory_capacity)
            logger.info(f"[RLAgent] replay buffer loaded ({len(self.memory)} items)")
        except Exception as e:
            logger.error(f"[RLAgent] memory load failed: {e}")

class BypassEnvironment:

    def __init__(self, target_profile: Dict[str, Any]) -> None:
        self.target_profile = target_profile or {}
        self.state_size = 32
        self._backend_vocab = ['nginx', 'apache', 'iis', 'node', 'flask', 'spring', 'django', 'rails']
        self._waf_vocab = ['cloudflare', 'akamai', 'aws', 'imperva', 'f5', 'modsecurity']
        self.action_space = self._initialize_action_space()

    def _initialize_action_space(self) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        for intensity in [0.1, 0.3, 0.5, 0.7, 0.9]:
            actions.append({"type": "path_trim", "intensity": float(intensity)})
        for header in ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "Referer"]:
            actions.append({"type": "header_injection", "header": header})

        for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]:
            actions.append({"type": "method_override", "method": method})

        for protocol in ["HTTP/0.9", "chunked_encoding", "line_folding"]:
            actions.append({"type": "protocol_attack", "protocol": protocol})

        return actions

    def get_state(self, response_history: List[Dict[str, Any]], target_info: Dict[str, Any]) -> np.ndarray:
        state = np.zeros(self.state_size, dtype=np.float32)
        if not response_history:
            state[0] = 1.0
            return state

        last = response_history[-1]
        state[0] = float(last.get("status_code", 0)) / 500.0
        state[1] = min(float(last.get("response_size", 0)) / 10_000.0, 1.0)
        state[2] = min(float(last.get("response_time", 0)) / 10.0, 1.0)
        state[3] = 1.0 if target_info.get("waf_detected") else 0.0
        backend = (target_info.get("backend") or "unknown").lower()
        base_idx = 4
        for i, b in enumerate(self._backend_vocab):
            if b in backend:
                state[base_idx + i] = 1.0

        waf = (target_info.get("waf_type") or "").lower()
        waf_idx = 12
        for i, w in enumerate(self._waf_vocab):
            if w in waf:
                state[waf_idx + i] = 1.0
        recent = response_history[-5:] if len(response_history) > 5 else response_history
        if recent:
            succ = sum(1 for r in recent if 200 <= int(r.get("status_code", 0)) < 300)
            err5 = sum(1 for r in recent if int(r.get("status_code", 0)) >= 500)
            state[18] = succ / len(recent)
            state[19] = err5 / len(recent)

            action_types = ['path_trim', 'header_injection', 'method_override', 'protocol_attack']
            for i, at in enumerate(action_types):
                cnt = sum(1 for r in recent if r.get("action_type") == at)
                state[20 + i] = cnt / len(recent)

        return state

    def calculate_reward(self, response: Dict[str, Any], previous_response: Optional[Dict[str, Any]] = None) -> float:
        reward = 0.0
        sc = int(response.get("status_code", 0))
        url = response.get("url", "") or ""
        if 200 <= sc < 300:
            reward += 10.0
            if any(p in url for p in ("/admin", "/api", "/config", "/internal", "/secure", "/private")):
                reward += 5.0
        elif sc not in (401, 403, 404, 500, 502, 503):
            reward += 3.0

        if previous_response:
            prev_sz = int(previous_response.get("response_size", 0))
            cur_sz = int(response.get("response_size", 0))
            if cur_sz > 0 and prev_sz >= 0 and cur_sz != prev_sz:
                ratio = abs(cur_sz - prev_sz) / max(prev_sz, 1)
                reward += min(ratio * 2.0, 2.0)

        if sc >= 500:
            reward -= 3.0
        if response.get("error"):
            reward -= 5.0
        if sc in (401, 403) and previous_response and int(previous_response.get("status_code", 0)) in (401, 403):
            reward -= 0.5

        return float(reward)
