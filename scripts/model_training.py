import argparse
import logging
import json
import os
import sys
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ai_core.bert_predictor import BERTPredictor
from core.ai_core.rl_agent import RLAgent, BypassEnvironment
from core.ai_core.payload_gan import PayloadGAN

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("training.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_training_data(data_dir: str) -> Dict:
    training_data = {
        'bert_responses': [],
        'bert_labels': [],
        'gan_payloads': [],
        'rl_experiences': []
    }
    
    try:
        bert_data_path = os.path.join(data_dir, 'bert_training_data.json')
        if os.path.exists(bert_data_path):
            with open(bert_data_path, 'r') as f:
                bert_data = json.load(f)
                training_data['bert_responses'] = bert_data.get('responses', [])
                training_data['bert_labels'] = bert_data.get('labels', [])
            
            logger.info(f"Loaded {len(training_data['bert_responses'])} BERT training samples")
        
        gan_data_path = os.path.join(data_dir, 'gan_training_data.json')
        if os.path.exists(gan_data_path):
            with open(gan_data_path, 'r') as f:
                gan_data = json.load(f)
                training_data['gan_payloads'] = gan_data.get('payloads', [])
            
            logger.info(f"Loaded {len(training_data['gan_payloads'])} GAN training samples")
        
        rl_data_path = os.path.join(data_dir, 'rl_training_data.json')
        if os.path.exists(rl_data_path):
            with open(rl_data_path, 'r') as f:
                rl_data = json.load(f)
                training_data['rl_experiences'] = rl_data.get('experiences', [])
            
            logger.info(f"Loaded {len(training_data['rl_experiences'])} RL training experiences")
        
        return training_data
        
    except Exception as e:
        logger.error(f"Failed to load training data: {e}")
        return training_data

def prepare_bert_dataset(responses: List[Dict], labels: List[str], output_path: str) -> bool:
    try:
        bert_predictor = BERTPredictor()
        processed_texts = []
        for response in responses:
            text = bert_predictor.preprocess_response(response)
            processed_texts.append(text)
    
        df = pd.DataFrame({
            'text': processed_texts,
            'label': labels
        })
        
        df.to_csv(output_path, index=False)
        logger.info(f"BERT dataset prepared and saved to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to prepare BERT dataset: {e}")
        return False

def train_bert_model(data_dir: str, output_dir: str, epochs: int = 3, batch_size: int = 16) -> bool:
    logger.info("Training BERT model for response classification...")
    
    try:
        bert_predictor = BERTPredictor(output_dir)
        dataset_path = os.path.join(data_dir, "bert_training_dataset.csv")
        
        if not os.path.exists(dataset_path):
            training_data = load_training_data(data_dir)
            if not training_data['bert_responses']:
                logger.error("No BERT training data available")
                return False
            
            if not prepare_bert_dataset(
                training_data['bert_responses'], 
                training_data['bert_labels'], 
                dataset_path
            ):
                return False
        
        bert_predictor.train(dataset_path, epochs, batch_size)
        
        logger.info(f"BERT model trained and saved to {output_dir}")
        return True
        
    except Exception as e:
        logger.error(f"BERT training failed: {e}")
        return False

def train_rl_agent(data_dir: str, output_dir: str, episodes: int = 1000) -> bool:
    logger.info("Training RL agent...")
    
    try:
        training_data = load_training_data(data_dir)
        
        target_profile = {
            'waf_detected': True,
            'waf_type': 'cloudflare',
            'backend': 'nginx'
        }

        state_size = 32  
        action_size = 20  
        
        agent = RLAgent(state_size, action_size, output_dir)
        environment = BypassEnvironment(target_profile)
        
        if training_data['rl_experiences']:
            logger.info(f"Training RL agent with {len(training_data['rl_experiences'])} historical experiences")
            
            for experience in training_data['rl_experiences']:
                agent.remember(
                    np.array(experience['state']),
                    experience['action'],
                    experience['reward'],
                    np.array(experience['next_state']),
                    experience['done']
                )

            for i in range(episodes):
                loss = agent.replay()
                
                if i % 100 == 0:
                    logger.info(f"Episode {i}, Loss: {loss if loss else 'N/A'}, Epsilon: {agent.epsilon:.3f}")
        
        logger.info("Training RL agent with simulated experiences")
        
        for episode in range(episodes):
            state = np.random.randn(state_size)
            action_idx = agent.act(state)
            next_state = state + np.random.randn(state_size) * 0.1 
            reward = np.random.uniform(-1, 1)  
            done = np.random.rand() < 0.1 
            agent.remember(state, action_idx, reward, next_state, done)
            loss = agent.replay()
            
            if episode % 100 == 0:
                logger.info(f"Simulated episode {episode}, Loss: {loss if loss else 'N/A'}, Epsilon: {agent.epsilon:.3f}")
        
        agent.save_model()
        
        logger.info(f"RL agent trained and saved to {output_dir}")
        return True
        
    except Exception as e:
        logger.error(f"RL training failed: {e}")
        return False

def train_gan_model(data_dir: str, output_dir: str, epochs: int = 1000) -> bool:
    logger.info("Training GAN model for payload generation...")
    
    try:
        training_data = load_training_data(data_dir)
        
        if not training_data['gan_payloads']:
            logger.error("No GAN training data available")
            return False
        
        gan = PayloadGAN(model_dir=output_dir)
        
        gan.train(training_data['gan_payloads'], epochs)
        
        logger.info(f"GAN model trained and saved to {output_dir}")
        return True
        
    except Exception as e:
        logger.error(f"GAN training failed: {e}")
        return False

def generate_sample_data(data_dir: str) -> bool:
    try:
        os.makedirs(data_dir, exist_ok=True)
        bert_data = {
            "responses": [
                {"status_code": 403, "headers": {"server": "nginx"}, "body": "Access denied"},
                {"status_code": 200, "headers": {"server": "apache"}, "body": "Welcome to admin panel"},
                {"status_code": 500, "headers": {}, "body": "Internal server error"},
                {"status_code": 401, "headers": {"www-authenticate": "Basic"}, "body": "Unauthorized"}
            ],
            "labels": ["blocked", "success", "error", "blocked"]
        }
        
        with open(os.path.join(data_dir, 'bert_training_data.json'), 'w') as f:
            json.dump(bert_data, f, indent=2)
        
        gan_data = {
            "payloads": [
                "/..%2fadmin",
                "/.%2e/admin",
                "/;bypass=/admin",
                "/%09/admin",
                "/%0a/admin",
                "/%0d/admin",
                "/%00/admin",
                "/%u002e%u002e/admin",
                "/.%2e%2fadmin",
                "/..%5cadmin"
            ]
        }
        
        with open(os.path.join(data_dir, 'gan_training_data.json'), 'w') as f:
            json.dump(gan_data, f, indent=2)
        
        rl_data = {
            "experiences": [
                {
                    "state": [0.5, 0.3, 0.8, 1.0] + [0] * 28, 
                    "action": 2,
                    "reward": 5.0,
                    "next_state": [0.6, 0.4, 0.9, 1.0] + [0] * 28,
                    "done": False
                },
                {
                    "state": [0.2, 0.1, 0.4, 0.0] + [0] * 28,
                    "action": 5,
                    "reward": -3.0,
                    "next_state": [0.2, 0.1, 0.4, 0.0] + [0] * 28,
                    "done": True
                }
            ]
        }
        
        with open(os.path.join(data_dir, 'rl_training_data.json'), 'w') as f:
            json.dump(rl_data, f, indent=2)
        
        logger.info(f"Sample training data generated in {data_dir}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate sample data: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Train Nuke403 AI models")
    parser.add_argument("--data-dir", default="training_data", help="Directory containing training data")
    parser.add_argument("--output-dir", default="core/ai_core/models", help="Output directory for trained models")
    parser.add_argument("--bert-epochs", type=int, default=3, help="Number of epochs for BERT training")
    parser.add_argument("--bert-batch-size", type=int, default=16, help="Batch size for BERT training")
    parser.add_argument("--rl-episodes", type=int, default=1000, help="Number of episodes for RL training")
    parser.add_argument("--gan-epochs", type=int, default=1000, help="Number of epochs for GAN training")
    parser.add_argument("--all", action="store_true", help="Train all models")
    parser.add_argument("--bert", action="store_true", help="Train BERT model")
    parser.add_argument("--rl", action="store_true", help="Train RL agent")
    parser.add_argument("--gan", action="store_true", help="Train GAN model")
    parser.add_argument("--generate-sample-data", action="store_true", help="Generate sample training data")
    
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    if args.generate_sample_data:
        if generate_sample_data(args.data_dir):
            logger.info("Sample data generation completed successfully!")
        else:
            logger.error("Sample data generation failed!")
            return 1
    
    if not os.path.exists(args.data_dir) or not os.listdir(args.data_dir):
        logger.error(f"No training data found in {args.data_dir}. Use --generate-sample-data to create sample data.")
        return 1
    
    train_all = args.all or not (args.bert or args.rl or args.gan)

    success = True
    start_time = datetime.now()
    
    if train_all or args.bert:
        bert_output = os.path.join(args.output_dir, "bert_model")
        success &= train_bert_model(args.data_dir, bert_output, args.bert_epochs, args.bert_batch_size)
    
    if train_all or args.rl:
        rl_output = args.output_dir
        success &= train_rl_agent(args.data_dir, rl_output, args.rl_episodes)
    
    if train_all or args.gan:
        gan_output = args.output_dir
        success &= train_gan_model(args.data_dir, gan_output, args.gan_epochs)
    
    end_time = datetime.now()
    training_time = end_time - start_time
    
    if success:
        logger.info(f"All model training completed successfully in {training_time}!")
    else:
        logger.error("Some model training failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())