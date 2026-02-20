![Project Name](https://raw.githubusercontent.com/AitherShield/aithershield/main/assets/aithershield.jpg)
# Hybrid AI powered SIEM


# Basic usage (Ollama only)
cargo run

# With confidence routing
export XAI_OPENAI_KEY="your-key"
export GROK_CONFIDENCE_THRESHOLD=0.8
cargo run

# Testing
cargo test --features mock-chroma