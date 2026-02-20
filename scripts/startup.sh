# Start everything
docker compose -f docker-compose.dev.yml up -d

# Check Ollama is alive + GPU
docker logs aithershield-ollama
# Should show GPU layers if models are loaded

# Pull a good starter model for SIEM / security use (e.g. 14B-32B quantized)
docker exec -it aithershield-ollama ollama pull qwen2.5:14b-instruct-q5_K_M
# or deepseek-coder-v2, llama3.1:70b (if you have enough VRAM), nomic-embed-text for embeddings

# Test Chroma
curl http://localhost:8000/api/v1/heartbeat

# Test ES
curl http://localhost:9200

# Build & run your Rust service (once you have Dockerfile)
docker compose build backend
docker compose up backend
