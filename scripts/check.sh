# List running containers + status
docker compose ps

# Ollama API check (should list tags/models)
curl http://localhost:11434/api/tags

# Chroma heartbeat (v2 preferred)
curl http://localhost:8000/api/v2/heartbeat

# Or v1 if you want to see the deprecation live
curl http://localhost:8000/api/v1/heartbeat

# Elasticsearch cluster health (should say "green" or "yellow" for single-node)
curl http://localhost:9200/_cluster/health?pretty
