# 1. NVIDIA drivers + CUDA (already assumed if you're running models locally)
#    Verify: nvidia-smi should show your RTX 5090 / DGX GPU

# 2. Install NVIDIA Container Toolkit (if not already done)
#    https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit

# 3. Configure Docker to use nvidia runtime
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# 4. (Optional) Test GPU passthrough
docker run --rm --gpus all nvidia/cuda:12.6.0-base-ubuntu24.04 nvidia-smi
