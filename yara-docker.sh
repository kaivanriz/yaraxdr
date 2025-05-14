#!/bin/bash

# Mengecek apakah Docker sudah terinstal
if ! command -v docker &> /dev/null
then
    echo "Docker tidak ditemukan. Menginstal Docker..."

    # Mengupdate package index
    sudo yum check-update

    # Menambahkan repository Docker
    sudo yum install -y yum-utils
    sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

    # Menginstal Docker
    sudo yum install -y docker-ce docker-ce-cli containerd.io

    # Memulai Docker dan memastikan Docker berjalan
    sudo systemctl start docker
    sudo systemctl enable docker

    echo "Docker berhasil diinstal!"
else
    echo "Docker sudah terinstal."
fi

# Melakukan login ke Docker registry
echo "Melakukan login ke Docker registry..."
echo "devop" | docker login gitlab-registry.tangerangkota.go.id -u devop --password-stdin

# Menarik image dari registry
echo "Menarik image dari gitlab-registry.tangerangkota.go.id..."
docker pull gitlab-registry.tangerangkota.go.id/yara:latest

# Memeriksa apakah docker run berhasil dan menampilkan versi dari 'yara'
echo "Memeriksa versi dari yara..."
docker run --rm gitlab-registry.tangerangkota.go.id/yara:latest yara -v

# Mengecek apakah perintah docker run berhasil
if [ $? -eq 0 ]; then
    echo "Docker run berhasil dan versi Yara berhasil ditampilkan."
else
    echo "Terjadi masalah saat menjalankan Yara atau menampilkan versinya."
fi
