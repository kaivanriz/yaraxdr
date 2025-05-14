#!/bin/bash

# Fungsi untuk mengecek apakah Docker sudah terinstal
install_docker() {
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
}

# Mengecek apakah Docker sudah terinstal
if ! command -v docker &> /dev/null
then
    install_docker
else
    echo "Docker sudah terinstal."
fi

# Melakukan login ke Docker registry tanpa interaksi
echo "Melakukan login ke Docker registry..."
docker login gitlab-registry.tangerangkota.go.id -u devop -p securepassword

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
    exit 1
fi

# Membuat script di /usr/bin/yara untuk menjalankan docker run secara otomatis
echo "Membuat script di /usr/bin/yara..."

cat <<EOF | sudo tee /usr/bin/yara > /dev/null
#!/bin/bash

# Menjalankan Docker untuk memeriksa versi Yara
docker run --rm gitlab-registry.tangerangkota.go.id/yara:latest yara "\$@"
EOF

# Membuat script di /usr/bin/yarac untuk menjalankan docker run secara otomatis
echo "Membuat script di /usr/bin/yarac..."

cat <<EOF | sudo tee /usr/bin/yarac > /dev/null
#!/bin/bash

# Menjalankan Docker untuk menjalankan yarac (Yara Compiler)
docker run --rm gitlab-registry.tangerangkota.go.id/yara:latest yarac "\$@"
EOF

# Memberikan izin eksekusi pada file /usr/bin/yara dan /usr/bin/yarac
sudo chmod +x /usr/bin/yara
sudo chmod +x /usr/bin/yarac

echo "Script /usr/bin/yara dan /usr/bin/yarac berhasil dibuat dan dapat dijalankan."
