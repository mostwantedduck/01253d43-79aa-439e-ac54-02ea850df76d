#!/bin/ash

apk add nginx

config_content=$(cat <<'EOF'
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name www.empire.tld;

        return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name www.empire.tld;

    ssl_certificate /etc/ssl/certs/srv02.crt;
    ssl_certificate_key /etc/ssl/private/srv02.key;

    ssl_protocols TLSv1.2;

    root /var/www/html;
}
EOF
)

echo "$config_content" | tee /etc/nginx/http.d/default > /dev/null

echo "Nginx configuration has been updated and the service has been restarted."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /dev/shm/srv02.key -out /dev/shm/srv02.crt -config /dev/shm/srv02.conf

mv /dev/shm/srv02.crt /etc/ssl/certs/srv02.crt
mv /dev/shm/srv02.key /etc/ssl/private/srv02.key

service nginx restart



