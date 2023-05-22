#!/bin/ash

apk add nginx nano iptables

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

/etc/init.d/iptables save
/etc/init.d/iptables restart



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

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/srv02.key -out /tmp/srv02.crt

mv /tmp/srv02.crt /etc/ssl/certs/srv02.crt
mv /tmp/srv02.key /etc/ssl/private/srv02.key

chmod 600 /etc/ssl/certs/srv02.crt
chmod 600 /etc/ssl/private/srv02.key

rc-service nginx start
rc-update add nginx default

[ ! -d "/var/www/html" ] && mkdir /var/www/html

echo "PCFkb2N0eXBlIGh0bWw+Cjx0aXRsZT5TaXRlIE1haW50ZW5hbmNlPC90aXRsZT4KPHN0eWxlPgogIGJvZHkgeyB0ZXh0LWFsaWduOiBjZW50ZXI7IHBhZGRpbmc6IDE1MHB4OyB9CiAgaDEgeyBmb250LXNpemU6IDUwcHg7IH0KI
CBib2R5IHsgZm9udDogMjBweCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7IGNvbG9yOiAjMzMzOyB9CiAgYXJ0aWNsZSB7IGRpc3BsYXk6IGJsb2NrOyB0ZXh0LWFsaWduOiBsZWZ0OyB3aWR0aDogNjUwcHg7IG1hcmdpbjogMCBhdXRvOyB9CiAgYSB7I
GNvbG9yOiAjZGM4MTAwOyB0ZXh0LWRlY29yYXRpb246IG5vbmU7IH0KICBhOmhvdmVyIHsgY29sb3I6ICMzMzM7IHRleHQtZGVjb3JhdGlvbjogbm9uZTsgfQo8L3N0eWxlPgoKPGFydGljbGU+CiAgICA8aDE+V2UmcnNxdW87bGwgYmUgYmFjayBzb
29uITwvaDE+CiAgICA8ZGl2PgogICAgICAgIDxwPlNvcnJ5IGZvciB0aGUgaW5jb252ZW5pZW5jZSBidXQgd2UmcnNxdW87cmUgcGVyZm9ybWluZyBzb21lIG1haW50ZW5hbmNlIGF0IHRoZSBtb21lbnQuIElmIHlvdSBuZWVkIHRvIHlvdSBjYW4gY
Wx3YXlzIDxhIGhyZWY9Im1haWx0bzojIj5jb250YWN0IHVzPC9hPiwgb3RoZXJ3aXNlIHdlJnJzcXVvO2xsIGJlIGJhY2sgb25saW5lIHNob3J0bHkhPC9wPgogICAgICAgIDxwPiZtZGFzaDsgVGhlIFRlYW08L3A+CiAgICA8L2Rpdj4KPC9hcnRpY
2xlPg==" | base64 -d | tee /var/www/html/index.html



