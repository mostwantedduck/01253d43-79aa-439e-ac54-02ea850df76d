#!/bin/ash

apk add nginx nano

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

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/srv02.key -out /tmp/srv02.crt -config /tmp/srv02.conf

mv /tmp/srv02.crt /etc/ssl/certs/srv02.crt
mv /tmp/srv02.key /etc/ssl/private/srv02.key

rc-service nginx start
rc-update add nginx default

mkdir /var/www/html

$html = $(cat <<'EOF'
<!doctype html>
<title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>

<article>
    <h1>We&rsquo;ll be back soon!</h1>
    <div>
        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href="mailto:#">contact us</a>, otherwise we&rsquo;ll be back online shortly!</p>
        <p>&mdash; The Team</p>
    </div>
</article>
}
EOF
)

echo "$html" | tee /var/wwww/html/index.html > /dev/null

