#!/bin/bash

if ! [ -x "$(command -v podman-compose)" ]; then
  echo 'Error: podman-compose is not installed.' >&2
  exit 1
fi

cert_name="nip.responsible-internet.org"
domains=(nip.responsible-internet.org)
rsa_key_size=4096
elliptic_curve="secp384r1"
data_path="./certbot"
email="" # Adding a valid address is strongly recommended
staging=0 # Set to 1 if you're testing your setup to avoid hitting request limits

echo "### Stopping all containers ..."
podman-compose down
echo

echo "### Clearing certbot directory ..."
podman-compose up -d --no-deps nginx certbot && podman-compose down -v nginx certbot
echo

echo "### Starting cetbot ..."
podman-compose up --force-recreate -d --no-deps certbot
sleep 5
echo

echo "### Creating dummy certificate for $domains ..."
path="/etc/letsencrypt/live/$domains"
podman-compose run --rm --entrypoint "\
  mkdir -p $path" certbot
echo
podman-compose run --rm --entrypoint "\
  openssl req -x509 -nodes -newkey rsa:2048 -days 1\
    -keyout '$path/privkey.pem' \
    -out '$path/fullchain.pem' \
    -subj '/CN=localhost'" certbot
sleep 5
echo

if [ -f "nginx/sites-enabled/responsible-internet.org.d/ssl_letsencrypt.conf" ]; then
  echo "Adapting Nginx SSL Configuration"
  mv nginx/sites-enabled/responsible-internet.org.d/ssl_letsencrypt.conf nginx/sites-enabled/responsible-internet.org.d/ssl_letsencrypt.conf.inactive
fi

echo "### Starting nginx ..."
podman-compose up --force-recreate -d nginx certbot
sleep 5
echo

echo "### Deleting dummy certificate for $domains ..."
podman-compose run --rm --entrypoint "\
  rm -Rf /etc/letsencrypt/live/$domains && \
  rm -Rf /etc/letsencrypt/archive/$domains && \
  rm -Rf /etc/letsencrypt/renewal/$domains.conf" certbot
echo

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  echo $domain
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging --debug-challenges"; fi

podman-compose run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $staging_arg \
    $email_arg \
    $domain_args \
    --rsa-key-size $rsa_key_size \
    --elliptic-curve $elliptic_curve \
    --cert-name $cert_name \
    --agree-tos \
    --force-renewal \
    --verbose" certbot
sleep 5
echo

echo "Restoring Nginx SSL Configuration"
mv nginx/sites-enabled/responsible-internet.org.d/ssl_letsencrypt.conf.inactive nginx/sites-enabled/responsible-internet.org.d/ssl_letsencrypt.conf

echo "### Stopping all containers ..."
podman-compose down
echo
