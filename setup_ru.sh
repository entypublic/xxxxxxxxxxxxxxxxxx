#!/usr/bin/env bash

# install soft
apt update && apt install -y curl openssl
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray
systemctl stop xray

# set variables
UUID=$(xray uuid)
X25519_OUTPUT=$(xray x25519)
PRIVATE_KEY=$(echo "$X25519_OUTPUT" | grep 'Private' | awk '{print $2}')
PUBLIC_KEY=$(echo "$X25519_OUTPUT" | grep 'Public' | awk '{print $2}')
while true; do
  SS_PASS=$(openssl rand -base64 16)
  if [[ "$SS_PASS" != *"/"* && "$SS_PASS" != *"+"* ]]; then
    break
  fi
done
PUBLIC_IP=$(curl -s ipinfo.io/ip)
# Автовыбор SERVER_IP без вопросов (ENV SERVER_IP имеет приоритет)
SERVER_IP=${SERVER_IP:-${PUBLIC_IP}}

# Утилита: проверка свободного порта
is_port_free() {
  local port=$1
  ss -tln | grep -q ":${port} " && return 1 || return 0
}

# Автовыбор порта VLESS (ENV VLESS_PORT имеет приоритет)
if [[ -z "${VLESS_PORT:-}" ]]; then
  CANDIDATES=(443 8443 4443 2053 7443)
  for p in "${CANDIDATES[@]}"; do
    if is_port_free "$p"; then VLESS_PORT=$p; break; fi
  done
  VLESS_PORT=${VLESS_PORT:-443}
else
  # Если указан ENV, но порт занят — подберём ближайший свободный
  if ! is_port_free "$VLESS_PORT"; then
    for p in 443 8443 4443 2053 7443; do
      if is_port_free "$p"; then VLESS_PORT=$p; break; fi
    done
  fi
fi

echo
# Подготовка списка SNI (по умолчанию — предоставленный список)
DEFAULT_SNI_LIST=(
  "www.unicreditbank.ru"
  "www.gazprombank.ru"
  "cdn.gpb.ru"
  "mkb.ru"
  "www.open.ru"
  "cobrowsing.tbank.ru"
  "cdn.rosbank.ru"
  "www.psbank.ru"
  "www.raiffeisen.ru"
  "www.rzd.ru"
  "st.gismeteo.st"
  "stat-api.gismeteo.net"
  "c.dns-shop.ru"
  "restapi.dns-shop.ru"
  "www.pochta.ru"
  "passport.pochta.ru"
  "chat-ct.pochta.ru"
  "www.x5.ru"
  "www.ivi.ru"
  "api2.ivi.ru"
  "hh.ru"
  "i.hh.ru"
  "hhcdn.ru"
  "sentry.hh.ru"
  "cpa.hh.ru"
  "www.kp.ru"
  "cdnn21.img.ria.ru"
  "lenta.ru"
  "sync.rambler.ru"
  "s.rbk.ru"
  "www.rbc.ru"
  "target.smi2.net"
  "hb-bidder.skcrtxr.com"
  "strm-spbmiran-07.strm.yandex.net"
  "pikabu.ru"
  "www.tutu.ru"
  "cdn1.tu-tu.ru"
  "api.apteka.ru"
  "static.apteka.ru"
  "images.apteka.ru"
  "scitylana.apteka.ru"
  "www.drom.ru"
  "c.rdrom.ru"
  "www.farpost.ru"
  "s11.auto.drom.ru"
  "i.rdrom.ru"
  "yummy.drom.ru"
  "www.drive2.ru"
  "lemanapro.ru"
)

# Выбор SNI без вопросов: ENV SNI_LIST (через пробел) имеет приоритет,
# иначе используется встроенный список
if [[ -n "${SNI_LIST:-}" ]]; then
  IFS=' ' read -r -a SNI_LIST <<< "${SNI_LIST}"
else
  SNI_LIST=("${DEFAULT_SNI_LIST[@]}")
fi

# Проверим поддержку TLSv1.3 у доменов (оставим только валидные)
VALID_SNIS=()
for sni in "${SNI_LIST[@]}"; do
  OPENSSL_OUTPUT=$(timeout 3 openssl s_client -connect "$sni":443 -brief 2>&1)
  if echo "$OPENSSL_OUTPUT" | grep -q "TLSv1.3"; then
    VALID_SNIS+=("$sni")
  fi
done

if (( ${#VALID_SNIS[@]} == 0 )); then
  echo "Предупреждение: ни один домен из списка не подтвердил TLSv1.3. Использую www.yahoo.com как SNI по умолчанию."
  VALID_SNIS=("www.yahoo.com")
fi

# Выберем первый валидный SNI как dest для Reality
DEST_SNI="${VALID_SNIS[0]}"
echo "Reality dest будет: $DEST_SNI"
echo
# Автовыбор порта SS (ENV SS_PORT имеет приоритет)
if [[ -z "${SS_PORT:-}" ]]; then
  SSCANDS=(8888 8889 8890 4444 8388)
  for p in "${SSCANDS[@]}"; do
    if is_port_free "$p"; then SS_PORT=$p; break; fi
  done
  SS_PORT=${SS_PORT:-8888}
else
  if ! is_port_free "$SS_PORT"; then
    for p in 8888 8889 8890 4444 8388; do
      if is_port_free "$p"; then SS_PORT=$p; break; fi
    done
  fi
fi

# prepare config file
cp ./config.json.template /usr/local/etc/xray/config.json
sed -i "s|SERVER_IP|${SERVER_IP}|g" /usr/local/etc/xray/config.json
sed -i "s|VLESS_PORT|${VLESS_PORT}|g" /usr/local/etc/xray/config.json
sed -i "s|UUID|${UUID}|g" /usr/local/etc/xray/config.json
sed -i "s|PRIVATE_KEY|${PRIVATE_KEY}|g" /usr/local/etc/xray/config.json
sed -i "s|SS_PASS|${SS_PASS}|g" /usr/local/etc/xray/config.json
sed -i "s|SS_PORT|${SS_PORT}|g" /usr/local/etc/xray/config.json
sed -i "s|DEST_SNI|${DEST_SNI}|g" /usr/local/etc/xray/config.json

# Подготовим JSON для serverNames и shortIds
SERVER_NAMES_JSON="["
SHORT_IDS_JSON="["
declare -A SNI_TO_SID
for sni in "${VALID_SNIS[@]}"; do
  sid=$(openssl rand -hex 8)
  SNI_TO_SID["$sni"]="$sid"
  SERVER_NAMES_JSON+="\"$sni\"," 
  SHORT_IDS_JSON+="\"$sid\"," 
done
SERVER_NAMES_JSON="${SERVER_NAMES_JSON%,}]" # убрать последнюю запятую
SHORT_IDS_JSON="${SHORT_IDS_JSON%,}]"       # убрать последнюю запятую

sed -i "s|SERVER_NAMES_JSON|${SERVER_NAMES_JSON}|g" /usr/local/etc/xray/config.json
sed -i "s|SHORT_IDS_JSON|${SHORT_IDS_JSON}|g" /usr/local/etc/xray/config.json

# Резюме выбранных параметров
echo "Использую SERVER_IP: ${SERVER_IP}"
echo "Порт VLESS: ${VLESS_PORT}"
echo "Порт Shadowsocks: ${SS_PORT}"
echo "Кол-во валидных SNI: ${#VALID_SNIS[@]}"

# apply settings
systemctl restart xray
sleep 1
echo
if systemctl status xray | grep -q active; then
  echo "Xray статус:"
  systemctl status xray | grep Active
else
  echo "Ошибка: служба не запустилась. Попробуй указать другие домены или порты или используй предложенные значения"
  exit 1
fi

# Get connection strings
echo
echo "========================================"
echo "Строки подключения сохранены в connect.txt:"
echo
echo "VLESS:" > connect.txt
# Для каждого валидного SNI сформируем отдельную ссылку vless
for sni in "${VALID_SNIS[@]}"; do
  sid="${SNI_TO_SID[$sni]}"
  echo "vless://${UUID}@${SERVER_IP}:${VLESS_PORT}/?encryption=none&type=tcp&sni=${sni}&fp=chrome&security=reality&alpn=h2&flow=xtls-rprx-vision&pbk=${PUBLIC_KEY}&sid=${sid}&packetEncoding=xudp" >> connect.txt
done
echo >> connect.txt
echo "Shadowsocks-2022:" >> connect.txt
echo "ss://2022-blake3-aes-128-gcm:${SS_PASS}@${SERVER_IP}:${SS_PORT}" >> connect.txt
cat connect.txt
echo
echo "========================================"
echo "Используй vpn-клиент Hiddify - https://github.com/hiddify/hiddify-app"
