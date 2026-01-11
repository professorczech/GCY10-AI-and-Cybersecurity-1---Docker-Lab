#!/bin/bash

# ----------------------------------------------------------------
# 1. CRITICAL: FIX PERMISSIONS FIRST
# ----------------------------------------------------------------
echo " [1/7] Fixing File Permissions..."

# Fix Log Permissions
touch /var/log/mail.log /var/log/syslog /var/log/gophish.log
chown syslog:adm /var/log/mail.log /var/log/syslog
chmod 666 /var/log/mail.log /var/log/syslog /var/log/gophish.log

# Fix User Permissions
chown -R alice:alice /home/alice
chown -R bob:bob /home/bob
chmod 700 /home/alice/Maildir
chmod 700 /home/bob/Maildir

# Fix Rsyslog Config
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf

# ----------------------------------------------------------------
# 2. CREATE FIREFOX SHORTCUTS
# ----------------------------------------------------------------
echo " [2/7] Creating Firefox Shortcuts..."

cat > /usr/share/applications/firefox.desktop <<EOF
[Desktop Entry]
Version=1.0
Name=Firefox Web Browser
Comment=Browse the World Wide Web
Exec=/usr/bin/firefox %u
Icon=firefox
Terminal=false
Type=Application
Categories=Network;WebBrowser;
EOF
chmod +x /usr/share/applications/firefox.desktop

# Copy to desktops
cp /usr/share/applications/firefox.desktop /home/alice/Desktop/
cp /usr/share/applications/firefox.desktop /home/bob/Desktop/
cp /usr/share/applications/firefox.desktop /home/ubuntu/Desktop/
chown alice:alice /home/alice/Desktop/firefox.desktop
chown bob:bob /home/bob/Desktop/firefox.desktop
chown bob:bob /home/ubuntu/Desktop/firefox.desktop
chmod +x /home/alice/Desktop/firefox.desktop /home/bob/Desktop/firefox.desktop /home/ubuntu/Desktop/firefox.desktop

# ----------------------------------------------------------------
# 3. START SERVICES
# ----------------------------------------------------------------
echo " [3/7] Starting Services..."

/usr/sbin/rsyslogd
service postfix start
service dovecot start

sleep 5

# ----------------------------------------------------------------
# 4. GENERATE MAIL PROFILES
# ----------------------------------------------------------------
echo " [4/7] Generating Mail Profiles..."

generate_claws_profile() {
    local USERNAME=$1
    local PASSWORD=$2
    local FULLNAME=$3
    local HOME_DIR="/home/$USERNAME"
    local CONFIG_DIR="$HOME_DIR/.claws-mail"

    mkdir -p "$CONFIG_DIR"
    
    # Account Config
    cat > "$CONFIG_DIR/accountrc" <<EOF
[Account: 1]
name=$FULLNAME
address=$USERNAME@lab.local
protocol=1
recv_server=localhost
smtp_server=localhost
user_id=$USERNAME
password=$PASSWORD
save_pass=1
inbox=
ssl_imap=0
ssl_smtp=0
set_domain=1
domain=lab.local
auto_check_newmail=1
EOF

    # Preferences
    cat > "$CONFIG_DIR/clawsrc" <<EOF
[Common]
primary_account_id=1
check_plugin_on_startup=0
widescreen_layout=1
EOF

    # Wizard Killer
    cat > "$CONFIG_DIR/folderlist.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<folderlist>
  <folder type="mh" name="Mailbox" path="$HOME_DIR/Maildir" />
</folderlist>
EOF

    # Permissions
    chown -R $USERNAME:$USERNAME "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 600 "$CONFIG_DIR/"*
}

generate_claws_profile "alice" "Password123!" "Alice Student"
generate_claws_profile "bob" "Password123!" "Bob Target"

# ----------------------------------------------------------------
# 5. START GOPHISH & DATABASE HEIST
# ----------------------------------------------------------------
echo " [5/7] Starting GoPhish & Auto-Resetting Password..."

service filebeat start

cd /opt/gophish
sed -i 's|0.0.0.0:80|0.0.0.0:8080|g' config.json

# Start GoPhish quietly
./gophish >> /var/log/gophish.log 2>&1 &

echo "Waiting for GoPhish database..."
sleep 10

# EXTRACT API KEY
API_KEY=$(sqlite3 /opt/gophish/gophish.db "SELECT api_key FROM users WHERE id=1;")

if [ ! -z "$API_KEY" ]; then
    echo "Extracted API Key. Resetting Admin Password..."
    
    # FIX: Send FULL USER OBJECT (Username + Role + Password)
    curl -X PUT -k https://127.0.0.1:3333/api/users/1 \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","role":"admin","password":"Password123!"}'
else
    echo "ERROR: Could not extract API Key from database."
fi

cd /

# ----------------------------------------------------------------
# 6. CONFIGURE FIREFOX AUTOSTART (TABS)
# ----------------------------------------------------------------
echo " [6/7] Configuring Browser Autostart..."

# Define the tabs to open
# Note: We use internal DNS names (soc-kibana, etc.) because Firefox is inside the container network.
LAB_URLS="https://127.0.0.1:3333 http://soc-kibana:5601 http://soc-open-webui:8080 http://soc-shuffle-frontend:3001"

setup_browser_autostart() {
    local USER=$1
    local HOME_DIR="/home/$USER"
    local AUTOSTART_DIR="$HOME_DIR/.config/autostart"

    # Create the XFCE Autostart directory
    mkdir -p "$AUTOSTART_DIR"

    # Create the Desktop Entry that launches Firefox with specific URLs
    cat > "$AUTOSTART_DIR/lab-dashboard.desktop" <<EOF
[Desktop Entry]
Type=Application
Exec=/usr/bin/firefox $LAB_URLS
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name=Lab Dashboard
Comment=Start Lab Tools
EOF

    # Fix permissions so the user can actually execute it
    chown -R $USER:$USER "$HOME_DIR/.config"
    chmod +x "$AUTOSTART_DIR/lab-dashboard.desktop"
}

setup_browser_autostart "alice"
setup_browser_autostart "bob"

# ----------------------------------------------------------------
# 7. FINALIZING
# ----------------------------------------------------------------
echo " [7/7] Finalizing..."

(sleep 15 && python3 /scripts/lab_gen.py) &

/usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf