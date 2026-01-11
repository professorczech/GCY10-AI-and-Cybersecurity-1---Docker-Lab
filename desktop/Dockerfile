# 1. Base Image
FROM atsushisaito/docker-ubuntu-sweb:latest

ENV DEBIAN_FRONTEND=noninteractive
USER root

# 2. Install Tools & Mozilla Firefox
# ADDED: sqlite3 (Critical for GoPhish Automation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    software-properties-common \
    wget \
    ca-certificates \
    gnupg \
    postfix \
    dovecot-core \
    dovecot-imapd \
    claws-mail \
    claws-mail-themes \
    curl \
    unzip \
    rsyslog \
    nano \
    iputils-ping \
    sqlite3 \
    dos2unix && \
    # Setup Mozilla Repo
    mkdir -p /etc/apt/keyrings && \
    wget -qO- https://packages.mozilla.org/apt/repo-signing-key.gpg | gpg --dearmor -o /etc/apt/keyrings/packages.mozilla.org.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/packages.mozilla.org.gpg] https://packages.mozilla.org/apt mozilla main" | tee /etc/apt/sources.list.d/mozilla.list && \
    echo "Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000" | tee /etc/apt/preferences.d/mozilla && \
    apt-get update && \
    apt-get install -y --no-install-recommends firefox && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Fix Postfix
RUN echo "lab.local" > /etc/mailname

# 3. Configure Users
RUN useradd -m -s /bin/bash alice && \
    useradd -m -s /bin/bash bob && \
    echo 'alice:Password123!' | chpasswd && \
    echo 'bob:Password123!' | chpasswd && \
    echo 'root:Password123!' | chpasswd

# FIX: GRANT DOVECOT PERMISSION (Stops "Auth Process Broken")
RUN usermod -aG shadow dovecot

# FIX: CREATE DOVECOT PASSWORD FILE
# This creates a separate password list just for the mail server.
# Format: user:{PLAIN}password
RUN echo "alice:{PLAIN}Password123!" > /etc/dovecot/users && \
    echo "bob:{PLAIN}Password123!" >> /etc/dovecot/users && \
    chown root:root /etc/dovecot/users && \
    chmod 644 /etc/dovecot/users

# 4. FIX: MANUALLY CREATE SHORTCUTS
# This ensures Firefox appears in the menu
RUN printf '[Desktop Entry]\nVersion=1.0\nName=Firefox Web Browser\nComment=Browse the World Wide Web\nExec=/usr/bin/firefox %%u\nIcon=firefox\nTerminal=false\nType=Application\nCategories=Network;WebBrowser;\n' > /usr/share/applications/firefox.desktop && \
    chmod +x /usr/share/applications/firefox.desktop

# Create Desktop Folders and copy icons
RUN mkdir -p /home/alice/Desktop /home/bob/Desktop && \
    cp /usr/share/applications/firefox.desktop /home/alice/Desktop/ && \
    cp /usr/share/applications/claws-mail.desktop /home/alice/Desktop/ && \
    cp /usr/share/applications/firefox.desktop /home/bob/Desktop/ && \
    cp /usr/share/applications/claws-mail.desktop /home/bob/Desktop/ && \
    chmod +x /home/alice/Desktop/*.desktop /home/bob/Desktop/*.desktop

# 5. Create Mailboxes
RUN mkdir -p /home/alice/Maildir/new /home/alice/Maildir/cur /home/alice/Maildir/tmp && \
    chown -R alice:alice /home/alice/Maildir && \
    chmod -R 700 /home/alice/Maildir

RUN mkdir -p /home/bob/Maildir/new /home/bob/Maildir/cur /home/bob/Maildir/tmp && \
    chown -R bob:bob /home/bob/Maildir && \
    chmod -R 700 /home/bob/Maildir

# 6. Install GoPhish
WORKDIR /opt/gophish
RUN curl -L -o gophish.zip https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip && \
    unzip gophish.zip && \
    chmod +x gophish && \
    rm gophish.zip

# 7. Install Filebeat
RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.13-amd64.deb && \
    dpkg -i filebeat-7.17.13-amd64.deb && \
    rm filebeat-7.17.13-amd64.deb

# 8. Config Injection
COPY desktop/config/main.cf /etc/postfix/main.cf
COPY desktop/config/dovecot.conf /etc/dovecot/dovecot.conf
COPY desktop/config/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
COPY elk/filebeat/filebeat.yml /etc/filebeat/filebeat.yml
RUN chmod 644 /etc/filebeat/filebeat.yml

# 9. Startup Script
COPY desktop/scripts/entrypoint.sh /startup.sh
COPY desktop/lab_gen.py /scripts/lab_gen.py
RUN dos2unix /startup.sh
RUN chmod +x /startup.sh

ENTRYPOINT ["/startup.sh"]