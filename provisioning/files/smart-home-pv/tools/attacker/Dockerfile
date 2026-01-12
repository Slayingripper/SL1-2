FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
  nmap \
  arp-scan \
  tcpdump \
  tshark \
  wireshark-common \
  dsniff \
  ettercap-text-only \
  iputils-ping \
  mosquitto-clients \
  sqlmap \
  hping3 \
  python3 \
  python3-pip \
  python3-venv \
  net-tools \
  iproute2 \
  curl \
  wget \
  vim \
  less \
  jq \
  sudo \
  openssh-server \
  && rm -rf /var/lib/apt/lists/*

# Create a venv and install non-system python packages inside it (Kali prevents system-wide pip installs)
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/python -m pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install pymodbus paho-mqtt scapy

ENV PATH="/opt/venv/bin:$PATH"
RUN ln -s /opt/venv/bin/python /opt/venv/bin/python3 || true

# Ensure sqlmap is available — sometimes not packaged; fallback to cloning the repo
RUN if ! command -v sqlmap >/dev/null 2>&1; then \
  apt-get update && apt-get install -y git && \
  git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
  ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap || true; \
  fi

# Run as root for network attacks (tcpdump, arpspoof require CAP_NET_RAW)
# Create attacker user but stay root
RUN useradd -m -s /bin/bash attacker || true
RUN mkdir -p /home/attacker/tools && chown -R attacker:attacker /home/attacker
WORKDIR /home/attacker

# Make /tmp writable by all (for script temp files)
RUN chmod 1777 /tmp

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Setup SSH and User Access (mimicking cyberrangecz/ansible-role-user-access)
RUN mkdir -p /var/run/sshd && echo 'attacker:attacker' | chpasswd

# Configure SSH authentication
RUN mkdir -p /etc/ssh/sshd_config.d && \
    echo 'ChallengeResponseAuthentication yes' > /etc/ssh/sshd_config.d/99-challenge-password-auth.conf && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config.d/99-challenge-password-auth.conf

# Clean up main sshd_config to avoid conflicts
RUN sed -i '/^ChallengeResponseAuthentication/d' /etc/ssh/sshd_config && \
    sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config && \
    sed -i '/^#PasswordAuthentication/d' /etc/ssh/sshd_config

# Fix PAM for Docker (prevents "tunnel closed" due to pam_loginuid failure)
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/g' /etc/pam.d/sshd || true

# Ensure Correct Permissions
RUN mkdir -p /home/attacker/.ssh && \
    chown attacker:attacker /home/attacker/.ssh && \
    chmod 700 /home/attacker/.ssh

# Configure passwordless sudo for attacker
RUN echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

EXPOSE 22

# Default command: run entrypoint then sshd
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]
