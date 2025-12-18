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

# Setup SSH
RUN mkdir -p /var/run/sshd && echo 'attacker:attacker' | chpasswd || true
RUN sed -i 's/^#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
RUN sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config || true
EXPOSE 22

# Default command: run entrypoint then sshd
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]
