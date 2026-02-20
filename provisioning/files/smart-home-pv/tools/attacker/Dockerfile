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
  xauth \
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
WORKDIR /home/test

# Make /tmp writable by all (for script temp files)
RUN chmod 1777 /tmp

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

# Setup SSH and User Access (mimicking cyberrangecz/ansible-role-user-access)
RUN mkdir -p /var/run/sshd \
 && useradd -m -s /bin/bash test 2>/dev/null || true \
 && echo 'test:password' | chpasswd

# Configure SSH authentication and X11 Forwarding
RUN mkdir -p /etc/ssh/sshd_config.d && \
    echo 'ChallengeResponseAuthentication yes' > /etc/ssh/sshd_config.d/99-challenge-password-auth.conf && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config.d/99-challenge-password-auth.conf && \
    echo 'X11Forwarding yes' > /etc/ssh/sshd_config.d/99-x11-forwarding.conf && \
    echo 'X11UseLocalhost no' >> /etc/ssh/sshd_config.d/99-x11-forwarding.conf

# Clean up main sshd_config to avoid conflicts
RUN sed -i '/^ChallengeResponseAuthentication/d' /etc/ssh/sshd_config && \
    sed -i '/^PasswordAuthentication/d' /etc/ssh/sshd_config && \
    sed -i '/^#PasswordAuthentication/d' /etc/ssh/sshd_config

# Fix PAM for Docker (prevents "tunnel closed" due to pam_loginuid failure)
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/g' /etc/pam.d/sshd || true

# Ensure Correct Permissions
RUN mkdir -p /home/test/.ssh && \
    chown test:test /home/test/.ssh && \
    chmod 700 /home/test/.ssh

# Configure passwordless sudo for test user
RUN echo 'test ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

EXPOSE 22

# Default command: run entrypoint then sshd
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]
