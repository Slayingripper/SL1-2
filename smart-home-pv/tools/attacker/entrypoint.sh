#!/bin/bash
# Make all scripts in /home/attacker/tools executable
if [ -d /home/attacker/tools ]; then
    echo "Setting executable permissions on all scripts in /home/attacker/tools..."
    find /home/attacker/tools -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod +x {} \;
    echo "Permissions set."
fi

# Execute the command passed to the container
exec "$@"
