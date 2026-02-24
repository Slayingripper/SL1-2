#!/usr/bin/env bash
set -e

# Configuration
# Adjust these delays to make it look more natural
TYPING_SPEED=0.05  # Seconds per character
THINK_TIME=2       # Seconds to "think" before answering a quiz
READ_TIME=2        # Seconds to "read" output before pressing Enter

# Path to the tutorial script
TUTORIAL_SCRIPT="./tutorial_attack_walkthrough.sh"

# Function to simulate human typing
type_text() {
    text="$1"
    for (( i=0; i<${#text}; i++ )); do
        echo -n "${text:$i:1}"
        sleep $TYPING_SPEED
    done
    echo "" # Newline at the end
}

# Function to simulate thinking and entering a choice
enter_choice() {
    choice="$1"
    sleep $THINK_TIME
    type_text "$choice"
}

# Function to simulate reading and pressing Enter
press_enter() {
    sleep $READ_TIME
    echo ""
}

# Start the tutorial in a separate process that reads from a pipe
# We will effectively "script" the input to the interactive tutorial.

(
    # 1. Start / Intro
    # It waits for a pause_step
    sleep 3
    press_enter

    # 2. Phase 1: Recon
    # Quiz: Network Scanning Strategy (Correct: 3)
    enter_choice "3"
    
    # 3. Post-scan pausing
    # pause_step after showing scoring
    press_enter

    # 4. Reference files found (sometimes)
    # pause_step
    press_enter

    # 5. Phase 2: Web Recon
    # Quiz: Web Reconnaissance Tool Selection (Correct: 2)
    enter_choice "2"
    
    # Quiz: Validating Attack Impact (Correct: 1)
    enter_choice "1"

    # Pause after wifi_scan check
    press_enter

    # 6. Phase 3: Phishing (Assuming --no-phishing is NOT used)
    # Quiz: Phishing Server Configuration (Correct: 2)
    enter_choice "2"

    # Quiz: Delivering the Payload (Correct: 1)
    enter_choice "1"

    # Quiz: Credential Harvesting Strategy (Correct: 2)
    enter_choice "2"

    # Pause after phishing section
    press_enter

    # 7. Phase 4: Brute Force
    # Quiz: Calibrating the Brute-Force Tool (Correct: 3)
    enter_choice "3"
    
    # Quiz: Wordlist preparation (Correct: 1)
    enter_choice "1"

    # Quiz: Efficient Cracking Strategy (Correct: 2)
    enter_choice "2"

    # Pause after brute force
    press_enter

    # 8. Phase 5: MQTT
    # This part depends on if mosquito_sub is installed and if a broker found.
    # Assuming standard lab setup where it is found.
    # Quiz: MQTT Reconnaissance (Correct: 1)
    enter_choice "1"

    # Quiz: Data Integrity Attack (Correct: 2)
    enter_choice "2"

    # Pause after MQTT
    press_enter

    # 9. Phase 6: Modbus
    # Quiz: Modbus Protocol Exploitation (Correct: 1)
    enter_choice "1"

    # Quiz: Executing the Control Command (Correct: 3)
    enter_choice "3"

    # Quiz: Modifying the Attack Payload (Correct: 1)
    enter_choice "1"

    # Quiz: Completing the Attack Cycle (Correct: 2)
    enter_choice "2"

    # Final pause before summary ? (Script ends with summary, usually no pause at very end)
    # There is a pause_step after Modbus section
    press_enter

) | $TUTORIAL_SCRIPT "$@"
