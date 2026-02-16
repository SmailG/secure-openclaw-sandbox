#!/bin/bash

# --- Configuration ---
# Set the terminal window title (Works for Mac/Linux/WSL2)
echo -n -e "\033]0;Sandbox-Monitor\007"

echo "🛡️  Security Sandbox: Interactive Approval Monitor"
echo "📡 Monitoring ai-gateway logs for blocked traffic..."
echo "----------------------------------------------------"

# --- Monitoring Loop ---
# --line-buffered ensures grep doesn't wait for a full buffer to output.
docker logs -f ai-gateway 2>&1 | grep --line-buffered " 403 " | while read -r line; do
    
    # Extract the quoted request first, then parse host/domain from it.
    # Examples:
    #   "CONNECT oauth2.googleapis.com:443 HTTP/1.1"
    #   "GET https://example.com/path HTTP/1.1"
    REQUEST=$(echo "$line" | sed -n 's/.*"\([^"]*\)".*/\1/p')
    DOMAIN=""
    if [[ "$REQUEST" =~ ^CONNECT[[:space:]]+([^[:space:]]+) ]]; then
        HOSTPORT="${BASH_REMATCH[1]}"
        DOMAIN="${HOSTPORT%%:*}"
    elif [[ "$REQUEST" =~ ^[A-Z]+[[:space:]]+https?://([^/:]+) ]]; then
        DOMAIN="${BASH_REMATCH[1]}"
    fi
    # Normalize IPv6 bracket form if present.
    DOMAIN="${DOMAIN#[}"
    DOMAIN="${DOMAIN%]}"

    # Skip if domain is empty
    if [ -z "$DOMAIN" ]; then continue; fi

    # 🚀 CROSS-PLATFORM AUTO-FOCUS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: Focus Terminal window using AppleScript
        osascript -e 'tell application "Terminal" to set frontmost of (every window whose name contains "Sandbox-Monitor") to true' 2>/dev/null
    elif command -v wmctrl &> /dev/null; then
        # Linux: Focus window using wmctrl (if installed)
        wmctrl -a "Sandbox-Monitor"
    fi

    echo -e "\n🚨 [BLOCK DETECTED]: $DOMAIN"
    echo -e "❓ Should the agent be allowed to access this domain?"
    read -p "Allow? (y/n): " choice

    if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Send the approval to the Shield API (Inspector)
        # We use docker exec to ensure the curl happens inside the project network
        RESPONSE=$(docker exec inspector-api curl -s -X POST \
            http://localhost:5000/approve_domain \
            -H "Content-Type: application/json" \
            -d "{\"domain\": \"$DOMAIN\"}")

        if [[ "$RESPONSE" == *"success"* ]]; then
            echo "✅ SUCCESS: $DOMAIN is now whitelisted."
        else
            echo "❌ ERROR: Failed to update whitelist. Check inspector-api logs."
        fi
    else
        echo "🚫 DENIED: $DOMAIN remains blocked."
    fi

    echo -e "\n📡 Resuming monitor..."
done