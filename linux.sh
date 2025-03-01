#!/bin/bash

# Colors for output readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Global variables
SILENT_MODE=0

# Function Definitions

## Check Internet Connectivity
check_internet() {
    echo -e "${GREEN}Checking internet connectivity...${NC}"
    if ping -q -c 1 -W 1 google.com >/dev/null; then
        echo -e "${GREEN}Internet is available.${NC}"
    else
        echo -e "${RED}No internet connection. Please check your connection and try again.${NC}"
        exit 1
    fi
}

## Apply All Updates
apply_updates() {
    echo -e "${GREEN}Applying all updates...${NC}"
    check_internet
    echo "Updating APT packages..."
    sudo apt update
    sudo apt upgrade -y
    sudo apt full-upgrade -y
    sudo apt autoremove -y
    sudo apt autoclean -y
    # Flatpak updates
    if command -v flatpak >/dev/null 2>&1; then
        echo "Updating Flatpak packages..."
        sudo flatpak update -y
    fi
    # Snap updates
    if command -v snap >/dev/null 2>&1; then
        echo "Updating Snap packages..."
        sudo snap refresh
    fi
    # Firmware updates
    if command -v fwupdmgr >/dev/null 2>&1; then
        echo "Updating firmware..."
        sudo fwupdmgr refresh
        sudo fwupdmgr update -y
    fi
    # Recovery partition update
    if command -v pop-upgrade >/dev/null 2>&1; then
        echo "Updating system & recovery partition..."
        sudo pop-upgrade release upgrade
        sudo pop-upgrade recovery upgrade from-release
    fi
    echo -e "${GREEN}Updates completed successfully.${NC}"
}

## Config New Install
config_new_install() {
    echo -e "${GREEN}Configuring new Pop!_OS installation...${NC}"
    check_internet

    # System updates
    echo "Updating system..."
    sudo apt update && sudo apt full-upgrade -y
    sudo apt autoremove -y && sudo apt autoclean

    # Install Lynis for security auditing
    echo "Installing Lynis..."
    sudo apt install -y lynis
    echo "Running Lynis system audit..."
    sudo lynis audit system

    # Harden ulimit and core dumps
    echo "Hardening ulimit and core dumps..."
    echo "ulimit -c 0" | sudo tee -a /etc/profile
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf

    # Apply kernel-level protections
    echo "Applying kernel protections..."
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    echo "kernel.unprivileged_userns_clone=0" | sudo tee -a /etc/sysctl.d/99-hardening.conf
    echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.d/99-hardening.conf
    sudo sysctl -p

    # Configure sudo timeout
    echo "Setting sudo timeout to 5 minutes..."
    echo "Defaults timestamp_timeout=5" | sudo tee /etc/sudoers.d/timeout

    # Secure /tmp with tmpfs
    echo "Securing /tmp with tmpfs..."
    echo "tmpfs /tmp tmpfs nosuid,nodev,noexec 0 0" | sudo tee -a /etc/fstab
    sudo mount -a || echo -e "${YELLOW}Warning: /tmp mount failed. Check /etc/fstab.${NC}"

    # Secure home directory permissions
    echo "Securing home directory..."
    chmod 700 /home/$USER

    # Configure UFW firewall
    echo "Configuring firewall..."
    sudo apt install -y ufw
    sudo ufw enable
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw status

    # Disable IPv6
    echo "Disabling IPv6..."
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    # Harden SSH configuration
    echo "Hardening SSH..."
    sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "SSH configured on port 2222. Use key-based auth only."

    # Disable unnecessary services
    echo "Disabling Avahi daemon..."
    sudo systemctl disable avahi-daemon && sudo systemctl stop avahi-daemon

    # Disable Pop!_OS telemetry
    echo "Disabling Pop!_OS telemetry..."
    sudo systemctl disable pop-hw-probe && sudo systemctl mask pop-hw-probe

    # Configure NextDNS
    echo "Configuring NextDNS..."
    sudo mkdir -p /etc/systemd
    cat << EOF | sudo tee /etc/systemd/resolved.conf
[Resolve]
DNS=45.90.28.0#2ce3b7.dns.nextdns.io
DNS=2a07:a8c0::#2ce3b7.dns.nextdns.io
DNS=45.90.30.0#2ce3b7.dns.nextdns.io
DNS=2a07:a8c1::#2ce3b7.dns.nextdns.io
DNSOverTLS=yes
EOF
    sudo systemctl restart systemd-resolved
    echo "NextDNS configured with DNS over TLS."

    # Configure privacy-respecting NTP
    echo "Configuring NTP..."
    sudo sed -i 's/#NTP=/NTP=pool.ntp.org/' /etc/systemd/timesyncd.conf
    sudo systemctl restart systemd-timesyncd
    echo "NTP set to pool.ntp.org."

    echo -e "${GREEN}New install configuration completed.${NC}"
}

## System Health Check
check_system_health() {
    echo -e "${GREEN}System Health Check:${NC}"
    echo "Load Average:"; uptime
    echo "Disk Usage:"; df -h | grep '^/dev'
    echo "Memory Usage:"; free -h
    echo "Top 5 Memory-Intensive Processes:"; ps -eo pid/ppid/cmd/%mem/%cpu --sort=-%mem | head -n 6
    echo "Failed Systemd Services:"; systemctl --failed
    echo -e "${GREEN}System health check completed.${NC}"
}

## Backup System
backup_system() {
    echo -e "${GREEN}Creating a backup of your home directory...${NC}"
    BACKUP_DIR=~/backups/$(date +'%Y-%m-%d_%H%M%S')
    mkdir -p "$BACKUP_DIR"
    tar -czvf "$BACKUP_DIR/home_backup.tar.gz" ~ --exclude="$BACKUP_DIR"
    echo -e "${GREEN}Backup completed: $BACKUP_DIR/home_backup.tar.gz${NC}"
}

## Manage Flatpaks
manage_flatpaks() {
    echo -e "${GREEN}Flatpak Options:${NC}"
    echo "1) List Installed Flatpaks"; echo "2) Uninstall a Flatpak"; echo "3) Update Flatpaks"
    read -p "Choose an option: " choice
    case $choice in
        1) flatpak list ;;
        2) read -p "Enter the Flatpak ID to uninstall: " flatpak_id; flatpak uninstall "$flatpak_id" -y ;;
        3) flatpak update -y ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

## Manage Snaps
manage_snaps() {
    echo -e "${GREEN}Snap Options:${NC}"
    echo "1) List Installed Snaps"; echo "2) Uninstall a Snap"; echo "3) Update Snaps"; echo "4) List Available Snap Updates"
    read -p "Choose an option: " choice
    case $choice in
        1) snap list ;;
        2) read -p "Enter the Snap name to uninstall: " snap_name; sudo snap remove "$snap_name" ;;
        3) sudo snap refresh ;;
        4) snap refresh --list ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

## Manage Cron Jobs
manage_cron_jobs() {
    echo -e "${GREEN}Cron Job Management:${NC}"
    echo "1) View Current Cron Jobs"; echo "2) Remove a Cron Job"
    read -p "Choose an option: " choice
    case $choice in
        1) crontab -l ;;
        2) echo "Current Cron Jobs:"; crontab -l | nl; read -p "Enter the line number to remove: " line; crontab -l | sed "${line}d" | crontab -; echo -e "${GREEN}Cron job removed.${NC}" ;;
        *) echo -e "${RED}Invalid option.${NC}" ;;
    esac
}

## Disk Cleanup
disk_cleanup() {
    echo -e "${GREEN}Performing disk cleanup...${NC}"
    sudo apt autoclean -y
    sudo apt autoremove -y
    sudo rm -rf ~/.cache/*
    sudo journalctl --vacuum-time=30d
    echo -e "${GREEN}Disk cleanup completed.${NC}"
}

## Security Checks
security_checks() {
    echo -e "${GREEN}Performing security checks...${NC}"
    echo "Firewall Status:"; sudo ufw status || echo -e "${YELLOW}UFW not installed.${NC}"
    echo "Open Ports:"; sudo ss -tuln || sudo netstat -tuln
    echo "World-Writable Files:"; find / -xdev -type f -perm -o+w -print 2>/dev/null | head -n 10
    echo -e "${GREEN}Security checks completed.${NC}"
}

## Install and Configure Apps (Stub - Expand as needed)
install_and_configure_apps() {
    # Ensure dependencies are installed
    if ! command -v flatpak >/dev/null 2>&1; then
        read -p "Flatpak is not installed. Install it? (y/N): " install_flatpak
        if [[ $install_flatpak =~ ^[Yy]$ ]]; then
            sudo apt install -y flatpak
            flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
        else
            echo "Some apps require Flatpak. Installation may be limited."
        fi
    fi
    if ! command -v wget >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        sudo apt install -y wget unzip
    fi
    if ! command -v curl >/dev/null 2>&1; then
        sudo apt install -y curl
    fi

    while true; do
        clear
        echo "Select an app to install and configure:"
        options=(
            "Brave" "BleachBit" "Cryptomator" "Element" "GIMP" "Grayjay" "Jitsi Meet" "KeepassXC" 
            "LibreWolf" "Nextcloud Client" "Obsidian" "Proton Pass" "Proton VPN" "Shortwave" 
            "Signal" "Standard Notes" "Syncthing" "Terminator" "Thunderbird" "Tor Browser" 
            "VLC" "VScodium" "Back to Main Menu"
        )
        select opt in "${options[@]}"; do
            case $opt in
                "Brave")
                    echo "Installing Brave (privacy-respecting browser)..."
                    if dpkg -l | grep -q brave-browser; then
                        echo "Brave already installed."
                    else
                        sudo curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
                        echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
                        sudo apt update
                        sudo apt install -y brave-browser
                        echo "Brave installed. Shields enabled by default. Disable Brave Rewards in settings for max privacy."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "BleachBit")
                    echo "Installing BleachBit (system cleaner)..."
                    if dpkg -l | grep -q bleachbit; then
                        echo "BleachBit already installed."
                    else
                        sudo apt install -y bleachbit
                        echo "BleachBit installed. Run 'bleachbit' and enable shredding for sensitive files."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Cryptomator")
                    echo "Installing Cryptomator (file encryption for cloud storage)..."
                    if flatpak list | grep -q org.cryptomator.Cryptomator; then
                        echo "Cryptomator already installed."
                    else
                        flatpak install -y flathub org.cryptomator.Cryptomator
                        echo "Cryptomator installed. Launch it and create an encrypted vault for your files."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Element")
                    echo "Installing Element (Matrix client for encrypted chat)..."
                    if flatpak list | grep -q im.riot.Riot; then
                        echo "Element already installed."
                    else
                        flatpak install -y flathub im.riot.Riot
                        echo "Element installed. Sign in or create a Matrix account; join privacy-focused rooms."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "GIMP")
                    echo "Installing GIMP (open-source image editor)..."
                    if dpkg -l | grep -q gimp; then
                        echo "GIMP already installed."
                    else
                        sudo apt install -y gimp
                        echo "GIMP installed. Ready to use for photo editing."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Grayjay")
    echo "Installing Grayjay (privacy-focused media aggregator)..."
    install_dir="$HOME/.local/opt/Grayjay"

    # Check if Grayjay is already installed and prompt to overwrite
    if [ -f "$install_dir/Grayjay" ]; then
        read -p "Grayjay is already installed at $install_dir. Overwrite? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            echo "Installation skipped."
            [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
            break
        fi
        rm -rf "$install_dir"
    fi

    # Download the zip file to /tmp
    wget "https://updater.grayjay.app/Apps/Grayjay.Desktop/Grayjay.Desktop-linux-x64.zip" -O /tmp/Grayjay.zip || {
        echo "Download failed."
        [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
        break
    }

    # Extract to a temporary directory
    unzip /tmp/Grayjay.zip -d /tmp/Grayjay-tmp || {
        echo "Extraction failed."
        rm -f /tmp/Grayjay.zip
        [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
        break
    }

    # Move contents to user-specific install_dir
    version_dir=$(ls /tmp/Grayjay-tmp | grep "Grayjay.Desktop-linux-x64")
    mkdir -p "$install_dir"
    mv /tmp/Grayjay-tmp/"$version_dir"/* "$install_dir" || {
        echo "Failed to move files to $install_dir."
        rm -rf /tmp/Grayjay-tmp /tmp/Grayjay.zip
        [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
        break
    }

    # Set executable permissions
    chmod +x "$install_dir/Grayjay" || {
        echo "Failed to set permissions."
        [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
        break
    }

    # Create launcher script in ~/.local/bin
    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/grayjay" << EOL
#!/bin/bash
cd $install_dir
./Grayjay
EOL
    chmod +x "$HOME/.local/bin/grayjay"

    # Remove any old system-wide launcher
    sudo rm -f /usr/local/bin/grayjay

    # Create desktop entry
    mkdir -p "$HOME/.local/share/applications"
    cat > "$HOME/.local/share/applications/grayjay.desktop" << EOL
[Desktop Entry]
Name=Grayjay
Exec=$HOME/.local/bin/grayjay
Icon=$install_dir/grayjay.png
Type=Application
Terminal=false
EOL
    chmod +x "$HOME/.local/share/applications/grayjay.desktop"

    # Clean up temporary files
    rm -rf /tmp/Grayjay.zip /tmp/Grayjay-tmp || echo "Warning: Could not clean up temporary files."

    echo "Grayjay installed in $install_dir. Launch it from the menu or type 'grayjay'."
    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
    break
    ;;
                "Jitsi Meet")
                    echo "Installing Jitsi Meet (open-source video conferencing)..."
                    if flatpak list | grep -q org.jitsi.jitsi-meet; then
                        echo "Jitsi Meet already installed."
                    else
                        flatpak install -y flathub org.jitsi.jitsi-meet
                        echo "Jitsi Meet installed. Start a meeting or join one directly from the app."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "KeepassXC")
                    echo "Installing KeepassXC (local password manager)..."
                    if dpkg -l | grep -q keepassxc; then
                        echo "KeepassXC already installed."
                    else
                        sudo apt install -y keepassxc
                        echo "KeepassXC installed. Launch it, create a new database, and set a strong master password."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "LibreWolf")
                    echo "Installing LibreWolf (privacy-enhanced Firefox fork)..."
                    if command -v librewolf >/dev/null 2>&1; then
                        echo "LibreWolf already installed."
                    else
                        sudo apt install -y software-properties-common
                        sudo add-apt-repository -y ppa:intika/librewolf
                        sudo apt update
                        sudo apt install -y librewolf
                        wget "https://raw.githubusercontent.com/vomxy/user.js/master/user.js" -O ~/librewolf.user.js
                        profile_dir=$(find ~/.librewolf -maxdepth 1 -type d -name "*.default-release" | head -n 1)
                        if [ -n "$profile_dir" ]; then
                            cp ~/librewolf.user.js "$profile_dir/user.js"
                            echo "Privacy-focused user.js applied to $profile_dir."
                        fi
                        rm ~/librewolf.user.js
                        echo "LibreWolf installed with enhanced privacy settings."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Nextcloud Client")
                    echo "Installing Nextcloud Client (self-hosted cloud sync)..."
                    if dpkg -l | grep -q nextcloud-desktop; then
                        echo "Nextcloud Client already installed."
                    else
                        sudo apt install -y nextcloud-desktop
                        echo "Nextcloud Client installed. Launch it and connect to your Nextcloud server."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Obsidian")
                    echo "Installing Obsidian (Markdown-based note-taking)..."
                    if flatpak list | grep -q md.obsidian.Obsidian; then
                        echo "Obsidian already installed."
                    else
                        flatpak install -y flathub md.obsidian.Obsidian
                        echo "Obsidian installed. Launch it, create a local vault, and disable telemetry in settings."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Proton Pass")
                    echo "Installing Proton Pass (encrypted password manager)..."
                    if dpkg -l | grep -q proton-pass; then
                        echo "Proton Pass already installed."
                    else
                        wget "https://proton.me/download/pass/linux/proton-pass_1.29.3_amd64.deb" -O ~/proton-pass.deb
                        sudo dpkg -i ~/proton-pass.deb
                        sudo apt-get install -f -y
                        rm ~/proton-pass.deb
                        echo "Proton Pass installed. Launch it and sign in with your Proton account."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Proton VPN")
                    echo "Installing Proton VPN (privacy-focused VPN)..."
                    if dpkg -l | grep -q protonvpn; then
                        echo "Proton VPN already installed."
                    else
                        wget "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3_all.deb" -O ~/protonvpn.deb
                        sudo dpkg -i ~/protonvpn.deb
                        sudo apt update
                        sudo apt install -y protonvpn
                        rm ~/protonvpn.deb
                        echo "Proton VPN installed. Launch it, log in, and enable the kill switch."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Shortwave")
                    echo "Installing Shortwave (modern internet radio)..."
                    if flatpak list | grep -q de.haeckerfelix.Shortwave; then
                        echo "Shortwave already installed."
                    else
                        flatpak install -y flathub de.haeckerfelix.Shortwave
                        echo "Shortwave installed. Launch it and add your favorite stations."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Signal")
                    echo "Installing Signal (secure messaging)..."
                    if dpkg -l | grep -q signal-desktop; then
                        echo "Signal already installed."
                    else
                        wget -O- https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor | sudo tee /usr/share/keyrings/signal-desktop-keyring.gpg > /dev/null
                        echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' | sudo tee /etc/apt/sources.list.d/signal-xenial.list
                        sudo apt update && sudo apt install -y signal-desktop-beta
                        echo "Signal installed. Launch it and link it to your phone for encrypted messaging."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Standard Notes")
                    echo "Installing Standard Notes (encrypted notes)..."
                    if flatpak list | grep -q org.standardnotes.standardnotes; then
                        echo "Standard Notes already installed."
                    else
                        flatpak install -y flathub org.standardnotes.standardnotes
                        echo "Standard Notes installed. Sign in to sync your encrypted notes."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Syncthing")
                    echo "Installing Syncthing (decentralized file sync)..."
                    if dpkg -l | grep -q syncthing; then
                        echo "Syncthing already installed."
                    else
                        sudo apt install -y syncthing
                        sudo systemctl enable syncthing@$USER.service
                        sudo systemctl start syncthing@$USER.service
                        echo "Syncthing installed and started. Access it at http://localhost:8384 to configure sync."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Terminator")
                    echo "Installing Terminator (advanced terminal emulator)..."
                    if dpkg -l | grep -q terminator; then
                        echo "Terminator already installed."
                    else
                        sudo apt install -y terminator
                        echo "Terminator installed. Right-click to split terminals or customize as needed."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Thunderbird")
                    echo "Installing Thunderbird (email client with privacy options)..."
                    if dpkg -l | grep -q thunderbird; then
                        echo "Thunderbird already installed."
                    else
                        sudo apt install -y thunderbird
                        echo "Thunderbird installed. Configure your email account and disable telemetry in settings."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Tor Browser")
                    echo "Installing Tor Browser (anonymous browsing)..."
                    if dpkg -l | grep -q torbrowser-launcher; then
                        echo "Tor Browser already installed."
                    else
                        sudo apt install -y torbrowser-launcher
                        torbrowser-launcher & # Launch to download and install
                        echo "Tor Browser installed. Launch it and set security level to 'Safest'."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "VLC")
                    echo "Installing VLC (versatile media player)..."
                    if dpkg -l | grep -q vlc; then
                        echo "VLC already installed."
                    else
                        sudo apt install -y vlc
                        echo "VLC installed. Disable network access in preferences for privacy."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "VScodium")
                    echo "Installing VScodium (open-source code editor)..."
                    if flatpak list | grep -q com.vscodium.codium; then
                        echo "VScodium already installed."
                    else
                        flatpak install -y flathub com.vscodium.codium
                        mkdir -p ~/.config/VSCodium/User
                        echo '{"telemetry.enableTelemetry": false}' > ~/.config/VSCodium/User/settings.json
                        echo "VScodium installed with telemetry disabled. Add extensions as needed."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Back to Main Menu")
                    return
                    ;;
                *)
                    echo -e "${RED}Invalid option.${NC}"
                    ;;
            esac
        done
    done
}

## Dry Run Updates
dry_run_updates() {
    echo -e "${GREEN}Performing a dry run of APT updates...${NC}"
    sudo apt update
    sudo apt upgrade --simulate
    sudo apt autoremove --simulate
    echo -e "${GREEN}Dry run completed.${NC}"
}

## Check for Release Upgrades
check_release_upgrades() {
    echo -e "${GREEN}Checking for release upgrades...${NC}"
    if command -v pop-upgrade >/dev/null 2>&1; then
        sudo pop-upgrade release check
        read -p "Perform the release upgrade now? (y/N): " upgrade
        if [[ $upgrade =~ ^[Yy]$ ]]; then
            sudo pop-upgrade release upgrade
        else
            echo "Release upgrade cancelled."
        fi
    else
        echo "pop-upgrade is not available."
    fi
}

## Reboot System
reboot_system() {
    read -p "Are you sure you want to reboot? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Rebooting the system...${NC}"
        sudo reboot
    else
        echo "Reboot cancelled."
    fi
}

## Shutdown System
shutdown_system() {
    read -p "Are you sure you want to shut down? (y/N): " confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Shutting down the system...${NC}"
        sudo shutdown now
    else
        echo "Shutdown cancelled."
    fi
}

## Parse Command-Line Arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --silent) SILENT_MODE=1; shift ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# Main Menu
if [ $SILENT_MODE -eq 0 ]; then
    while true; do
        clear
        echo "Welcome to the Pop!_OS Maintenance Script"
        echo "Please select an option:"
        options=(
            "Apply All Updates" "Config New Install" "System Health Check" "Backup System" 
            "Manage Flatpaks" "Manage Snaps" "Manage Cron Jobs" "Disk Cleanup" 
            "Dry Run Updates" "Check for Release Upgrades" "Install and Configure Apps" 
            "Security Checks" "Reboot System" "Shutdown System" "Exit"
        )
        select opt in "${options[@]}"; do
            case $opt in
                "Apply All Updates") apply_updates; read -p "Press Enter to continue..."; break ;;
                "Config New Install") config_new_install; read -p "Press Enter to continue..."; break ;;
                "System Health Check") check_system_health; read -p "Press Enter to continue..."; break ;;
                "Backup System") backup_system; read -p "Press Enter to continue..."; break ;;
                "Manage Flatpaks") manage_flatpaks; read -p "Press Enter to continue..."; break ;;
                "Manage Snaps") manage_snaps; read -p "Press Enter to continue..."; break ;;
                "Manage Cron Jobs") manage_cron_jobs; read -p "Press Enter to continue..."; break ;;
                "Disk Cleanup") disk_cleanup; read -p "Press Enter to continue..."; break ;;
                "Dry Run Updates") dry_run_updates; read -p "Press Enter to continue..."; break ;;
                "Check for Release Upgrades") check_release_upgrades; read -p "Press Enter to continue..."; break ;;
                "Install and Configure Apps") install_and_configure_apps; break ;;
                "Security Checks") security_checks; read -p "Press Enter to continue..."; break ;;
                "Reboot System") reboot_system; break ;;
                "Shutdown System") shutdown_system; break ;;
                "Exit") echo -e "${GREEN}Exiting the script. Goodbye!${NC}"; exit 0 ;;
                *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
            esac
        done
    done
else
    echo -e "${GREEN}Running in silent mode...${NC}"
    apply_updates
    disk_cleanup
    security_checks
    backup_system
    check_release_upgrades
    echo -e "${GREEN}Silent maintenance completed.${NC}"
fi
