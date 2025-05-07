#!/bin/bash

# Colors for output readability
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Global variables
SILENT_MODE=0
LOG_FILE="/var/log/popos_maintenance.log"

# Helper function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | sudo tee -a "$LOG_FILE" > /dev/null
    if [ $SILENT_MODE -eq 0 ]; then
        echo -e "$message"
    fi
}

# Check Internet Connectivity
check_internet() {
    log_message "${GREEN}Checking internet connectivity...${NC}"
    if ping -q -c 1 -W 1 google.com >/dev/null; then
        log_message "${GREEN}Internet is available.${NC}"
    else
        log_message "${RED}No internet connection. Please check your connection and try again.${NC}"
        exit 1
    fi
}

# Apply All Updates
apply_updates() {
    log_message "${GREEN}Applying all updates...${NC}"
    check_internet
    log_message "Updating APT packages..."
    sudo apt update || { log_message "${RED}APT update failed.${NC}"; return 1; }
    sudo apt upgrade -y || { log_message "${RED}APT upgrade failed.${NC}"; return 1; }
    sudo apt full-upgrade -y || { log_message "${RED}APT full-upgrade failed.${NC}"; return 1; }
    sudo apt autoremove -y || { log_message "${RED}APT autoremove failed.${NC}"; return 1; }
    sudo apt autoclean -y || { log_message "${RED}APT autoclean failed.${NC}"; return 1; }

    if command -v flatpak >/dev/null 2>&1; then
        log_message "Updating Flatpak packages..."
        sudo flatpak update -y || log_message "${YELLOW}Flatpak update failed.${NC}"
    fi

    if command -v fwupdmgr >/dev/null 2>&1; then
        log_message "Updating firmware..."
        sudo fwupdmgr refresh || log_message "${YELLOW}Firmware refresh failed.${NC}"
        sudo fwupdmgr update -y || log_message "${YELLOW}Firmware update failed.${NC}"
    fi

    if command -v pop-upgrade >/dev/null 2>&1; then
        log_message "Updating system & recovery partition..."
        sudo pop-upgrade release upgrade || log_message "${YELLOW}System upgrade failed.${NC}"
        sudo pop-upgrade recovery upgrade from-release || log_message "${YELLOW}Recovery upgrade failed.${NC}"
    fi
    log_message "${GREEN}Updates completed successfully.${NC}"
}

# Config New Install
config_new_install() {
    log_message "${GREEN}Configuring new Pop!_OS installation...${NC}"
    check_internet

    log_message "Updating system..."
    sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean

    log_message "Installing Lynis..."
    sudo apt install -y lynis || { log_message "${RED}Failed to install Lynis.${NC}"; return 1; }

    log_message "Creating custom Lynis profile..."
    sudo mkdir -p /etc/lynis
    cat << EOF | sudo tee /etc/lynis/custom.prf > /dev/null
colors=yes
machine-role=personal
profile-name=Default Audit Template
pause-between-tests=0
quick=yes
refresh-repositories=yes
show-report-solution=yes
show-tool-tips=yes
skip-plugins=no
skip-test ACCT-9622
skip-test FILE-6310
skip-test FIRE-4510
skip-test HTTP-6622
skip-test HTTP-6640
skip-test HTTP-6660
skip-test DBS-1808
skip-test NETW-3200
skip-test NETW-3032
skip-test SSH-7408
skip-test SQUID-3602
skip-test STRG-1840
test-scan-mode=full
verbose=no
plugin=authentication
plugin=control-panels
plugin=dns
plugin=docker
plugin=file-integrity
plugin=file-systems
plugin=firewalls
plugin=hardware
plugin=kernel
plugin=malware
plugin=security-modules
plugin=software
plugin=system-integrity
plugin=systemd
plugin=users
upload=no
config-data=sysctl;fs.suid_dumpable;0;1;Restrict core dumps;sysctl -a;url:https://www.kernel.org/doc/Documentation/sysctl/fs.txt;category:security;
config-data=sysctl;fs.protected_fifos;2;1;Restrict FIFO special device creation behavior;sysctl -a;url:https://www.kernel.org/doc/Documentation/sysctl/fs.txt;category:security;
config-data=sysctl;fs.protected_hardlinks;1;1;Restrict hardlink creation behavior;sysctl -a;url:https://www.kernel.org/doc/Documentation/sysctl/fs.txt;category:security;
config-data=sysctl;fs.protected_regular;2;1;Restrict regular files creation behavior;sysctl -a;url:https://www.kernel.org/doc/Documentation/sysctl/fs.txt;category:security;
config-data=sysctl;fs.protected_symlinks;1;1;Restrict symlink following behavior;sysctl -a;url:https://www.kernel.org/doc/Documentation/sysctl/fs.txt;category:security;
config-data=sysctl;kernel.core_uses_pid;1;1;No description;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.dmesg_restrict;1;1;Restrict use of dmesg;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.kptr_restrict;2;1;Restrict access to kernel symbols;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.perf_event_paranoid;3;1;Restrict unprivileged access to the perf_event_open() system call.;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.randomize_va_space;2;1;Randomize of memory address locations (ASLR);sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.suid_dumpable;0;1;Restrict core dumps;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.sysrq;0;1;Disable magic SysRQ;sysctl -a;url:https://kernel.org/doc/Documentation/sysctl/kernel.txt;category:security;
config-data=sysctl;kernel.yama.ptrace_scope;1;1;Disable process tracing for everyone;-;category:security;
config-data=sysctl;net.ipv4.conf.all.accept_redirects;0;1;Disable/Ignore ICMP routing redirects;-;category:security;
config-data=sysctl;net.ipv4.conf.all.accept_source_route;0;1;Disable IP source routing;-;category:security;
config-data=sysctl;net.ipv4.conf.all.forwarding;0;1;Disable IP source routing;-;category:security;
config-data=sysctl;net.ipv4.conf.all.log_martians;1;1;Log all packages for which the host does not have a path back to the source;-;category:security;
config-data=sysctl;net.ipv4.conf.all.rp_filter;1;1;Enforce ingress/egress filtering for packets;-;category:security;
config-data=sysctl;net.ipv4.conf.all.send_redirects;0;1;Disable/Ignore ICMP routing redirects;-;category:security;
config-data=sysctl;net.ipv4.conf.default.accept_redirects;0;1;Disable/Ignore ICMP routing redirects;-;category:security;
config-data=sysctl;net.ipv4.conf.default.accept_source_route;0;1;Disable IP source routing;-;category:security;
config-data=sysctl;net.ipv4.conf.default.log_martians;1;1;Log all packages for which the host does not have a path back to the source;-;category:security;
config-data=sysctl;net.ipv4.icmp_echo_ignore_broadcasts;1;1;Ignore ICMP packets directed to broadcast address;-;category:security;
config-data=sysctl;net.ipv4.icmp_ignore_bogus_error_responses;1;1;Ignore;-;category:security;
config-data=sysctl;net.ipv4.tcp_syncookies;1;1;Use SYN cookies to prevent SYN attack;-;category:security;
config-data=sysctl;net.ipv6.conf.all.accept_redirects;0;1;Disable/Ignore ICMP routing redirects;-;category:security;
config-data=sysctl;net.ipv6.conf.all.accept_source_route;0;1;Disable IP source routing;-;category:security;
config-data=sysctl;net.ipv6.conf.all.forwarding;0;1;Do not allow forwarding of traffic;-;category:security;
config-data=sysctl;net.ipv6.conf.default.accept_redirects;0;1;Disable/Ignore ICMP routing redirects;-;category:security;
config-data=sysctl;net.ipv6.conf.default.accept_source_route;0;1;Disable IP source routing;-;category:security;
EOF
    [ -f /etc/lynis/custom.prf ] || { log_message "${RED}Failed to create Lynis profile.${NC}"; return 1; }

    log_message "Updating Lynis signatures..."
    sudo lynis update info

    log_message "Running Lynis audit..."
    sudo lynis audit system --profile /etc/lynis/custom.prf || log_message "${YELLOW}Lynis audit failed.${NC}"

    log_message "Hardening ulimit and core dumps..."
    echo "ulimit -c 0" | sudo tee -a /etc/profile
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf

    log_message "Applying kernel protections..."
    sudo sysctl -w kernel.unprivileged_userns_clone=0
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    echo "kernel.unprivileged_userns_clone=0" | sudo tee -a /etc/sysctl.d/99-hardening.conf
    echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.d/99-hardening.conf
    sudo sysctl -p

    log_message "Setting sudo timeout to 5 minutes..."
    echo "Defaults timestamp_timeout=5" | sudo tee /etc/sudoers.d/timeout

    log_message "Securing /tmp with tmpfs..."
    echo "tmpfs /tmp tmpfs nosuid,nodev,noexec 0 0" | sudo tee -a /etc/fstab
    sudo mount -a || log_message "${YELLOW}Warning: /tmp mount failed. Check /etc/fstab.${NC}"

    log_message "Securing home directory..."

    chmod 700 /home/$USER

    log_message "Configuring firewall..."
    sudo apt install -y ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow from 192.168.1.0/24 to any port 137,138 proto udp
    sudo ufw allow from 192.168.1.0/24 to any port 139,445 proto tcp
    sudo ufw logging medium
    sudo ufw enable

    log_message "Disabling IPv6..."
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    log_message "Hardening SSH..."
    sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd

    log_message "Disabling Avahi daemon..."
    sudo systemctl disable avahi-daemon && sudo systemctl stop avahi-daemon

    log_message "Disabling Pop!_OS telemetry..."
    sudo systemctl disable pop-hw-probe && sudo systemctl mask pop-hw-probe

    log_message "Configuring NextDNS..."
    sudo mkdir -p /etc/systemd/resolved.conf.d
    cat << EOF | sudo tee /etc/systemd/resolved.conf.d/nextdns.conf
[Resolve]
DNS=45.90.28.0#2ce3b7.dns.nextdns.io
DNS=2a07:a8c0::#2ce3b7.dns.nextdns.io
DNS=45.90.30.0#2ce3b7.dns.nextdns.io
DNS=2a07:a8c1::#2ce3b7.dns.nextdns.io
Domains=~.
DNSOverTLS=yes
EOF
    sudo systemctl restart systemd-resolved

    log_message "Configuring NTP..."
    sudo sed -i 's/#NTP=/NTP=pool.ntp.org/' /etc/systemd/timesyncd.conf
    sudo systemctl restart systemd-timesyncd

    log_message "${GREEN}New install configuration completed.${NC}"
}

# System Health Check
check_system_health() {
    log_message "${GREEN}System Health Check:${NC}"
    log_message "Load Average:"; uptime
    log_message "Disk Usage:"; df -h | grep '^/dev'
    log_message "Memory Usage:"; free -h
    log_message "Top 5 Memory-Intensive Processes:"; ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 6
    log_message "Failed Systemd Services:"; systemctl --failed
    log_message "${GREEN}System health check completed.${NC}"
}

# Backup System
backup_system() {
    log_message "${GREEN}Creating a backup of your home directory...${NC}"
    BACKUP_DIR=~/backups/$(date +'%Y-%m-%d_%H%M%S')
    mkdir -p "$BACKUP_DIR" || { log_message "${RED}Failed to create backup directory.${NC}"; return 1; }
    tar -czvf "$BACKUP_DIR/home_backup.tar.gz" ~ --exclude="$BACKUP_DIR" || { log_message "${RED}Backup failed.${NC}"; return 1; }
    log_message "${GREEN}Backup completed: $BACKUP_DIR/home_backup.tar.gz${NC}"
}

# Manage Flatpaks
manage_flatpaks() {
    log_message "${GREEN}Flatpak Options:${NC}"
    echo "1) List Installed Flatpaks"; echo "2) Uninstall a Flatpak"; echo "3) Update Flatpaks"
    read -p "Choose an option: " choice
    case $choice in
        1) flatpak list ;;
        2) read -p "Enter the Flatpak ID to uninstall: " flatpak_id; flatpak uninstall "$flatpak_id" -y ;;
        3) flatpak update -y ;;
        *) log_message "${RED}Invalid option.${NC}" ;;
    esac
}

# Manage Cron Jobs
manage_cron_jobs() {
    log_message "${GREEN}Cron Job Management:${NC}"
    echo "1) View Current Cron Jobs"; echo "2) Remove a Cron Job"
    read -p "Choose an option: " choice
    case $choice in
        1) crontab -l ;;
        2) echo "Current Cron Jobs:"; crontab -l | nl; read -p "Enter the line number to remove: " line; crontab -l | sed "${line}d" | crontab -; log_message "${GREEN}Cron job removed.${NC}" ;;
        *) log_message "${RED}Invalid option.${NC}" ;;
    esac
}

# Disk Cleanup
disk_cleanup() {
    log_message "${GREEN}Performing disk cleanup...${NC}"
    sudo apt autoclean -y || log_message "${YELLOW}APT autoclean failed.${NC}"
    sudo apt autoremove -y || log_message "${YELLOW}APT autoremove failed.${NC}"
    sudo rm -rf ~/.cache/* || log_message "${YELLOW}Cache cleanup failed.${NC}"
    sudo journalctl --vacuum-time=30d || log_message "${YELLOW}Journal cleanup failed.${NC}"
    log_message "${GREEN}Disk cleanup completed.${NC}"
}

# Security Checks
security_checks() {
    log_message "${GREEN}Performing security checks...${NC}"
    log_message "Firewall Status:"; sudo ufw status || log_message "${YELLOW}UFW not installed.${NC}"
    log_message "Open Ports:"; sudo ss -tuln || sudo netstat -tuln
    log_message "World-Writable Files:"; find / -xdev -type f -perm -o+w -print 2>/dev/null | head -n 10
    log_message "${GREEN}Security checks completed.${NC}"
}

# Install and Configure Apps
install_and_configure_apps() {
    log_message "${GREEN}Installing and configuring apps...${NC}"
    if ! command -v flatpak >/dev/null 2>&1; then
        read -p "Flatpak is not installed. Install it? (y/N): " install_flatpak
        if [[ $install_flatpak =~ ^[Yy]$ ]]; then
            sudo apt install -y flatpak || { log_message "${RED}Failed to install Flatpak.${NC}"; return 1; }
            flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
        fi
    fi
    for cmd in wget unzip curl; do
        if ! command -v $cmd >/dev/null 2>&1; then
            sudo apt install -y $cmd || { log_message "${RED}Failed to install $cmd.${NC}"; return 1; }
        fi
    done

    while true; do
        clear
        log_message "Select an app to install and configure:"
        options=(
            "Brave" "BleachBit" "Cryptomator" "Element" "GIMP" "Grayjay" "Jitsi Meet" "KeepassXC" 
            "LibreWolf" "Nextcloud Client" "Obsidian" "Proton Pass" "Proton VPN" "Shortwave" 
            "Signal" "Standard Notes" "Syncthing" "Terminator" "Thunderbird" "Tor Browser" 
            "VLC" "VScodium" "Back to Main Menu"
        )
        select opt in "${options[@]}"; do
            case $opt in
                "Brave")
                    log_message "Installing Brave..."
                    if dpkg -l | grep -q brave-browser; then
                        log_message "Brave already installed."
                    else
                        sudo curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
                        echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main" | sudo tee /etc/apt/sources.list.d/brave-browser-release.list
                        sudo apt update && sudo apt install -y brave-browser || log_message "${RED}Brave installation failed.${NC}"
                        log_message "Brave installed. Disable Brave Rewards in settings for max privacy."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "BleachBit")
                    log_message "Installing BleachBit..."
                    if dpkg -l | grep -q bleachbit; then
                        log_message "BleachBit already installed."
                    else
                        sudo apt install -y bleachbit || log_message "${RED}BleachBit installation failed.${NC}"
                        log_message "BleachBit installed. Run 'bleachbit' and enable shredding."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Cryptomator")
                    log_message "Installing Cryptomator..."
                    if flatpak list | grep -q org.cryptomator.Cryptomator; then
                        log_message "Cryptomator already installed."
                    else
                        flatpak install -y flathub org.cryptomator.Cryptomator || log_message "${RED}Cryptomator installation failed.${NC}"
                        log_message "Cryptomator installed. Create an encrypted vault."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Element")
                    log_message "Installing Element..."
                    if flatpak list | grep -q im.riot.Riot; then
                        log_message "Element already installed."
                    else
                        flatpak install -y flathub im.riot.Riot || log_message "${RED}Element installation failed.${NC}"
                        log_message "Element installed. Sign in or create a Matrix account."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "GIMP")
                    log_message "Installing GIMP..."
                    if dpkg -l | grep -q gimp; then
                        log_message "GIMP already installed."
                    else
                        sudo apt install -y gimp || log_message "${RED}GIMP installation failed.${NC}"
                        log_message "GIMP installed."
                    fi
                    [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                    break
                    ;;
                "Grayjay")
                    log_message "Installing Grayjay..."
                    install_dir="$HOME/.local/opt/Grayjay"
                    if [ -f "$install_dir/Grayjay" ]; then
                        read -p "Grayjay is already installed at $install_dir. Overwrite? (y/N): " overwrite
                        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
                            log_message "Installation skipped."
                            [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."
                            break
                        fi
                        rm -rf "$install_dir"
                    fi

                    wget "https://updater.grayjay.app/Apps/Grayjay.Desktop/Grayjay.Desktop-linux-x64.zip" -O /tmp/Grayjay.zip || {
                        log_message "${RED}Download failed.${NC}"
                        break
                    }
                    unzip /tmp/Grayjay.zip -d /tmp/Grayjay-tmp || {
                        log_message "${RED}Extraction failed.${NC}"
                        rm -f /tmp/Grayjay.zip
                        break
                    }
                    version_dir=$(ls /tmp/Grayjay-tmp | grep "Grayjay.Desktop-linux-x64")
                    mkdir -p "$install_dir"
                    mv /tmp/Grayjay-tmp/"$version_dir"/* "$install_dir" || {
                        log_message "${RED}Failed to move files.${NC}"
                        rm -rf /tmp/Grayjay-tmp /tmp/Grayjay.zip
                        break
                    }
                    chmod +x "$install_dir/Grayjay"
                    mkdir -p "$HOME/.local/bin"
                    cat > "$HOME/.local/bin/grayjay" << EOL
#!/bin/bash
cd $install_dir && ./Grayjay
EOL
                    chmod +x "$HOME/.local/bin/grayjay"
                    sudo rm -f /usr/local/bin/grayjay
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
                    rm -rf /tmp/Grayjay.zip /tmp/Grayjay-tmp || log_message "${YELLOW}Cleanup failed.${NC}"
                    log_message "Grayjay installed in $install_dir. Launch from menu or 'grayjay'."
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

# Dry Run Updates
dry_run_updates() {
    log_message "${GREEN}Performing a dry run of APT updates...${NC}"
    sudo apt update
    sudo apt upgrade --simulate
    sudo apt autoremove --simulate
    log_message "${GREEN}Dry run completed.${NC}"
}

# Check for Release Upgrades
check_release_upgrades() {
    log_message "${GREEN}Checking for release upgrades...${NC}"
    if command -v pop-upgrade >/dev/null 2>&1; then
        sudo pop-upgrade release check
        read -p "Perform the release upgrade now? (y/N): " upgrade
        if [[ $upgrade =~ ^[Yy]$ ]]; then
            sudo pop-upgrade release upgrade
        else
            log_message "Release upgrade cancelled."
        fi
    else
        log_message "pop-upgrade is not available."
    fi
}

# Parse Command-Line Arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --silent) SILENT_MODE=1; shift ;;
        *) log_message "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# Main Menu
if [ $SILENT_MODE -eq 0 ]; then
    while true; do
        clear
        log_message "Welcome to the Pop!_OS Maintenance Script"
        echo "Please select an option:"
        options=(
            "Apply All Updates" "Config New Install" "System Health Check" "Backup System" 
            "Manage Flatpaks" "Manage Cron Jobs" "Disk Cleanup" 
            "Dry Run Updates" "Check for Release Upgrades" "Install and Configure Apps" 
            "Security Checks" "Exit"
        )
        select opt in "${options[@]}"; do
            case $opt in
                "Apply All Updates") apply_updates; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Config New Install") config_new_install; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "System Health Check") check_system_health; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Backup System") backup_system; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Manage Flatpaks") manage_flatpaks; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Manage Cron Jobs") manage_cron_jobs; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Disk Cleanup") disk_cleanup; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Dry Run Updates") dry_run_updates; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Check for Release Upgrades") check_release_upgrades; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Install and Configure Apps") install_and_configure_apps; break ;;
                "Security Checks") security_checks; [ $SILENT_MODE -eq 0 ] && read -p "Press Enter to continue..."; break ;;
                "Exit") log_message "${GREEN}Exiting the script. Goodbye!${NC}"; exit 0 ;;
                *) log_message "${RED}Invalid option.${NC}" ;;
            esac
        done
    done
else
    log_message "${GREEN}Running in silent mode...${NC}"
    apply_updates
    disk_cleanup
    security_checks
    backup_system
    check_release_upgrades
    log_message "${GREEN}Silent maintenance completed.${NC}"
fi
