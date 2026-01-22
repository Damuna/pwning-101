# vhd vmsk vhdx Mounter
vhdMount() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: vhdMount <File>"
        echo "To unmount: vhdMount -u"
        return 1
    fi

    if [[ "$1" == "-u" ]]; then
        echo "Unmounting VHD..."
        sudo umount /mnt/my_vhs 2>/dev/null
        sudo vgchange -an 2>/dev/null
        sudo kpartx -d /dev/nbd0 2>/dev/null
        sudo qemu-nbd -d /dev/nbd0 2>/dev/null
        sudo rmmod nbd 2>/dev/null
        sudo rm -f /var/lock/qemu-nbd-nbd0 2>/dev/null
        echo "Unmount complete"
        return 0
    fi

    echo "Mounting VHD: $1"
    
    sudo umount /mnt/my_vhs 2>/dev/null
    sudo vgchange -an 2>/dev/null
    sudo kpartx -d /dev/nbd0 2>/dev/null
    sudo qemu-nbd -d /dev/nbd0 2>/dev/null
    sudo rmmod nbd 2>/dev/null
    sudo rm -f /var/lock/qemu-nbd-nbd0 2>/dev/null
    
    sudo mkdir -p /mnt/my_vhs
    sudo modprobe nbd max_part=16
    
    if ! sudo qemu-nbd -r --connect=/dev/nbd0 "$1"; then
        echo "Failed to connect to NBD device"
        echo "Trying alternative approach..."
        sudo qemu-nbd -r -c /dev/nbd0 "$1" || {
            echo "Error: Could not connect $1 to /dev/nbd0"
            return 1
        }
    fi
    
    sleep 2
    
    if [[ ! -b /dev/nbd0 ]]; then
        echo "Error: /dev/nbd0 block device not created"
        return 1
    fi
    
    if ! sudo kpartx -av /dev/nbd0; then
        echo "Error: Failed to create partition mappings"
        sudo qemu-nbd -d /dev/nbd0
        return 1
    fi
    
    sleep 2
    
    if [[ -b /dev/mapper/nbd0p1 ]]; then
        if sudo mount -t ntfs-3g /dev/mapper/nbd0p1 /mnt/my_vhs 2>/dev/null; then
            echo "Successfully mounted to /mnt/my_vhs"
            return 0
        else
            echo "Mount failed, trying alternative methods..."
            if sudo mount -t ntfs-3g -o ro /dev/mapper/nbd0p1 /mnt/my_vhs 2>/dev/null; then
                echo "Mounted as read-only to /mnt/my_vhs"
                return 0
            fi
        fi
    fi
    
    echo "Could not automatically mount partition."
    echo "Available devices:"
    ls /dev/nbd0* /dev/mapper/nbd0* 2>/dev/null || echo "No devices found"
    
    echo "You can try mounting manually with:"
    echo "sudo mount -t ntfs-3g /dev/mapper/nbd0pX /mnt/my_vhs"
    echo "Or for read-only access:"
    echo "sudo mount -t ntfs-3g -o ro /dev/mapper/nbd0pX /mnt/my_vhs"
    return 1
}

# Bitlocker Mounting
bitmount(){
    if [[ $# -eq 0 ]]; then
        echo -e "\nUsage: bitmount [FILE] [PWD]\n"
        return 1
    fi
    echo -e "\nCLEANING UP PREVIOUS DISKS\n"
    sudo rm -rf /media/bitlocker /media/bitlockermount
    for loop_device in $(losetup --all | grep "$1" | cut -d ':' -f 1)
    do
        echo "Detaching ${loop_device}..."
        sudo losetup -d "${loop_device}"
    done

    echo -e "\nMOUNTING \"$1\" WITH PASSWORD \"$2\"\n"
    sudo mkdir -p /media/bitlocker; sudo mkdir -p /media/bitlockermount
    sudo losetup -f -P $1
    disk=$(losetup --all | grep "$1" | awk '{print $1}' | head -n 1 | tr -d ':')
    sudo dislocker ${disk}p1 -u$2 -- /media/bitlocker
    sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

    echo -e "\nCD AND LISTING CONTENT\n"
    cd /media/bitlockermount && sudo ls -la .
}


# PFX Certificate & Key extraction
pfx2key(){
    filename=$(echo $1)
    echo "pfx2key <pfx_file>\n"
    openssl pkcs12 -in $1 -clcerts -nokeys -out "${filename%.*}.crt"
    openssl pkcs12 -in $1 -nocerts -out /tmp/out.enc
    openssl rsa -in /tmp/out.enc -out "${filename%.*}.key"; rm /tmp/out.enc
    echo "\n SAVED ${filename%.*}.key and ${filename%.*}.crt"
}

# SMB share mount
smbmount() {
    local ip="" user="" pass="" share=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--user)
                user="$2"
                shift 2
                ;;
            -p|--pass)
                pass="$2"
                shift 2
                ;;
            *)
                if [[ -z "$ip" ]]; then
                    ip="$1"
                else
                    echo "Unknown argument: $1"
                    return 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$ip" ]]; then
        echo "Usage: smbmount <IP> -u <user> -p <pass>"
        return 1
    fi

    vared -p "Select a share to mount: " -c share

    local mount_point="/mnt/$share"
    sudo mkdir -p "$mount_point"
    sudo mount -t cifs "//$ip/$share" "$mount_point" -o username="$user",password="$pass"

    if mount | grep -q "$mount_point"; then
        echo "Successfully mounted //$ip/$share at $mount_point"
        cd $mount_point
    else
        echo "Failed to mount //$ip/$share"
        return 1
    fi
}

# Mount nfs share
nfsmount(){
    if [[ -z "$1" ]]; then
        echo "Usage: nfsmount <IP> {<PORT>}"
        return 1
    fi
    
    read -r shr\?"Enter share path: "
    
    if [[ -z "$2" ]]; then
        sudo mkdir -p /mnt/$1$shr && sudo mount -t nfs -o nolock $1:$shr /mnt/$1$shr && sudo ls -la /mnt/$1$shr
    else
        sudo mkdir -p /mnt/$1$shr && sudo mount -t nfs -o nolock -o port=$2 $1:$shr /mnt/$1$shr && sudo ls -la /mnt/$1$shr
    fi
    
    echo -e "\nCOPYING CONTENT INTO \"$1_$(echo $shr | tr '/' '_')\"\n"
    sudo cp -r /mnt/$1$shr ./$1$(echo $shr | tr '/' '_')
    sudo chmod -R +r ./$1$(echo $shr | tr '/' '_')
    cd ./$1$(echo $shr | tr '/' '_')
}

# SMB File Upload
llmnr() {
    if [ $# -lt 4 ]; then
        echo "Usage: smb_upload <server> <share> <username> <password> [file|directory|pattern]"
        echo "Examples:"
        echo "  smb_upload 10.10.11.69 IT j.fleischman 'password'          # Upload all files in current dir"
        echo "  smb_upload 10.10.11.69 IT j.fleischman 'password' exploit.zip  # Upload specific file"
        echo "  smb_upload 10.10.11.69 IT j.fleischman 'password' *.txt    # Upload all txt files"
        echo "  smb_upload 10.10.11.69 IT j.fleischman 'password' ./path   # Upload all files in ./path"
        return 1
    fi
    
    local server="$1"
    local share="$2"
    local username="$3"
    local auth="$4"
    local target="${5:-*}"
    local success_count=0
    local fail_count=0
    
    echo "Connecting to //$server/$share..."
    
    local auth_options=(-U "$username%$auth")
    if [[ "$auth" == *":"* ]]; then
        auth_options=(--pw-nt-hash -U "$username%$auth")
    fi
    
    if [ "$target" = "*" ]; then
        echo "Uploading all files from current directory: $(pwd)"
        for file in *; do
            if [ -f "$file" ]; then
                echo -n "Uploading $file... "
                if smbclient "//$server/$share" "${auth_options[@]}" -c "put \"$file\"" 2>/dev/null; then
                    echo "✓"
                    ((success_count++))
                else
                    echo "✗"
                    ((fail_count++))
                fi
            fi
        done
    elif [ -f "$target" ]; then
        echo "Uploading specific file: $target"
        echo -n "Uploading $(basename "$target")... "
        if smbclient "//$server/$share" "${auth_options[@]}" -c "put \"$target\"" 2>/dev/null; then
            echo "✓"
            ((success_count++))
        else
            echo "✗"
            ((fail_count++))
        fi
    elif [ -d "$target" ]; then
        echo "Uploading all files from directory: $target"
        for file in "$target"/*; do
            if [ -f "$file" ]; then
                echo -n "Uploading $(basename "$file")... "
                if smbclient "//$server/$share" "${auth_options[@]}" -c "put \"$file\"" 2>/dev/null; then
                    echo "✓"
                    ((success_count++))
                else
                    echo "✗"
                    ((fail_count++))
                fi
            fi
        done
    else
        echo "Uploading files matching pattern: $target"
        for file in $target; do
            if [ -f "$file" ]; then
                echo -n "Uploading $file... "
                if smbclient "//$server/$share" "${auth_options[@]}" -c "put \"$file\"" 2>/dev/null; then
                    echo "✓"
                    ((success_count++))
                else
                    echo "✗"
                    ((fail_count++))
                fi
            fi
        done
    fi
    
    echo "Upload complete: $success_count successful, $fail_count failed"
    return $fail_count
}
