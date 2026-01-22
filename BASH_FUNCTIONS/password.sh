# Password spraying
wordgen(){
    echo -e "\nGENERATING USERNAMES/PASSWORDS\n"
    cewl $1 -d 2 -m 4 --lowercase --with-numbers -w /tmp/tmp.txt && cat /tmp/tmp.txt | anew -q wordlist_custom.txt
    rm /tmp/tmp.txt
}

# Usernames Generation
usergen(){
    echo -e "\nGENERATING USERNAMES\n"
    /home/damuna/tools/username-anarchy/username-anarchy -i $1 > gen_users.txt
}

# Hashcat cracking
hashcrack() {
    local hash_file="$1"
    local wordlist="${2:-$HOME/wordlists/rockyou.txt}"

    if [[ -z "$hash_file" ]]; then
        echo "[!] Error: You must provide a hash file." >&2
        echo "Usage: hashcrack <hash_file> [wordlist_file]" >&2
        return 1
    fi
    if [[ ! -f "$hash_file" ]]; then
        echo "[!] Error: Hash file not found at '$hash_file'" >&2
        return 1
    fi
    if [[ ! -f "$wordlist" ]]; then
        echo "[!] Error: Wordlist not found at '$wordlist'" >&2
        return 1
    fi

    echo "[*] Getting hash mode suggestions or cracking directly using hashcat..."
    local suggested_modes_string
    suggested_modes_string=$(hashcat "$hash_file" "$wordlist" 2>&1 | grep -oE '^[[:space:]]*[0-9]+' | tr -d ' ' | paste -sd ' ' -)

    if [[ -z "$suggested_modes_string" ]]; then
        echo "[!] No hash mode suggestions found. Please check your hash file or hashcat's output." >&2
        return 1
    fi

    local modes_array=("${(@s/ /)suggested_modes_string}")
    if [[ -n "$BASH_VERSION" ]]; then
      read -r -a modes_array <<< "$suggested_modes_string"
    fi

    echo "[*] Found suggested hash modes to try: ${modes_array[*]}"
    
    for mode in "${modes_array[@]}"; do
        echo
        echo "============================================================"
        echo "[*] Trying hash mode: $mode"
        echo "============================================================"

        /home/damuna/tools/HASHCAT/hashcat-7.1.2/hashcat.bin -m "$mode" "$hash_file" "$wordlist" --force

        local cracked
        cracked=$(hashcat -m "$mode" --show "$hash_file")

        if [[ -n "$cracked" ]]; then
            echo
            echo "[+] SUCCESS! Hash cracked with mode: $mode"
            echo "[+] Cracked hash(es):"
            echo "$cracked"
            return 0
        else
            echo "[-] Hash not cracked with mode: $mode. Trying next mode..."
        fi
    done

    echo
    echo "[!] Exhausted all suggested hash modes. The hash could not be cracked with the provided wordlist."
    return 1
}

# Default credentials for services / applications
searchpass(){
    pass-station search $1
}
