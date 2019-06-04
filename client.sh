#!/bin/bash
# -*- coding: utf-8 -*-
# @author: FBK CyberSecurity [ by Andrey Skuratov]
# @contact: https://fbkcs.ru
# @license Apache License, Version 2.0
# Copyright (C) 2018


# This is a Bash client for ThunderDNS tool.
# It can forward TCP traffic over DNS protocol.


# Rebind KeyboardInterrupt
trap 'echo; echo Exiting...; delete ${id}; echo Bye!; exit 1' 2

# Check if any excess argument provided
check_args () {
	if [[ $OPTARG =~ ^- ]]
		then
		echo "Unknow argument $OPTARG for option $opt!"
		exit 1
	fi
}

# Prints logo
echo_logo ()
{
	echo ' ________________               _________         _______________   _________'
	echo ' ___/__  __/__/ /_____  ______________/ /______________/ __ \__/ | / //_ ___/'
	echo ' _____/ /____/ __ \  / / /_/ __ \/ __  /_/ _ \_/ __/ _/ / / /_/  |/ //____ \ '
	echo ' ____/ /____/ / / / /_/ /_  / / / /_/ / /  __// /  __/ /_/ /_/ /|  / ____/ / '
	echo ' ___/_/____/_/ /_/\__,_/ /_/ /_/\__,_/__\___//_/  __/_____/ /_/ |_/ /_____/  '
	echo ''
	echo "Usage: $0 [options]"
	echo ''
}

# Generates random N-chars
generate_random()
{
	cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $1 | head -n 1
}

# Register client
register()
{
	dig ${HOST} 0$(generate_random 7)$1.${DNS_DOMAIN} TXT | grep -oP '\"\K[^\"]+'
}

# Cuts text data from dig result
get_data()
{
    dig ${HOST} 1$(generate_random 7)$1.${DNS_DOMAIN} TXT | grep -oP '\"\K[^\"]+'|sed ':a;N;$!ba;s/\n//g' | tr -d ' '
}

# Removes client
delete()
{
	del_data=$(dig ${HOST} 3$(generate_random 7)$1.${DNS_DOMAIN} TXT | grep -oP '\"\K[^\"]+')
	if [[ ${del_data:0:2} = $1 ]] && [[ ${del_data:2} = 'REMOVED' ]]
		then
		echo "Client '${CLIENT_NAME}' with ID:${id} was removed"
	fi
}

# Some debug emulator
debug_echo ()
{
  [[ "$DEBUG" ]] && echo $@
}

# Send data to DNS
reply()
{
    response=$(timeout 0.1 dd bs=2048 count=1 <&3 2> /dev/null | base64 -w0)
    echo $response
    if [[ $response != '' ]]
        then
        debug_echo 'Got response from target server '
        response_len=${#response}
        number_of_blocks=$(( ${response_len} / ${MESSAGE_LEN}))

        if [[ $(($response_len % $MESSAGE_LEN)) = 0 ]]
        	then
        	number_of_blocks=$((number_of_blocks-1))
        fi

        debug_echo 'Sending message back...'
        point=0

        for ((i=$number_of_blocks;i>=0;i--))
        do
        	blocks_data=${response:$point:$MESSAGE_LEN}

        	if [[ ${#blocks_data} -gt 63 ]]
        		then
        		localpoint=0

        		while :
        		do
        			block=${blocks_data:localpoint:63}

        			if [[ $block != '' ]]
        				then
	        			dat+=$block.
	        			localpoint=$((localpoint + 63))
	        		else
	        			break
	        		fi

        		done

        		blocks_data=$dat
        		dat=''
        		point=$((point + MESSAGE_LEN))
        	else
        		blocks_data+=.
        	fi

            while :
            do
                block=$(printf %03d $i)
                check_deliver=$(dig ${HOST} 2$(generate_random 4)$id$block.$blocks_data${DNS_DOMAIN} TXT | grep -oP '\"\K[^\"]+')

                if [[ $check_deliver = 'ENDBLOCK' ]]
                    then
                        debug_echo 'Message delivered!'
                        break
                fi

                IFS=':' read -r -a check_deliver_array <<< $check_deliver
                deliver_data=${check_deliver_array[0]}
                block_check=${deliver_data:2}

                if [[ ${check_deliver_array[1]} = 'OK' ]] && [[ $((10#${deliver_data:2})) = $i ]] && [[ ${deliver_data:0:2} = $id ]]
                    then
                        break
                fi

            done
        done
    else
        	debug_echo 'Empty message from target server, forward the next package '
    fi

}


###########################
# Some argparser		  #
###########################

if [ $# -lt 1 ]
	then
	echo_logo
	echo 'No options found, use -h to get help'
	exit 1
fi

while getopts "d:n:i:hD" opt
	do
	case $opt in
	d) check_args
		readonly DNS_DOMAIN=$(grep -E "^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$" <<< $OPTARG)

		if [[ $DNS_DOMAIN = '' ]]
			then
			echo 'Invalid domain name'
			exit 1
		fi
	;;

	n) check_args
		CLIENT_NAME=$(grep -E '^[a-zA-Z0-9]{1,100}$' <<< "$OPTARG")

		if [[ $CLIENT_NAME = '' ]]
			then
			echo 'Client name supports only english characters,numbers and underscore less than 100 symbols'
			exit 1
		fi
	;;

	i) check_args
		readonly HOST=@$(grep -E "^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$|^localhost$|^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$" <<< $OPTARG)

		if [[ $HOST = '' ]]
			then
			echo 'Invalid ip or domain for resolve'
			exit 1
		fi
	;;

	D) check_args
		DEBUG="TRUE"
	;;

	h) check_args
		echo_logo
		echo 'Options:'
		echo '	-h            Show basic help message and exit'
		echo '	-d            Domain name for tunnel (required)'
		echo '	-n            Name for client (required)'
		echo '	-i            Dns server ip for resolve'
		echo '	-D            DEBUG MODE'
		echo ''
		exit 1
	;;

	*)
		exit 1
	;;
	esac
	done

# Print best logo ever
echo_logo

if [[ $DNS_DOMAIN = '' || $CLIENT_NAME = '' ]]
	then
	echo "Required args: -d -n"
	exit 1
fi

DOMAIN_LEN=${#DNS_DOMAIN}

if [[ $DOMAIN_LEN -gt 235 ]]
	then
	echo 'DOMAIN NAME IS TOO LONG!'
	exit 1
fi

###########################
# Main cycle
###########################

MESSAGE_LEN=$((250-${DOMAIN_LEN}-15))
echo 'Starting...'
reg_info=$(register ${CLIENT_NAME})

id=${reg_info:0:2}

if [[ $(grep -oE '^?[0-9]+$' <<< $((10#$id))) = '' || $((10#$id)) = '0' ]]
	then
	echo 'REGISTER ERROR: Can not establish connection with DNS'
	exit 1
fi

key=${reg_info:2:3}

last_ip=none

response=''

is_set=''

echo "CONNECTED TO $DNS_DOMAIN"
echo "CLIENT NAME: $CLIENT_NAME"
echo "Client registered with id: $((10#$id)) and key:${key}"
while :
do
	if [[ $is_set = 'SET' ]]
		then
		reply
	fi

	data=$(get_data $id)

	if [[ ${data:0:2} = $id ]]
		then

		if [[ ${data:2:2} = 'ND' ]]
			then
			sleep 0.1
		else
			IFS=':' read -r -a data_array <<< $data
			data=${data_array[0]}
			is_id=${data:0:2}
			ip=${data:2}
			port=${data_array[1]}

			if [[ $is_id = $id ]]
				then

				if [[ $ip = '0.0.0.0'  &&  $port = '00' ]]
					then
					exec 3<&-
					exec 3>&-
					is_set='NOTSET'
					echo "Connection OFF"
					last_ip=$ip
				fi

				if [[ $last_ip != $ip  ]]
					then
					exec 3<>/dev/tcp/$ip/$port
					is_set='SET'
					echo "Connection ON"
					last_ip=$ip
				fi

				if [[ $is_set = 'SET' ]]
					then
					echo -e -n ${data_array[2]} | base64 -d >&3
				fi

			fi
		fi
	fi
done
