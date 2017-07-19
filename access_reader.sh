#!/bin/bash

####
# reads an Apache access log with the following fields
# "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
####

# Set the internal field separator
IFS=$'\n'

if [ -n "$1" ] && [ -r "$1" ]
then
	log_file="$1"
else
	printf "Bad log file given: %s\n" "$1"
	exit 1
fi

echo "##########"
echo "Source IPs"
cat "$log_file" | cut -d " " -f 1 | sort | uniq -c | sort -nr
echo "##########"

echo "##########"
echo "User-Agents"
cat "$log_file" | rev | cut -d "\"" -f 2 | rev | sort | uniq -ci | sort -nr
echo "##########"

for f in $(ls | grep "\.log$")  # expecting us to be in our own directory, so clear out all the old logs
do
	if ! [ "$log_file" == "$f" ]
	then
		rm "$f"
	fi
done

while read -r line
do
	#echo "$line"
	source_ip="$(printf "%s" "$line" | cut -d " " -f 1)"
	user_id="$(printf "%s" "$line" | cut -d " " -f 3)"
	request_time="$(printf "%s" "$line" | cut -d " " -f 4-5)"
	request_line="$(printf "%s" "$line" | cut -d " " -f 6-8)"
	http_status="$(printf "%s" "$line" | cut -d " " -f 9)"

	re='^[0-9]+$'
	if ! [[ $http_status =~ $re ]]
	then
   		#echo "error: Not a number, $http_status"
		request_line="$(printf "%s" "$line" | cut -d " " -f 6)"
        	http_status="$(printf "%s" "$line" | cut -d " " -f 7)"
		if ! [[ $http_status =~ $re ]]
		then
			echo "error: Not a number, $http_status"
			exit 1
		fi
	fi

	user_agent="$(printf "%s" "$line" | rev | cut -d "\"" -f 2 | rev)"
	#echo "$user_agent"

	if [ "$http_status" -gt 399 ]  # codes in the 200 range are successes and the 300 range is just redirects
	then
		if [ -n "$(printf "%s" "$request_line" | grep -w "\.\./")" ]  # is someone is trying to build a relative file path in the URI?
		then
			echo "$line" >> "$source_ip.log"
			#echo "$line" | tee -a "$source_ip.log"
		else
			echo "$line" >> "$source_ip.log"
		fi
	fi

done < "$log_file"

col1="Suspect"
col2="Num of Failures"
printf "\n%13s %21s\n" "$col1" "$col2"
for f in $(ls | grep "\.log$")  # do some analysis on each of our suspects
do
        if ! [ "$log_file" == "$f" ]
        then
                num_attacks="$(cat "$f" | wc -l)"
		printf "%19s %10s\n" "$f" "$num_attacks"
        fi
done | sort -nr -k 2

unset IFS

exit 0
