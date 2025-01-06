#!/bin/bash

# FOLDER configuration; modify as needed
LOGSPath="/home/misp/sentinelfeeder/logs/" 
IOCSPath="/home/misp/sentinelfeeder/iocs/" 

# MISP configuration; modify as needed
MISPURL="https://127.0.0.1"
MISPKey="INSERT KEY HERE"
MISPOrg="INSERT ORG UUID HERE"

# SENTINELONE configuration; modify as needed
SentinelOneURL="INSERT SENTINELONE URL HERE"
SentinelOneAPIKey="INSERT SENTINELONE API KEY HERE"
AccountId="INSERT ACCOUNT ID HERE"
#SiteID="IF YOU PREFER YOU CAN RESTRICT IOCS TO A SPECIFIC SITE; not working for iocs deletion, just for iocs push"

# import external IOCs
function Fetch_IOCs {
    echo 'MAP YOUR FUNCTION HERE'
}

#emptying SentinelOne TI database from iocs older than X day, where X is equal to $lifetime variable
function ClearIOCs {
    local lifetime=14
    local uploadTime__lt=$(date -u -d "-$lifetime days" +"%Y-%m-%dT%H:%M:%SZ")
    local Response=$(curl -X DELETE -s -H "Authorization: ApiToken $SentinelOneAPIKey" -H "Content-Type: application/json" -d "{\"filter\": {\"source\": \"Misp\", \"uploadTime__lt\": \"$uploadTime__lt\"}}" "$SentinelOneURL""web/api/v2.1/threat-intelligence/iocs")

    if [[ "$Response" != *"data"* ]]; then
        echo "ERROR deleting indicators from SentinelOne Threat Intelligence Database; Check log file"
    else
        echo "Indicators older than $lifetime days deleted successfully from SentinelOne Threat Intelligence Database."
    fi
}

function Push_IOCs {
    #calculate difference in seconds since last update of iocs; based on file timestamp
    if [[ "$@" = "domain" ]]; then
	local last_mod=$(stat -c %Y "${IOCSPath}dns-list.txt")
    elif [[ "$@" = "ip-src" ]]; then
        local last_mod=$(stat -c %Y "${IOCSPath}ipv4-list.txt")
    else
        local last_mod=$(stat -c %Y "${IOCSPath}${@}-list.txt")
    fi

    local now=$(date +%s)
    local diff_seconds=$((now - last_mod - 300))
    local MISPLast=$((diff_seconds / 60))m


    local Data="{\"type\":\"$@\",\"org\":\"$MISPOrg\",\"last\": \"$MISPLast\"}"

    local ValidUntil=""
    local JsonPayload=""

    # exporting attribute from MISP
    local EventArray=$(curl -s --insecure -X POST -H "Authorization: $MISPKey" -H "Accept: application/json" -H "Content-Type: application/json" -d "$Data" "$MISPURL/attributes/restSearch")
    local matrice=""

    # checking ioc type and qty
    local type=($(jq -r '.response.Attribute[0].type' <<< "$EventArray"))
    local length=($(jq '.response.Attribute | length' <<< "$EventArray" ))

    if [[ "$type" = "null" ]]; then
        echo "No indicator of type $@ present on Misp."
	return
    fi


    #setting lifetime based on type of indicator; see API doc for lifetime reference
    if [[ "$type" = "domain" ]]; then
	type="dns"
	ValidUntil=$(date -u -d "+14 days" +"%Y-%m-%dT%H:%M:%SZ")
    elif [[ "$type" = "url" ]]; then
	type="url"
	ValidUntil=$(date -u -d "+14 days" +"%Y-%m-%dT%H:%M:%SZ")
    elif [[ "$type" = "ip-src" ]]; then
	type='ipv4'
	ValidUntil=$(date -u -d "+14 days" +"%Y-%m-%dT%H:%M:%SZ")
    elif [[ "$type" = "sha1" ]]; then
	type='sha1'
	ValidUntil=$(date -u -d "+14 days" +"%Y-%m-%dT%H:%M:%SZ")
    elif [[ "$type" = "sha256" ]]; then
	ValidUntil=$(date -u -d "+14 days" +"%Y-%m-%dT%H:%M:%SZ")
    fi
    #empty indicator file
    cat /dev/null > "$IOCSPath""$type""-list.txt"

    #cycling through the response
    jq -r '.response.Attribute[] | [.value, .category, .first_seen, .Event.info] | @tsv' <<< "$EventArray" > "${IOCSPath}extracted_data.tsv"

	while IFS=$'\t' read -r value category first_seen event_info; do
	    JsonPayload+="{\"source\":\"Misp\",\"method\":\"EQUALS\","
	    JsonPayload+="\"type\":\"${type^^}\","
	    JsonPayload+="\"value\":\"$value\","
	    JsonPayload+="\"category\":\"$category\","
	    JsonPayload+="\"creationTime\":\"$first_seen\","
	    JsonPayload+="\"malwareNames\":\"$(echo "$event_info" | awk '{ print $NF }')\","
	    JsonPayload+="\"validUntil\":\"$ValidUntil\"},"

    	    echo "$value" >> "${IOCSPath}${type}-list.txt"
	done < "${IOCSPath}extracted_data.tsv"
    rm -f "${IOCSPath}extracted_data.tsv"


    JsonPayload="${JsonPayload%,}"
    #echo "{\"filter\": {\"siteIds\": [\"$SiteId\"]},\"data\": [$JsonPayload]}" > "$IOCSPath""data_file.json"
    echo "{\"filter\": {\"accountIds\": [\"$AccountId\"]},\"data\": [$JsonPayload]}" > "$IOCSPath""data_file.json"


    local Response=$(curl -X POST -s -H "Authorization: ApiToken $SentinelOneAPIKey" -H "Content-Type: application/json" --data-binary "@""$IOCSPath""data_file.json" "$SentinelOneURL""web/api/v2.1/threat-intelligence/iocs")
    echo "$Response" > "$LOGSPath""sentinel_""$type"".log"
    local validating=$(echo "$Response" | jq -r '.data[0].batchId')
    if [[ -z "$validating" ]]; then
        echo "ERROR importing $type indicator from Misp to SentinelOne Threat Intelligence Database; Check log file"
    else
	echo "$length Indicator $type imported Correctly to SentinelOne Threat Intelligence Database."
    fi
}

function printhelp {
    echo "This script will allow you to export from Misp to SentinelOne Threat Intelligence database."
    echo "      -f: fetch iocs from External threat intelligence."
    echo "      -c: clear iocs from SentinelOne Threat Intelligence database. By default only IOCs from the last 14 days are retained"
    echo "      -p: push iocs from misp to SentinelOne"
}

#Mapping functions to be able to call them as needed
first=0

if [[ $# -eq 0 ]]; then
    printhelp
    exit 0
fi

while getopts ":f :c :p :h" option; do 
    case "${option}" in
	f)
	    if [ -n "$(ps -ax | grep misp_import.py | grep -v grep)" ]; then
		    echo "IOCS import process already running"
		    exit 0
    	fi

	    Fetch_IOCs
  ;;
	c)
	    ClearIOCs
	;;
  p)
	    #API call max 5 calls per minute
	    Push_IOCs "sha1"
      echo "Sleeping 20 to avoid rate limits."; sleep 20 | pv -t
	    Push_IOCs "sha256"
      echo "Sleeping 20 to avoid rate limits."; sleep 20 | pv -t
	    Push_IOCs "ip-src"
      echo "Sleeping 20 to avoid rate limits."; sleep 20 | pv -t
	    Push_IOCs "domain"
      echo "Sleeping 20 to avoid rate limits."; sleep 20 | pv -t
	    Push_IOCs "url"
	;;
	h)
	    printhelp
	;;
	*)
	    if [[ $first -eq 0 ]]; then
	      echo "unknown option" $1
	      echo ""
	      printhelp
	      first=1
	    fi
	;;
    esac
done
