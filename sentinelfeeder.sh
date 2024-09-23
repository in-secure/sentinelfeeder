#!/bin/bash

# FOLDER configuration; modify as needed
LOGSPath="/home/misp/sentinelfeeder/logs/" 
IOCSPath="/home/misp/sentinelfeeder/iocs/" 

# MISP configuration; modify as needed
MISPURL="https://127.0.0.1"
MISPKey="INSERT KEY HERE"
MISPLast=60m
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
    local Headers="Authorization: ApiToken $SentinelOneAPIKey"
    local ThreatIntelUrl="$SentinelOneURL""web/api/v2.1/threat-intelligence/iocs"
    local uploadTime__lt=$(date -u -d "-$lifetime days" +"%Y-%m-%dT%H:%M:%SZ")
    local Response=$(curl -X DELETE -s -H "$Headers" -H "Content-Type: application/json" -d "{\"filter\": {\"source\": \"Misp\", \"uploadTime__lt\": \"$uploadTime__lt\"}}" $ThreatIntelUrl)

    if [[ "$Response" != *"data"* ]]; then
        echo "ERROR deleting indicators from SentinelOne Threat Intelligence Database; Check log file"
    else
        echo "Indicators older than $lifetime days deleted successfully from SentinelOne Threat Intelligence Database."
    fi
}

function Push_IOCs {
    local HeadersGET="Authorization: $MISPKey"
    local Data="{\"type\":\"$@\",\"org\":\"$MISPOrg\",\"timestamp\": \"$MISPLast\"}"

    local ValidUntil=""
    local ThreatIntelUrl="$SentinelOneURL""web/api/v2.1/threat-intelligence/iocs"
    local Headers="Authorization: ApiToken $SentinelOneAPIKey"
    local JsonPayload=""

    # exporting attribute from MISP
    EventArray=$(curl -s --insecure -X POST -H "$HeadersGET" -H "Accept: application/json" -H "Content-Type: application/json" -d "$Data" "$MISPURL/attributes/restSearch")
    matrice=""

    # checking ioc type and qty
    type=($(jq -r '.response.Attribute[0].type' <<< "$EventArray"))
    length=($(jq '.response.Attribute | length' <<< "$EventArray" ))

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

    while [ $(jq '.response.Attribute | length' <<< "$EventArray") -gt 0 ]; do
    	matrice[0]=$(jq '.response.Attribute['0'].value' <<< "$EventArray")
    	matrice[1]=$(jq '.response.Attribute['0'].category' <<< "$EventArray")
    	matrice[2]=$(jq '.response.Attribute['0'].first_seen' <<< "$EventArray")
    	matrice[3]=$(jq '.response.Attribute['0'].Event.info' <<< "$EventArray")
    
    	EventArray=$(jq 'del(.response.Attribute['0'])' <<< "$EventArray" -r) 
    
    	JsonPayload+="{\"source\": \"Misp\","
    	JsonPayload+="\"method\": \"EQUALS\","
    	JsonPayload+="\"type\": \"${type^^}\","
    	JsonPayload+="\"value\": ${matrice[0]},"
    	JsonPayload+="\"category\": ${matrice[1]},"
    	JsonPayload+="\"creationTime\": ${matrice[2]},"
    	JsonPayload+="\"malwareNames\": \""$(echo ${matrice[3]} | awk '{ print $NF }')","
    	JsonPayload+="\"validUntil\": \"$ValidUntil\"},"
    
    	sed 's/"//g' <<< "${matrice[0]}" >> "$IOCSPath""$type""-list.txt"
    done

    JsonPayload="${JsonPayload%,}"
    # SEE VARIABLE DEFINITION FOR PUSHING ON SITE ONLY
    #echo "{\"filter\": {\"siteIds\": [\"$SiteId\"]},\"data\": [$JsonPayload]}" > "$IOCSPath""data_file.json"
    echo "{\"filter\": {\"accountIds\": [\"$AccountId\"]},\"data\": [$JsonPayload]}" > "$IOCSPath""data_file.json"

    local Response=$(curl -X POST -s -H "$Headers" -H "Content-Type: application/json" --data-binary "@""$IOCSPath""data_file.json" "$ThreatIntelUrl")
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
