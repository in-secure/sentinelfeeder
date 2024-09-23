# Sentinelfeeder
Simple bash script for exporting attribute from a MISP instance to SentinelOne threat intelligence database.

The script will allow you to:
 - fetch iocs from an external feed to misp (you have to insert your own code here)
 - clear S1 TI database from old iocs (by default 14 days)
 - export events' attribute in TXT format and import them in S1 TI database

Attribute are mapped as it follows (MISP - S1 TI)
 - Value to Value
 - Category to Category
 - First Seen as Creation Time
 - Event info as Malware Name

How to use
- install curl, jq and pv
- set up a cron schedule (here mine)
```
# m h  dom mon dow   command
*/15 * * * * run-one /home/misp/sentinelfeeder/sentinelfeeder.sh -f
*/30 * * * * run-one /home/misp/sentinelfeeder/sentinelfeeder.sh -p
0 0 * * * run-one /home/misp/sentinelfeeder/sentinelfeeder.sh -c

```
- point your ids/ips/nta/firewall to TXT iocs
- take a beer and watch them (not) being matched on your data lake

<br>
NB: This is not optimized for huge amount of data, use it for continuously push small amount of iocs.
