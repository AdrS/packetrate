# packetrate
Determines data transmission rates for all hosts in a pcap

## Ouput Columns
1. ip
2. min pps sent
3. max pps sent
4. avg pps sent
5. stdev pps sent
6. total packets sent
7. min Bps sent
8. max Bps sent
9. avg Bps sent
10. stdev Bps sent
11. total byte sent
12. min pps received
13. max pps received
14. avg pps received
15. stdev pps received
16. total packets received
17. min Bps received
18. max Bps received
19. avg Bps received
20. stdev Bps received
21. total byte received

# Usage Example
`./packetrate -pcap dump.pcap -output rates.csv`

## View Specific Fields
`cut -d, -f1,13 rates.csv`

## See IPs with highest receive rate
cut -d, -f1,13 < rates.csv  | sort -nr -k 2 | head -n 10
