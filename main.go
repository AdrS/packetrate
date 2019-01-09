package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	stream "github.com/adrs/packetrate/stream"
)

func OpenFileOrFail(path string) *os.File {
	if path == "-" {
		return os.Stdin
	}
	fd, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	return fd
}

func CreateFileOrFail(path string) *os.File {
	if path == "-" {
		return os.Stdout
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func OpenPcapOrFail(path string) *pcap.Handle {
	if handle, err := pcap.OpenOffline(path); err != nil {
		log.Fatal(err)
		return nil
	} else {
		return handle
	}
}

func PacketTimestamp(packet gopacket.Packet) time.Time {
	return packet.Metadata().CaptureInfo.Timestamp
}

// Packets in a PCAP are not guaranteed to be in chronological order. This
// function correctly orders packets under mild assumptions by buffering packets
// for time window epsilon.
// input - semi ordered stream of packets such that
//         timestamp for ith packet is >= previous packet timestamps - epsilon
// output - totally ordered stream of packets
// epsilon - value such that timestamps for all 
func OrderPacketStream(input <-chan gopacket.Packet, output chan<- gopacket.Packet, epsilon time.Duration) {
	buffer := make([]gopacket.Packet, 0)
	// Earliest timestamp in buffer + epsilon
	var loadTil time.Time
	// Store time of last outputted packet to verify output is in order
	var previousTimestamp time.Time

	compare := func(i, j int) bool {
		return PacketTimestamp(buffer[i]).Before(PacketTimestamp(buffer[j]))
	}

	for packet := range input {
		timestamp := PacketTimestamp(packet)
		buffer := append(buffer, packet)
		if timestamp.After(loadTil) {
			// Keep buffer sorted
			sort.Slice(buffer, compare)
			timestamp = PacketTimestamp(buffer[0])
			// Verify that output is in chronological order
			if previousTimestamp.After(timestamp) {
				log.Fatal("Stream sorting did not work, epsilon parameter is too small")
			}
			previousTimestamp = timestamp
			loadTil = timestamp.Add(epsilon)
			output <- buffer[0]
			buffer = buffer[1:]
		}
	}

	// Clear out end of stream
	sort.Slice(buffer, compare)
	for _, packet := range buffer {
		output <- packet
	}
	close(output)
}

var labels = []string{
	"min pps sent",
	"max pps sent",
	"avg pps sent",
	"stdev pps sent",
	"total packets sent",
	"min Bps sent",
	"max Bps sent",
	"avg Bps sent",
	"stdev Bps sent",
	"total byte sent",
	"min pps received",
	"max pps received",
	"avg pps received",
	"stdev pps received",
	"total packets received",
	"min Bps received",
	"max Bps received",
	"avg Bps received",
	"stdev Bps received",
	"total byte received",
}

func makeHostStatistics() []stream.Statistic {
	return []stream.Statistic{
		// sent
		stream.NewMin(),
		stream.NewMax(),
		stream.NewMean(),
		stream.NewStdev(),
		stream.NewSum(),
		stream.NewMin(),
		stream.NewMax(),
		stream.NewMean(),
		stream.NewStdev(),
		stream.NewSum(),
		// received
		stream.NewMin(),
		stream.NewMax(),
		stream.NewMean(),
		stream.NewStdev(),
		stream.NewSum(),
		stream.NewMin(),
		stream.NewMax(),
		stream.NewMean(),
		stream.NewStdev(),
		stream.NewSum(),
	}
}

var hostStatistics = make(map[string][]stream.Statistic)

// aggregate 
//var aggregateSendStatistics = []stream.Statistic{stream.NewMin()}
//var aggregateReceiveStatistics = []stream.Statistic{NewStreamMin()}

type WindowState struct {
	NumPacketsSent int
	NumPacketsReceived int
	NumBytesSent int
	NumBytesReceived int
	// TODO: First and last times
}

func process(packets <-chan gopacket.Packet, window time.Duration) {
	var windowEnd time.Time
	var windowSeconds = window.Seconds()

	// Stores number of packets sent so far in window
	var states = make([]WindowState, 0)
	// Maps ips to current counts
	var ip2index = make(map[string]int)

	getIndex := func(ip net.IP) int {
		ipString := ip.String()
		if i, ok := ip2index[ipString]; ok {
			return i
		}
		i := len(states)
		ip2index[ipString] = i
		states = append(states, WindowState{})
		return i
	}

	updateStatistics := func() {
		for ip, i := range ip2index {
			var hostStats []stream.Statistic
			var ok bool
			if hostStats, ok = hostStatistics[ip]; !ok {
				hostStats = makeHostStatistics()
			}
			// update stats on 
			pps := float64(states[i].NumPacketsSent)/windowSeconds
			hostStats[0].Update(pps)
			hostStats[1].Update(pps)
			hostStats[2].Update(pps)
			hostStats[3].Update(pps)
			hostStats[4].Update(float64(states[i].NumPacketsSent))

			bps := float64(states[i].NumBytesSent)/windowSeconds
			hostStats[5].Update(bps)
			hostStats[6].Update(bps)
			hostStats[7].Update(bps)
			hostStats[8].Update(bps)
			hostStats[9].Update(float64(states[i].NumBytesSent))

			pps = float64(states[i].NumPacketsReceived)/windowSeconds
			hostStats[10].Update(pps)
			hostStats[11].Update(pps)
			hostStats[12].Update(pps)
			hostStats[13].Update(pps)
			hostStats[14].Update(float64(states[i].NumPacketsReceived))

			bps = float64(states[i].NumBytesReceived)/windowSeconds
			hostStats[15].Update(bps)
			hostStats[16].Update(bps)
			hostStats[17].Update(bps)
			hostStats[18].Update(bps)
			hostStats[19].Update(float64(states[i].NumBytesReceived))
			hostStatistics[ip] = hostStats
		}
	}

	for packet := range packets {
		curTime := PacketTimestamp(packet)
		if curTime.After(windowEnd) {
			// Window is over -> update statistics
			updateStatistics()
			// TODO: how to have windows be consecutive while skipping large gaps
			windowEnd = curTime.Add(window)
		}

		ip4layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4layer == nil {
			continue
		}
		ip4 := ip4layer.(*layers.IPv4)

		// Packet size in bytes
		size := len(packet.Data())

		i := getIndex(ip4.SrcIP)
		states[i].NumPacketsSent++
		states[i].NumBytesSent += size
		i = getIndex(ip4.DstIP)
		states[i].NumPacketsReceived++
		states[i].NumBytesReceived += size
	}
	// Finish processing any last packets
	updateStatistics()
}

func WriteOutput(output *os.File) {
	// Print header
	fmt.Fprintf(output, "1) ip, ")
	for i, label := range labels {
		fmt.Fprintf(output, "%d) %s, ", i + 2, label)
	}

	for ip, hostStats := range hostStatistics {
		fmt.Fprintf(output, "\n%s, ", ip)
		for _, stat := range hostStats {
			fmt.Fprintf(output, "%g, ", stat.Result())
		}
	}
}

func main() {
	var pcapPath = flag.String("pcap", "", "path to PCAP file")
	var outputPath = flag.String("output", "-", "output path")
	var filter = flag.String("filter", "", "packet filter to apply")
	var window = flag.Duration("window", time.Second * 5, "timestep to average over when packets/sec")
	var epsilon = flag.Duration("epsilon", time.Second * 5, "tolerance in packet ordering")
	flag.Parse()

	// {min, max, avg, stdev, 90th, 95th} x {packets/sec, bits/sec} U {total} x {packets, bits}
	// times of first and last packet

	outputFile := CreateFileOrFail(*outputPath)
	pcapFile := OpenPcapOrFail(*pcapPath)

	// Only look at tcp traffic directed scanning machine
	if err := pcapFile.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Loads packets from PCAP
	packets := gopacket.NewPacketSource(pcapFile, pcapFile.LinkType()).Packets()
	orderedPackets := make(chan gopacket.Packet)
	go OrderPacketStream(packets, orderedPackets, *epsilon)
	process(orderedPackets, *window)
	WriteOutput(outputFile)
}
