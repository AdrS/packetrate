package main

import (
//	"bufio"
//	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
//	"net"
	"os"
	"sort"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
//	"github.com/google/gopacket/layers"
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

// TODO: move to streaming statistics package
// Stores information pertaining to the computation of a statistic ex: min, max, mean, stdev
type Statistic interface {
	Update(sample float64)
	Result() float64
}

// Store minimum value in a stream
type StreamMin struct {
	Min float64
}

func NewStreamMin() *StreamMin {
	return &StreamMin{math.MaxFloat64}
}

func (s *StreamMin) Update(sample float64) {
	if(sample < s.Min) {
		s.Min = sample
	}
}

func (s *StreamMin) Result() float64 { return s.Min }


/*
type StatisticsGroup struct {
	Statistics []Statistic
	Labels     []string
} */

// IP -> statistics for packets sent to IP
var destinationStatistics = make(map[string][]Statistic)

// IP -> statistics for packets received from IP
var sourceStatistics = make(map[string][]Statistic)

// aggregate 
var aggregateSendStatistics = []Statistic{NewStreamMin()}
var aggregateReceiveStatistics = []Statistic{NewStreamMin()}

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

func process(packets <-chan gopacket.Packet) {
	//var stepStart time.Time
	for packet := range packets {
		fmt.Println(PacketTimestamp(packet))
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

	//outputFile := CreateFileOrFail(*outputPath)
	fmt.Println(*outputPath, *window)
	pcapFile := OpenPcapOrFail(*pcapPath)

	// Only look at tcp traffic directed scanning machine
	if err := pcapFile.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// Loads packets from PCAP
	packets := gopacket.NewPacketSource(pcapFile, pcapFile.LinkType()).Packets()
	orderedPackets := make(chan gopacket.Packet)
	go OrderPacketStream(packets, orderedPackets, *epsilon)
	process(orderedPackets)
	log.Println("Done!")
}
