package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv6"
)

// A Spoofer is an Object containing various needs to send spoofed ND messages
type Spoofer struct {
	c       *ndp.Conn
	spoofer net.HardwareAddr
	lock    sync.RWMutex
	ips     map[string]net.IP
}

// NewSpoofer creates a new Spoofer object based on interface name to listen on, Mac Address to use in spoofed replies
func NewSpoofer(iface, mac string) (*Spoofer, error) {
	m, err := net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	log.Infof("Spoofing MAC: %v", mac)

	// Ensure valid interface and IPv4 address
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	c, listen, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return nil, err
	}

	filter := &ipv6.ICMPFilter{}
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeNeighborSolicitation)

	if err := c.SetICMPFilter(filter); err != nil {
		return nil, err
	}

	log.Infof("listening on %v", listen)

	return &Spoofer{
		c:       c,
		spoofer: m,
		ips:     make(map[string]net.IP),
	}, nil
}

func (s *Spoofer) readND() {
	for {
		msg, _, from, err := s.c.ReadFrom()
		if err != nil {
			log.Warnf("failed to receive: %v", err)
			continue
		}
		go s.handleND(msg, from)
	}
}

func (s *Spoofer) hasIP(ip net.IP) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, exists := s.ips[ip.String()]
	return exists
}

func (s *Spoofer) handleND(msg ndp.Message, from net.IP) {
	req := msg.(*ndp.NeighborSolicitation)
	log.Tracef("requested %v from %v", req.TargetAddress, from)

	if s.hasIP(req.TargetAddress) {
		if err := s.SendNA(from, req.TargetAddress); err != nil {
			log.Warnf("unable to send a spoofed reply: %v", err)
		}
	}
}

// SendNA sends a single NA for ip to destination, destionation may be All link local nodes
func (s *Spoofer) SendNA(to, ip net.IP) error {
	sol := true

	// if to is equal to the all link local nodes I'm sending a non-solicited NA, this means I also wanna set override flag to true
	if to.Equal(net.IPv6linklocalallnodes) {
		sol = false
	}

	m := &ndp.NeighborAdvertisement{
		Router:        true,
		Solicited:     sol,
		Override:      !sol,
		TargetAddress: ip,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Addr:      s.spoofer,
				Direction: ndp.Target,
			},
		},
	}

	cm := &ipv6.ControlMessage{
		// Hop limit is always 255, per RFC 4861
		HopLimit: 255,
		//Src:      eui.Eui64(mac),
		Dst: to,
	}

	if err := s.c.WriteTo(m, cm, to); err != nil {
		return fmt.Errorf("failed to send spoofed nd to %v: %w", to, err)
	}

	log.Debugf("sent spoofed nd to %v Spoofing %v with %v", to, ip, s.spoofer)
	return nil
}

func (s *Spoofer) handleNonSolicits(timer time.Duration) {
	for {
		select {
		case <-time.After(timer):
		}

		s.lock.RLock()
		for _, ip := range s.ips {
			if err := s.SendNA(net.IPv6linklocalallnodes, ip); err != nil {
				log.Warnf("Failed sending non-solicit ND for %v: %v", ip, err)
			}
		}
		s.lock.RUnlock()
	}
}

func (s *Spoofer) updateIps(newIps map[string]net.IP) {
	s.lock.Lock()
	for sip, ip := range s.ips {
		if _, exists := newIps[sip]; !exists {
			if err := s.leaveGroup(ip); err != nil {
				log.Warnf("failed to leave multicast group: %v", err)
			}
			delete(s.ips, sip)
		}
	}

	for sip, ip := range newIps {
		if _, exists := s.ips[sip]; !exists {
			if err := s.joinGroup(ip); err != nil {
				log.Warnf("failed to join multicast group: %v", err)
			}
			s.ips[sip] = ip
		}
	}
	s.lock.Unlock()
}

func (s *Spoofer) joinGroup(ip net.IP) error {
	m, err := ndp.SolicitedNodeMulticast(ip)
	if err != nil {
		return err
	}
	if err := s.c.JoinGroup(m); err != nil {
		return err
	}
	log.Debugf("joined %v for %v", m, ip)
	return nil
}

func (s *Spoofer) leaveGroup(ip net.IP) error {
	m, err := ndp.SolicitedNodeMulticast(ip)
	if err != nil {
		return err
	}
	if err := s.c.LeaveGroup(m); err != nil {
		return err
	}
	log.Debugf("left %v for %v", m, ip)
	return nil
}
