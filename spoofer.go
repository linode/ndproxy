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

type Spoofer struct {
	c       *ndp.Conn
	spoofer net.HardwareAddr
	lock    sync.RWMutex
	ips     map[string]net.IP
}

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

func (c *Spoofer) CheckIp(ip net.IP) bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	_, exists := c.ips[ip.String()]
	return exists
}

func (s *Spoofer) handleND(msg ndp.Message, from net.IP) {
	ns := msg.(*ndp.NeighborSolicitation)
	log.Tracef("requested %v from %v", ns.TargetAddress, from)

	if s.CheckIp(ns.TargetAddress) {
		if err := s.SendNA(from, ns.TargetAddress, true); err != nil {
			log.Warnf("unable to send a spoofed reply: %v", err)
		}
	}
}

func (s *Spoofer) SendNA(to, ip net.IP, sol bool) error {
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

func (s *Spoofer) sendGratuitous(timer time.Duration) {
	for {
		select {
		case <-time.After(timer):
		}

		s.lock.RLock()
		for _, ip := range s.ips {
			if err := s.SendNA(net.IPv6linklocalallnodes, ip, false); err != nil {
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
