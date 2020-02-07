/*
** Zabbix
** Copyright (C) 2001-2020 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

package tcpudp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"zabbix.com/internal/agent"
	"zabbix.com/pkg/log"
	"zabbix.com/pkg/plugin"
)

const (
	errorInvalidFirstParam  = "Invalid first parameter."
	errorInvalidSecondParam = "Invalid second parameter."
	errorInvalidThirdParam  = "Invalid third parameter."
	errorTooManyParams      = "Too many parameters."
	errorUnsupportedMetric  = "Unsupported metric."
)

const (
	tcpExpectFail   = -1
	tcpExpectOk     = 0
	tcpExpectIgnore = 1
)

// Plugin -
type Plugin struct {
	plugin.Base
}

var impl Plugin

func (p *Plugin) exportNetTcpPort(params []string) (result int, err error) {
	if len(params) > 2 {
		err = errors.New(errorTooManyParams)
		return
	}
	if len(params) < 2 || len(params[1]) == 0 {
		err = errors.New(errorInvalidSecondParam)
		return
	}

	port := params[1]

	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		err = errors.New(errorInvalidSecondParam)
		return
	}

	var address string

	if params[0] == "" {
		address = net.JoinHostPort("127.0.0.1", port)
	} else {
		address = net.JoinHostPort(params[0], port)
	}

	if _, err := net.Dial("tcp", address); err != nil {
		return 0, nil
	}
	return 1, nil
}

func (p *Plugin) validateSsh(buf []byte, conn net.Conn) int {
	var major, minor int
	var sendBuf string
	ret := tcpExpectFail

	if _, err := fmt.Sscanf(string(buf), "SSH-%d.%d", &major, &minor); err == nil {
		sendBuf = fmt.Sprintf("SSH-%d.%d-zabbix_agent\r\n", major, minor)
		ret = tcpExpectOk
	}

	if ret == tcpExpectFail {
		sendBuf = fmt.Sprintf("0\n")
	}

	if _, err := conn.Write([]byte(sendBuf)); err != nil {
		log.Debugf("SSH check error: %s\n", err.Error())
	}

	return ret
}

func (p *Plugin) validateSmtp(buf []byte) int {
	if string(buf[:3]) == "220" {
		if string(buf[3]) == "-" {
			return tcpExpectIgnore
		}
		if string(buf[3]) == "" || string(buf[3]) == " " {
			return tcpExpectOk
		}
	}
	return tcpExpectFail
}

func (p *Plugin) validateFtp(buf []byte) int {
	if string(buf[:4]) == "220 " {
		return tcpExpectOk
	}
	return tcpExpectIgnore
}

func (p *Plugin) validatePop(buf []byte) int {
	if string(buf[:3]) == "+OK" {
		return tcpExpectOk
	}
	return tcpExpectFail
}

func (p *Plugin) validateNntp(buf []byte) int {
	if string(buf[:3]) == "200" || string(buf[:3]) == "201" {
		return tcpExpectOk
	}
	return tcpExpectFail
}

func (p *Plugin) validateImap(buf []byte) int {
	if string(buf[:4]) == "* OK" {
		return tcpExpectOk
	}
	return tcpExpectFail
}

func (p *Plugin) tcpExpect(service string, ip string, port string) (result int) {
	var conn net.Conn
	var err error
	address := net.JoinHostPort(ip, port)

	if conn, err = net.Dial("tcp", address); err != nil {
		log.Debugf("TCP expect network error: cannot connect to [%s]: %s", address, err.Error())
		return
	}
	defer conn.Close()

	if service == "http" || service == "tcp" {
		return 1
	}

	if err = conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(agent.Options.Timeout))); nil != err {
		return
	}

	var sendToClose string
	var checkResult int
	buf := make([]byte, 2048)

	for {
		if _, err := conn.Read(buf); err == nil {
			switch service {
			case "ssh":
				checkResult = p.validateSsh(buf, conn)
			case "smtp":
				checkResult = p.validateSmtp(buf)
				sendToClose = fmt.Sprintf("%s", "QUIT\r\n")
			case "ftp":
				checkResult = p.validateFtp(buf)
				sendToClose = fmt.Sprintf("%s", "QUIT\r\n")
			case "pop":
				checkResult = p.validatePop(buf)
				sendToClose = fmt.Sprintf("%s", "QUIT\r\n")
			case "nntp":
				checkResult = p.validateNntp(buf)
				sendToClose = fmt.Sprintf("%s", "QUIT\r\n")
			case "imap":
				checkResult = p.validateImap(buf)
				sendToClose = fmt.Sprintf("%s", "a1 LOGOUT\r\n")
			default:
				err = errors.New(errorInvalidFirstParam)
				return
			}

			if checkResult == tcpExpectOk {
				break
			}
		} else {
			log.Debugf("TCP expect network error: cannot read from [%s]: %s", address, err.Error())
			return 0
		}
	}

	if checkResult == tcpExpectOk {
		if sendToClose != "" {
			conn.Write([]byte(sendToClose))
		}
		result = 1
	}

	if checkResult == tcpExpectFail {
		log.Debugf("TCP expect content error, received [%s]", buf)
	}

	return
}

func (p *Plugin) exportNetService(params []string) int {
	var ip, port string
	var useDefaultPort bool
	service := params[0]

	if len(params) == 1 {
		ip = "127.0.0.1"
		useDefaultPort = true
	} else if len(params) == 2 {
		if len(params[1]) == 0 {
			ip = "127.0.0.1"
		} else {
			ip = params[1]
		}
		useDefaultPort = true
	} else {
		if len(params[1]) == 0 {
			ip = "127.0.0.1"
		} else {
			ip = params[1]
		}
		if len(params[2]) == 0 {
			useDefaultPort = true
		} else {
			port = params[2]
		}
	}

	if service == "pop" {
		if useDefaultPort {
			port = fmt.Sprintf("%d", 110)
			useDefaultPort = false
		}
	}

	if useDefaultPort {
		return p.tcpExpect(service, ip, service)
	}
	return p.tcpExpect(service, ip, port)
}

func round(num float64) int {
	return int(num + math.Copysign(0.5, num))
}

func toFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(round(num*output)) / output
}

func (p *Plugin) exportNetServicePerf(params []string) float64 {
	const floatPrecision = 0.0001

	start := time.Now()
	ret := p.exportNetService(params)

	if ret == 1 {
		elapsedTime := toFixed(time.Since(start).Seconds(), 6)

		if elapsedTime < floatPrecision {
			elapsedTime = floatPrecision
		}
		return elapsedTime
	}
	return 0.0
}

// Export -
func (p *Plugin) Export(key string, params []string, ctx plugin.ContextProvider) (result interface{}, err error) {
	switch key {
	case "net.tcp.port":
		return p.exportNetTcpPort(params)
	case "net.tcp.service", "net.tcp.service.perf":
		if len(params) > 3 {
			err = errors.New(errorTooManyParams)
			return
		}
		if len(params) < 1 || (len(params) == 1 && len(params[0]) == 0) {
			err = errors.New(errorInvalidFirstParam)
			return
		}
		if params[0] == "tcp" && (len(params) != 3 || len(params[2]) == 0) {
			err = errors.New(errorInvalidThirdParam)
			return
		}

		if key == "net.tcp.service" {
			return p.exportNetService(params), nil
		} else if key == "net.tcp.service.perf" {
			return p.exportNetServicePerf(params), nil
		}
	}

	/* SHOULD_NEVER_HAPPEN */
	return nil, errors.New(errorUnsupportedMetric)
}

func init() {
	plugin.RegisterMetrics(&impl, "TCP",
		"net.tcp.port", "Checks if it is possible to make TCP connection to specified port.",
		"net.tcp.service", "Checks if service is running and accepting TCP connections.",
		"net.tcp.service.perf", "Checks performance of TCP service.")
}
