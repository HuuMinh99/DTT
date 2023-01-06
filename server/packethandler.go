// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/sensoroni/sensoroni/model"
	"github.com/sensoroni/sensoroni/web"
)

type PacketHandler struct {
	web.BaseHandler
	server *Server
}

func NewPacketHandler(srv *Server) *PacketHandler {
	handler := &PacketHandler{}
	handler.Host = srv.Host
	handler.server = srv
	handler.Impl = handler
	return handler
}

func (packetHandler *PacketHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	switch request.Method {
	case http.MethodGet:
		return packetHandler.get(writer, request)
	}
	return http.StatusMethodNotAllowed, nil, errors.New("method not supported")
}

func (packetHandler *PacketHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	statusCode := http.StatusBadRequest
	invalidQuery := errors.New("invalid query")
	jobId, err := strconv.ParseInt(request.URL.Query().Get("jobId"), 10, 32)
	if err != nil {
		return statusCode, nil, invalidQuery
	}

	offset, err := strconv.ParseInt(request.URL.Query().Get("offset"), 10, 32)
	if err != nil {
		return statusCode, nil, invalidQuery
	}

	var startTime int64
	var endTime int64
	if request.URL.Query().Get("startTime") != "" && request.URL.Query().Get("endTime") != "" {
		startTime, err = strconv.ParseInt(request.URL.Query().Get("startTime"), 10, 32)
		if err != nil {
			return statusCode, nil, invalidQuery
		}
		endTime, err = strconv.ParseInt(request.URL.Query().Get("endTime"), 10, 32)
		if err != nil {
			return statusCode, nil, invalidQuery
		}
		if endTime < startTime {
			return statusCode, nil, invalidQuery
		}
	}

	search := request.URL.Query().Get("search")
	if offset <= 0 || err != nil {
		offset = 0
	}
	count := int(packetHandler.server.Config.MaxPacketCount)
	if request.URL.Query().Get("count") != "" {
		count, err = strconv.Atoi(request.URL.Query().Get("count"))
		if err != nil {
			return statusCode, nil, invalidQuery
		}
	}
	var packets []*model.Packet
	var totalPages int
	packets, totalPages, err = packetHandler.server.Datastore.GetPacketsByTime(int(jobId), int(offset), int(count), int64(startTime), int64(endTime), search)
	DataLast := model.PacketPaging{
		TotalPages: totalPages,
		Data:       packets,
	}
	if err == nil {
		statusCode = http.StatusOK
	} else {
		statusCode = http.StatusNotFound
	}
	return statusCode, DataLast, err
}
