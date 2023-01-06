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
	"math"
	"net/http"
	"strconv"

	"github.com/sensoroni/sensoroni/model"
	"github.com/sensoroni/sensoroni/web"
)

type JobsHandler struct {
	web.BaseHandler
	server *Server
}

func NewJobsHandler(srv *Server) *JobsHandler {
	handler := &JobsHandler{}
	handler.Host = srv.Host
	handler.server = srv
	handler.Impl = handler
	return handler
}

func (jobsHandler *JobsHandler) HandleNow(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {

	switch request.Method {
	case http.MethodGet:
		return jobsHandler.get(writer, request)
	}
	return http.StatusMethodNotAllowed, nil, errors.New("Method not supported")
}

func (jobsHandler *JobsHandler) get(writer http.ResponseWriter, request *http.Request) (int, interface{}, error) {
	Interface := request.URL.Query().Get("interface")
	startTime, _ := strconv.ParseInt(request.URL.Query().Get("startTime"), 10, 32)
	endTime, _ := strconv.ParseInt(request.URL.Query().Get("endTime"), 10, 32)
	offset, err := strconv.ParseInt(request.URL.Query().Get("offset"), 10, 32)

	if offset <= 0 || err != nil {
		offset = 0
	}
	count := int(jobsHandler.server.Config.MaxPacketCount)
	if request.URL.Query().Get("count") != "" {
		count, err = strconv.Atoi(request.URL.Query().Get("count"))
		if err != nil {
			return http.StatusBadRequest, nil, errors.New("invalid query")
		}
	}
	data, dataLength := jobsHandler.server.Datastore.GetJobsByInterfaces(int(offset), int(count), Interface, startTime, endTime)
	DataLast := model.JobPaging{
		TotalPages: int(math.Ceil(float64(dataLength) / float64(count))),
		Data:       data,
	}

	return http.StatusOK, DataLast, nil
}
