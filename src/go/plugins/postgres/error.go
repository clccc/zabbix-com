/*
** Zabbix
** Copyright (C) 2001-2019 Zabbix SIA
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

package postgres

import "strings"

type zabbixError string

func (e zabbixError) Error() string { return string(e) }

const (
	errorTooManyParameters               = zabbixError("Too many parameters.")
	errorCannotFetchData                 = zabbixError("Cannot fetch data.")
	errorPostgresPing                    = zabbixError("PostgreSQL ping failed: got wrong data.")
	errorCannotParseData                 = zabbixError("Cannot parse data.")
	errorUnsupportedMetric               = zabbixError("Unsupported metric.")
	errorEmptyResult                     = zabbixError("Empty result.")
	errorUnsupportePostgresVersion       = zabbixError("Unsupported version of Postgres.")
	errorCannotParsePostgresURL          = zabbixError("Cannot parse Postgres connection URL.")
	errorCannotConnectPostgres           = zabbixError("Cannot connect to Postgres server.")
	errorCannotGetPostgresVersion        = zabbixError("Cannot get Postgres version.")
	errorCannotConvertPostgresVersionInt = zabbixError("Cannot convert Postgres version to integer.")
	errorEmptyParam                      = zabbixError("Empty param.")
)

// formatZabbixError formats a given error text. It capitalizes the first letter and adds a dot to the end.
// TBD: move to the agent's core
func formatZabbixError(errText string) string {
	if errText[len(errText)-1:] != "." {
		errText = errText + "."
	}

	return strings.Title(errText)
}
