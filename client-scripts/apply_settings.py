#!/usr/bin/env python
import fileinput
import urllib
import os
import json

#### Settings: ####
query_url = "https://bd42.clai.co/query"

settings_list = {
	"realityconfig_admin" : "mods/pr/python/game/realityconfig_admin.py",
	"banlist"             : "mods/pr/settings/banlist.con",
#	"reservedslots"       : "mods/pr/settings/reservedslots.con",
	"serversettings"      : "mods/pr/settings/serversettings.con",
        "maplist"         : "mods/pr/settings/maplist.con",
#	"start_pr"         : "start_pr.sh"
}

#### Settings end ####

# get the server key:

key_file    = open(os.path.dirname(os.path.realpath(__file__)) + "/server_key", "r");
server_key  = key_file.readlines()[0].strip();

query_url = query_url + "?server_key=" + server_key + "&command="

for settings_key in settings_list:
	data = urllib.urlopen(query_url + settings_key).read()
	f    = open(os.path.dirname(os.path.realpath(__file__)) + "/" + settings_list[settings_key], "w")
	f.write(data)

