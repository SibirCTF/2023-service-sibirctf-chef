#!/bin/sh
chown chef:chef -R /opt/chef/storage
su chef -c /opt/chef/server