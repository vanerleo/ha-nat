#!/usr/bin/env python

# Copyright 2014: Lithium Technologies, Inc
# License: Apache License v2.0
# Author(s):
#   - Paul Allen (paul.allen@lithium.com)
# Example Usage:
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8"
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8" --eips "1.2.3.4,10.20.30.40,99.88.77.66"
#   - ./ha-nat.py --log-file /var/log/ha-nat.log --monitor-interval 15 --private-subnets "subnet-30fe0b55,subnet-eeb782a8" --create-eips
#
import boto
import boto.ec2
from boto.exception import EC2ResponseError
import datetime
import os
import sys
from optparse import OptionParser
from boto.vpc import VPCConnection
import subprocess
import socket
import time

version = "0.1.6"

## globals for caching
MY_AZ = None
MY_VPC_ID = None
INSTANCE_ID = None
MY_SUBNETS = None
MY_ROUTE_TABLES = None

def parseArgs():
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("--debug",             dest="debug",          default=False, action="store_true",     help="Whether or not to run in debug mode [default: %default]")
    parser.add_option("--version",           dest="version",        default=False, action="store_true",     help="Display the version and exit")
    parser.add_option("--env",               dest="env",            default="dev",                          help="The environment in which this is running")
    parser.add_option("--monitor-interval",  dest="monitorInterval",default="300",                          help="The frequency in seconds of which to check the routes [default: %default]")
    parser.add_option("--private-subnets",   dest="privateSubnets", default="",                             help="A CSV of private subnet ids to ensure a 0.0.0.0/0 route exists from each subnet to the NAT instance")
    parser.add_option("--eips",              dest="eips",           default=None,                           help="A CSV of EIPs to assign to the NATs.")
    parser.add_option("--create-eips",       dest="createEips",     default=False, action="store_true",     help="Create EIPs to assign if there are none available.")
    parser.add_option("--log-file",          dest="logFile",        default="/var/log/ha-nat.log",          help="The log file in which to dump debug information [default: %default]")
    return parser.parse_args()

def log(statement):
    statement = str(statement)
    if options.logFile is None:
        return
    if not os.path.exists(os.path.dirname(options.logFile)):
        os.makedirs(os.path.dirname(options.logFile))
    logFile = open(options.logFile, 'a')
    ts = datetime.datetime.now()
    isFirst = True
    for line in statement.split("\n"):
        if isFirst:
            logFile.write("%s - %s\n" % (ts, line))
            isFirst = False
        else:
            logFile.write("%s -    %s\n" % (ts, line))
    logFile.close()

def sendEvent(title, text, options):
    tag = "env:%s,region:%s,vpc:%s,az:%s" % (options.env, getRegion(), getMyVPCId(), getAvailabilityZone())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # event datagram is as follows
    # _e{title.length,text.length}:title|text|d:date_happened|h:hostname|p:priority|t:alert_type|#tag1,tag2
    datagram = u'_e{%d,%d}:%s|%s|#%s' % (len(title), len(text), title, text, tag)
    log("event datagram %s" % datagram)
    # Send event down to the local dogstatsd
    if options.debug:
        log("sending event to datadog => " + datagram)
    else:
        sock.sendto(datagram, ("127.0.0.1", 8125))

def cmd_output(args, **kwds):
    ## this function will run a command on the OS and return the result
    kwds.setdefault("stdout", subprocess.PIPE)
    kwds.setdefault("stderr", subprocess.STDOUT)
    proc = subprocess.Popen(args, **kwds)
    return proc.communicate()[0]
    
def metaData(dataPath):
    ## using 169.254.169.254 instead of 'instance-data' because some people
    ## like to modify their dhcp tables...
    return cmd_output(["curl", "-sL", "169.254.169.254/latest/meta-data/" + dataPath])

def getAvailabilityZone():
    ## cached
    global MY_AZ
    if MY_AZ is None:
        MY_AZ = metaData("placement/availability-zone")
    return MY_AZ

def getRegion():
  return getAvailabilityZone()[:-1]

def getInstanceId():
    ## cached
    global INSTANCE_ID
    if INSTANCE_ID == None:
        INSTANCE_ID = metaData("instance-id")
    return INSTANCE_ID

def findBlackholes():
    ## don't cache this value as we need to keep checking
    myFilters = [['vpc-id', getMyVPCId()], ['route.state', 'blackhole']]
    return VPC.get_all_route_tables(filters=myFilters)

def disableSourceDestChecks():
    EC2.modify_instance_attribute(getInstanceId(), "sourceDestCheck", False)

def getMySubnets():
    ## cached
    global MY_SUBNETS
    if MY_SUBNETS == None:
        az_subnet_filters = [['availability-zone', getAvailabilityZone()],['vpc-id', getMyVPCId()]]
        MY_SUBNETS = VPC.get_all_subnets(filters=az_subnet_filters)
    return MY_SUBNETS

def getMyRouteTables(subnet):
    ## this cannot be cached beacuse we need to keep checking the route tables
    rt_filters = [['vpc-id', getMyVPCId()], ['association.subnet-id', subnet.id]]
    return VPC.get_all_route_tables(filters=rt_filters)
  
def getMyVPCId():
    ## cached
    global MY_VPC_ID
    if MY_VPC_ID == None:
        MY_VPC_ID = getMe().vpc_id
    return MY_VPC_ID
  
def getMe():
    ## don't cache this as our instance attributes can change
    return EC2.get_only_instances(instance_ids=[getInstanceId()])[0]

def replaceIfWrongAZ():
    log("replaceIfWrongAZ | checking getAvailabilityZone(): %s" % getAvailabilityZone())
    ## find subnet(s) in my AZ
    for subnet in getMySubnets():
        log("replaceIfWrongAZ | checking subnet: %s" % subnet.id)
        ## find routes with instances
        for route_table in getMyRouteTables(subnet):
            log("replaceIfWrongAZ | checking route table: %s" % route_table.id)
            if route_table.id == None:
                continue
            for route in route_table.routes:
                log("replaceIfWrongAZ | checking route: %s | %s" % (route.destination_cidr_block, route.instance_id))
                if route.instance_id == None:
                    continue
                if route.destination_cidr_block != '0.0.0.0/0':
                    continue
                if route.instance_id == None or route.instance_id == "":
                    continue
                ## check the AZ of the instances
                for instance in EC2.get_only_instances(instance_ids=[route.instance_id]):
                    if instance.placement != getAvailabilityZone():
                        ## wrong zone
                        ## if the AZ of the instance is different than ours and the route table, replace it
                        log('incorrect az - replacing route')
                        if not options.debug:
                            VPC.replace_route(route_table_id = route_table.id,
                                              destination_cidr_block = route.destination_cidr_block,
                                              gateway_id = route.gateway_id,
                                              instance_id = getInstanceId())
                            sendEvent("Taking over route (preferred AZ)", "instance [%s] is assinging cidr [%s] to itself on route table [%s]" % (getInstanceId(), route.destination_cidr_block, route_table.id), options)
                        else:
                            log('skipped VPC.replace_route due to debug flag')

                    else:
                        ## correct zone
                        ## if the AZ of the instance is the same, do nothing
                        log('correct az - not replacing the route')

def ensureSubnetRoutes():
    for subnet in options.privateSubnets.split(','):
        rt_filters = [['vpc-id', getMyVPCId()], ['association.subnet-id', subnet]]
        route_tables = VPC.get_all_route_tables(filters=rt_filters)
        for route_table in route_tables:
            if route_table.id == None:
                continue
            natRouteExists = False
            for route in route_table.routes:
                if route.destination_cidr_block == '0.0.0.0/0':
                    natRouteExists = True
                    break
            if not natRouteExists:
                ## we create the route in a try/catch because during a race condition
                ## AWS will not allow duplicate route entries. This exception simply
                ## means the work has already been done
                try:
                    log("creating route route_table_id = %s, destination_cidr_block = '0.0.0.0/0', instance_id = %s" % (route_table.id, getInstanceId()))
                    if not options.debug:
                        VPC.create_route(route_table_id = route_table.id,
                                         destination_cidr_block = '0.0.0.0/0',
                                         instance_id = getInstanceId())
                        sendEvent("Missing Routes", "instance [%s] is creating routes for cidr [0.0.0.0/.0] to itself on route table [%s]" % (getInstanceId(), route_table.id), options)

                    else:
                        log('skipped VPC.create_route due to debug flag')

                except Exception as e:
                    log(str(e))

def main():
    ## this should do the following
    ##   1) if eips are called out or createEips is enabled, ensure we have an EIP assigned to us
    ##      a) if we do not
    ##         i) look through the list assinged
    ##        ii) if we find one unassigned, take it
    ##       iii) if we do not find one unassigned, check if we are allowed to create EIPs
    ##        iv) if we are allowed to create EIPs, create one and assign it to ourself
    ##         v) if we are not allowed to create EIPs, log an error and continue to try again later
    ##       b) if we do have an EIP, move on
    ##   2) ensure a private subnet route exists pointing to 0.0.0.0/0
    ##   3) ensure source/destination checks are disabled
    ##   4) if there is a blackhole in replace it with this instnace
    ##   5) if there is no blackhole in this AZ, replace only if the registered instance
    ##      is NOT in this AZ
    if options.createEips or (options.eips != None and options.eips != ""):
        log("we have been asked to handle eips - handling now")
        ## check if we have an EIP assigned to us
        filters = {'instance-id': getInstanceId()}
        addresses = EC2.get_all_addresses(filters = filters)
        log("got addresses: %s" % addresses)
        have_eip = False
        if not addresses:
            ## we don't have an EIP
            log("no EIP assigned to this instance - looking for EIPS")
            if options.eips != "":
                log("eips have been specified")
                for eip_assigned in options.eips.split(','):
                    if eip_assigned == "":
                        continue
                    log(" - searching for %s" % eip_assigned)
                    try:
                        address = EC2.get_all_addresses(addresses = [eip_assigned])[0]
                        log(" - found address: %s" % (address))
                    except EC2ResponseError:
                        log("ERROR: address not found in account %s" % eip_assigned)
                        continue
                    ## we only care about addresses that are not associated
                    if address.association_id:
                        continue
                    if address.public_ip == eip_assigned:
                        log("found matching usable ip %s - associating to this instance [%s]" % (eip_assigned, getInstanceId()))
                        EC2.associate_address(instance_id = getInstanceId(), public_ip = eip_assigned)
                        have_eip = True
                ## we should have an eip here now, if not lets raise an exception
                raise Exception("Expected to have an EIP at this point, but do not")

            if have_eip == False and options.createEips:
                ## we still dont have an EIP, but we are allowed to create them, so lets do that
                ## first, we will just check if there is an empty one we can use
                addresses = EC2.get_all_addresses()
                for address in addresses:
                    if address.association_id:
                        ## we only care about unassociated ip addresses
                        continue
                    ## if we made it here, lets just take it and exit
                    log("found an IP address - associating [%s] with instance_id [%s]" % (address.public_ip, getInstanceId()))
                    EC2.associate_address(instance_id = getInstanceId(), public_ip = address.public_ip)
                    have_eip = True
                    break
                if have_eip == False:
                    ## we still have no EIP - time to create one
                    log("creating new IP address")
                    try:
                        new_address = EC2.allocate_address()
                        log("associating new ip address [%s] with instance_id [%s]" % (new_address.public_ip, getInstanceId()))
                        EC2.associate_address(instance_id = getInstanceId(), public_ip = new_address.public_ip)
                        have_eip = True
                    except:
                        log("ERROR: cannot allocate and assign a new IP address")
            log("EIPs have been handled to the best of our ability - continuing on now")
        else:
            have_eip = True
        
        if have_eip == False:
            sendEvent("Cannot assign EIP", "instance [%s] is unable to assign an eip although asked to do so" % (getInstanceId()), options)
            raise Exception('Unable to assign requested EIP - not continuing')

    log("continuing to ensureSubnetRoutes()")
    ensureSubnetRoutes()
    for route_table in findBlackholes():
        log("main | checking route table: %s" % route_table.id)
        if route_table.id == None:
            continue
        for route in route_table.routes:
            log("main | checking route: %s | %s" % (route.destination_cidr_block, route.instance_id))
            if not route.state == 'blackhole':
                continue
            if route.destination_cidr_block != '0.0.0.0/0':
                continue
            log('main | found a black hole - taking the route over')
            if not options.debug:
                VPC.replace_route(route_table_id = route_table.id,
                                  destination_cidr_block = route.destination_cidr_block,
                                  gateway_id = route.gateway_id,
                                  instance_id = getInstanceId())
                sendEvent("Found a black hole", "instance [%s] is assinging cidr [%s] to itself on route table [%s]" % (getInstanceId(), route.destination_cidr_block, route_table.id), options)
            else:
                log('skipped VPC.replace_route due to debug flag')
    replaceIfWrongAZ()                         
   
(options, args) = parseArgs()

if options.version:
    print(version)
    sys.exit(0)

EC2 = boto.ec2.connect_to_region(getRegion())
VPC = boto.vpc.connect_to_region(getRegion())

## these only need to run once
log("disabling source/destination checks")
disableSourceDestChecks()
if len(options.privateSubnets) > 0 and len(options.privateSubnets.split(',')) > 0:
    log("ensuring private subnet routes exist")
    ensureSubnetRoutes()

while True:
    try:
        main()
    except Exception as e:
        log("ERROR: %s" % str(e))
    log("sleeping %d before rechecking" % (int(options.monitorInterval)))
    time.sleep(int(options.monitorInterval))
