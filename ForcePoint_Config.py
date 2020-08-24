#!/bin/python

import os
import sys
import argparse
import csv
import xml.etree.ElementTree as ET

cliParser = argparse.ArgumentParser(description="Parse firewall rules and configuration from ForcePoint XML files")
cliParser.add_argument('-f', '--file', help='ForcePoint XML File')
cliParser.add_argument('-v', '--verbosity', help='Detailed Output', action="store_true")
cliParser.add_argument('-o', '--output', help='Output to cwd', action="store_true")

#Global variable
verbose = cliParser.parse_args().verbosity

#------------------------------------------------------
# Classes

class Policy:
    def __init__(self,name):
        self.Name = name
        self.Rules = []

class Rule:
    def __init__(self,id,name):
        self.Id = id
        self.Name = name
        self.Sources = []
        self.Destinations = []
        self.Services = []
        self.Action = ''
        self.Logging = ''

class Match:
    def __init__(self,type,value):
        self.Type = type
        self.Value = value


class MatchExpression:
    def __init__(self,name):
        self.Name = name
        self.Elements = []

class MatchElement:
    def __init__(self,ref,class_id):
        self.Ref = ref
        self.Class_id = class_id

class Host:
    def __init__(self, name, comment):
        self.Name = name
        self.Comment = comment
        self.IPs = []

class Service:
    def __init__(self,name,comment,port):
        self.Name = name
        self.Comment = comment
        self.Port = port

class ServiceGroup:
    def __init__(self,name):
        self.Name = name
        self.Services = []

class InterfaceZone:
    def __init__(self,name):
        self.Name = name

class Network:
    def __init__(self,name,ipv4,comment):
        self.Name = name
        self.Range = ipv4
        self.Comment = comment

class Group:
    def __init__(self,name,comment):
        self.Name = name
        self.Comment = comment
        self.Elements = []

class AddressRange:
    def __init__(self,name,ip_range):
        self.Name = name
        self.Range = ip_range

class DomainName:
    def __init__(self,name,comment):
        self.Name = name
        self.Comment = comment

class Alias:
    def __init__(self,name,comment):
        self.Name = name
        self.Comment = comment

class FirewallCluster:
    def __init__(self,name):
        self.Name = name

class Node:
    def __init__(self,name,disabled,version):
        self.Name = name
        self.Disabled = disabled
        self.Version = version

class NodeInterface:
    def __init__(self,name,network_value):
        self.Name = name
        self.Network = network_value
        self.Address = ""

#-------------------------------------------------
#Functions

def DisplayFirewallConfig(config):
    clusters = GetFWClusters(config)

    print('Firewall Cluster:')
    for cluster in clusters:
        print('\t',cluster.Name)


def GetFWClusters(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()

    clusters = []
    for cluster in root.findall('fw_cluster'):
        newCluster = FirewallCluster(cluster.get('name'))
        clusters.append(newCluster)
    
    return clusters


# List Aliases from XML
def GetAliases(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    aliases = {}

    for alias in root.findall('alias'):
        newAlias = Alias(alias.get('name'),alias.get('comment'))
        aliases[newAlias.Name] = newAlias

    return aliases

# List Domains from XML
def GetDomains(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    domains = {}

    for domain in root.findall('domain_name'):
        newDomain = DomainName(domain.get('name'), domain.get('comment'))
        domains[newDomain.Name] = newDomain

    return domains

# List Hosts from XML
def GetHosts(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    hosts = {}

    for host in root.findall('host'):
        newHost = Host(host.get('name'),host.get('comment'))
        for ip in host.findall('mvia_address'):
            newHost.IPs.append(ip.get('address'))
        hosts[newHost.Name] = newHost

    return hosts

# List TCP Service from XML
def GetServices(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    services = {}

    for service in (root.findall('service_tcp') or root.findall('service_udp')):
        newService = Service(service.get('name'),service.get('comment'), service.get('min_dst_port'))
        services[newService.Name] = newService

    return services

# List Address Ranges from XML
def GetAddressRanges(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    addressRanges = {}

    for range in root.findall('address_range'):
        newRange = AddressRange(range.get('name'), range.get('ip_range'))
        addressRanges[newRange.Name] = newRange

    return addressRanges

# List service groups from XML
def GetServiceGroups(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    serviceGroups = {}

    for group in root.findall('gen_service_group'):
        newServiceGroup = ServiceGroup(group.get('name'))
        for service in group.findall('service_ref'):
                newServiceGroup.Services.append(service.get('ref'))
        serviceGroups[newServiceGroup.Name] = newServiceGroup

    return serviceGroups

# List Interface zones from XML
def GetInterfaceZone(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    interfaceZones = []

    for zone in root.findall('interface_zone'):
        newZone = InterfaceZone(zone.get('name'))
        interfaceZones.append(newZone)

    return interfaceZones

# List Groups from XML
def GetGroups(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    groups = {}

    for group in root.findall('group'):
        newGroup = Group(group.get('name'),group.get('comment'))
        for item in group.findall('ne_list'):
                newGroup.Elements.append(item.get('ref'))
        groups[newGroup.Name] = newGroup

    return groups


# List networks from XML
def GetNetworks(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    networks = {}

    for network in root.findall('network'):
        newNetwork= Network(network.get('name'),network.get('ivp4_network'),network.get('comment'))
        networks[newNetwork.Name] = newNetwork

    return networks

# List MatchExpressions from XML
def GetMatchExpression(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()
    matches = {}

    for expression in root.findall('match_expression'):
        newMatchExpression = MatchExpression(expression.get('name'))
        
        for entry in expression.findall('match_element_entry'):
            newElement = MatchElement(entry.get('ref'), entry.get('class_id'))
            newMatchExpression.Elements.append(newElement)
        matches[newMatchExpression.Name] = newMatchExpression

    return matches

# List MatchExpressions from XML
def GetFirewallRules(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()

    Policies = []
    
    for policy in root.findall('fw_policy'):
        #Creae new policy and append to policy list
        currentPolicy = Policy(policy.get('name'))
        Policies.append(currentPolicy)
        
        for rule in policy.findall('access_entry/rule_entry'):
            #Create a new rule and appent to the policy rule array.
            currentRule = Rule(rule.get('tag'), rule.get('name'))
            currentPolicy.Rules.append(currentRule)

            for source in rule.findall('access_rule/match_part/match_sources/match_source_ref'):
                #Append source to the rule sources list.
                sourceMatch = Match(source.get('type'),source.get('value'))
                currentRule.Sources.append(sourceMatch)
            for destination in rule.findall('access_rule/match_part/match_destinations/match_destination_ref'):
                #Append destinations to the rule destination list
                destinationMatch = Match(destination.get('type'),destination.get('value'))
                currentRule.Destinations.append(destinationMatch)
            for service in rule.findall('access_rule/match_part/match_services/match_service_ref'):
                #Add service to the currentRule services list
                currentRule.Services.append(service.get('value'))
            if(rule.find('access_rule/action') is not None):
                #set action for the current rule
                currentRule.Action = rule.find('access_rule/action').get('type')
            if(rule.find('access_rule/option/log_policy') is not None):
                #Set the logging policy for the current rule
                currentRule.Logging = rule.find('access_rule/option/log_policy').get('log_level')

    return Policies

def DisplayFirewallPolicies(policies, config):
    print('Firewall Policies')
    print('-----------------')

    matches = GetMatchExpression(config)
    groups = GetGroups(config)
    hosts = GetHosts(config)
    interfaceZones = GetInterfaceZone(config)
    networks = GetNetworks(config)
    addressRanges = GetAddressRanges(config)

    #Print Policy Names
    for policy in policies:
        print('Policy: ', policy.Name)

        #Print rule names and ID
        for rule in policy.Rules:
            print('Rule: ', rule.Id, ' - ', rule.Name)
            
            #Print Sources
            print('\tSources:')
            for source in rule.Sources:
                try:
                    print('\t\t',source.Value)
                    if(verbose):
                        for item in matches[source.Value].Elements:
                            if item.Ref in groups:
                                print('\t\t\tGroup: ', item.Ref)
                            if(any(zone.Name == item.Ref for zone in interfaceZones)):
                                print('\t\t\tInterface: ', item.Ref)
                            if item.Ref in hosts:
                                print('\t\t\tHost: ', item.Ref)
                            if item.Ref in networks:
                                print('\t\t\tNetwork: ', item.Ref)
                            if item.Ref in addressRanges:
                                print('\t\t\tRange: ', item.Ref)
                except:
                    pass
            #Print Destinations
            print('\tDestination Group:')
            for destination in rule.Destinations:
                try:
                    print('\t\t',destination.Value)
                    if(verbose):
                        for item in matches[destination.Value].Elements:
                            if item.Ref in groups:
                                print('\t\t\tGroup: ', item.Ref)
                            if(any(zone.Name == item.Ref for zone in interfaceZones)):
                                print('\t\t\tInterface: ', item.Ref)
                            if item.Ref in hosts:
                                print('\t\t\tHost: ', item.Ref)
                            if item.Ref in networks:
                                print('\t\t\tNetwork: ', item.Ref)
                except:
                    pass

            #Print Services
            print('\tServices:')
            for service in rule.Services:
                print('\t\t',service)
            
            #Print Action
            print('\tAction: ', rule.Action)

            #Print Logging
            print('\tLogging: ', rule.Logging)

def OutputFirewallPolicies(policies, config):
    print('Outputting to file...')

    with open('FirewallPolicies.csv', mode='w') as PolicyFile:
        writer = csv.writer(PolicyFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        #writer.writeheader(['Policy','Rule ID', 'Rule Name','Souces','Destinations','Services','Action','Logging'])

        matches = GetMatchExpression(config)
        groups = GetGroups(config)
        hosts = GetHosts(config)
        interfaceZones = GetInterfaceZone(config)
        networks = GetNetworks(config)
        ranges = GetAddressRanges(config)

        #Print Policy Names
        for policy in policies:
            for rule in policy.Rules:               
                for source in rule.Sources:
                    sourceList = []
                    if source.Type == "match_expression":
                        for item in matches[source.Value].Elements:
                            if item.Ref.upper() in (group.upper() for group in groups):
                                sourceList.append('Group: ' + item.Ref)
                            if(any(zone.Name.upper() == item.Ref.upper() for zone in interfaceZones)):
                                sourceList.append('Interface: ' + item.Ref)
                            if item.Ref.upper() in (host.upper() for host in hosts):
                                sourceList.append('Host: ' + item.Ref)
                            if item.Ref.upper() in (network.upper() for network in networks):
                                sourceList.append('Network: ' + item.Ref)
                            if item.Ref.upper() in (range.upper() for range in ranges):
                                sourceList.append('Range: ' + item.Ref)
                    else:
                        if(any(zone.Name.upper() == source.Value.upper() for zone in interfaceZones)):
                            sourceList.append('Interface: ' + source.Value)
                        if source.Value.upper() in (host.upper() for host in hosts):
                            sourceList.append('Host: ' + source.Value)
                        if source.Value.upper() in (network.upper() for network in networks):
                            sourceList.append('Network: ' + source.Value)
                        if source.Value.upper() in (range.upper() for range in ranges):
                            sourceList.append('Range: ' + source.Value)
                        if source.Value.upper() in (group.upper() for group in groups):
                            sourceList.append('Group: ' + source.Value)
                for destination in rule.Destinations:
                    destinationList = []
                    if destination.Type == "match_expression":
                        for item in matches[destination.Value].Elements:
                            if item.Ref.upper() in (group.upper() for group in groups):
                                destinationList.append('Group: ' + item.Ref)
                            if(any(zone.Name.upper() == item.Ref.upper() for zone in interfaceZones)):
                                destinationList.append('Interface: ' + item.Ref)
                            if item.Ref.upper() in (host.upper() for host in hosts):
                                destinationList.append('Host: '+ item.Ref)
                            if item.Ref.upper() in (network.upper() for network in networks):
                                destinationList.append('Host: ' + item.Ref)
                            if item.Ref.upper() in (range.upper() for range in ranges):
                                destinationList.append('Range: ' + item.Ref)
                    else:
                        if (any(zone.Name.upper() == destination.Value.upper() for zone in interfaceZones)):
                            destinationList.append('Interface: ' + destination.Value)
                        if destination.Value.upper() in (host.upper() for host in hosts):
                            destinationList.append('Host: ' + destination.Value)
                        if destination.Value.upper() in (network.upper() for network in networks):
                            destinationList.append('Network: ' + destination.Value)
                        if destination.Value.upper() in (range.upper() for range in ranges):
                            destinationList.append('Range: ' + destination.Value)
                        if destination.Value.upper() in (group.upper() for group in groups):
                            destinationList.append('Group: ' + destination.Value)

                    writer.writerow([policy.Name,rule.Id, rule.Name,sourceList, destinationList, rule.Services, rule.Action, rule.Logging])

# List MatchExpressions from XML
def GetNATRules(config):
    #create a root element
    tree = ET.parse(config)

    root = tree.getroot()

    Policies = []
    
    for policy in root.findall('fw_policy'):
        #Creae new policy and append to policy list
        currentPolicy = Policy(policy.get('name'))
        Policies.append(currentPolicy)
        
        
        for rule in policy.findall('nat_entry/rule_entry'):
            #Create a new rule and appent to the policy rule array.
            currentRule = Rule(rule.get('tag'), rule.get('name'))
            currentPolicy.Rules.append(currentRule)

            for source in rule.findall('nat_rule/match_part/match_sources/match_source_ref'):
                #Append source to the rule sources list.
                sourceMatch = Match(source.get('type'),source.get('value'))
                currentRule.Sources.append(sourceMatch)
            for destination in rule.findall('nat_rule/match_part/match_destinations/match_destination_ref'):
                #Append destinations to the rule destination list
                destinationMatch = Match(destination.get('type'),destination.get('value'))
                currentRule.Destinations.append(destinationMatch)
            for service in rule.findall('nat_rule/match_part/match_services/match_service_ref'):
                #Add service to the currentRule services list
                currentRule.Services.append(service.get('value'))
            if(rule.find('nat_rule/action') is not None):
                #set action for the current rule
                currentRule.Action = rule.find('nat_rule/action').get('type')
            if(rule.find('nat_rule/option/log_policy') is not None):
                #Set the logging policy for the current rule
                currentRule.Logging = rule.find('nat_rule/option/log_policy').get('log_level')

    return Policies

def DisplayNATPolicies(policies, config):
    print('NAT Policies')
    print('-----------------')

    matches = GetMatchExpression(config)
    groups = GetGroups(config)
    hosts = GetHosts(config)
    interfaceZones = GetInterfaceZone(config)
    networks = GetNetworks(config)

    #Print Policy Names
    for policy in policies:
        print('Policy: ', policy.Name)

        #Print rule names and ID
        for rule in policy.Rules:
            print('Nat Rule: ', rule.Id, ' - ', rule.Name)
            
            #Print Sources
            print('\tSources:')
            for source in rule.Sources:
                try:
                    print('\t\t',source.Value)
                    if(verbose):
                        for item in matches[source.Value].Elements:
                            if item.Ref in groups:
                                print('\t\t\tGroup: ', item.Ref)
                            if(any(zone.Name == item.Ref for zone in interfaceZones)):
                                print('\t\t\tInterface: ', item.Ref)
                            if item.Ref in hosts:
                                print('\t\t\tHost: ', item.Ref)
                            if item.Ref in networks:
                                print('\t\t\tNetwork: ', item.Ref)
                except:
                    pass
            #Print Destinations
            print('\tDestination Group:')
            for destination in rule.Destinations:
                try:
                    print('\t\t',destination.Value)
                    if(verbose):
                        for item in matches[destination.Value].Elements:
                            if item.Ref in groups:
                                print('\t\t\tGroup: ', item.Ref)
                            if(any(zone.Name == item.Ref for zone in interfaceZones)):
                                print('\t\t\tInterface: ', item.Ref)
                            if item.Ref in hosts:
                                print('\t\t\tHost: ', item.Ref)
                            if item.Ref in networks:
                                print('\t\t\tNetwork: ', item.Ref)
                except:
                    pass

            #Print Services
            print('\tServices:')
            for service in rule.Services:
                print('\t\t',service)
            
            #Print Action
            print('\tAction: ', rule.Action)

            #Print Logging
            print('\tLogging: ', rule.Logging)

def OutputNATPolicies(policies, config):
    print('Outputting to file...')

    with open('NATPolicies.csv', mode='w') as PolicyFile:
        writer = csv.writer(PolicyFile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        #writer.writeheader(['Policy','Rule ID', 'Rule Name','Souces','Destinations','Services','Action','Logging'])

        matches = GetMatchExpression(config)
        groups = GetGroups(config)
        hosts = GetHosts(config)
        interfaceZones = GetInterfaceZone(config)
        networks = GetNetworks(config)
        domainNames = GetDomains(config)
        addressRanges = GetAddressRanges(config)

        #Print Policy Names
        for policy in policies:
            for rule in policy.Rules:               
                for source in rule.Sources:
                    sourceList = []
                    if source.Type in matches:
                        for item in matches[source.Value].Elements:
                            if item.Ref.upper() in (group.upper() for group in groups):
                                sourceList.append('Group: ' + item.Ref)
                            if(any(zone.Name.upper() == item.Ref.upper() for zone in interfaceZones)):
                                sourceList.append('Interface: ' + item.Ref)
                            if item.Ref.upper() in (host.upper() for host in hosts):
                                sourceList.append('Host: ' + item.Ref)
                            if item.Ref.upper() in (network.upper() for network in networks):
                                sourceList.append('Network: ' + item.Ref)
                    else:
                        if source.Value.upper() in (group.upper() for group in groups):
                            sourceList.append('Group: ' + source.Value)
                        if(any(zone.Name.upper() == source.Value.upper() for zone in interfaceZones)):
                            sourceList.append('Interface: ' + source.Value)
                        if(source.Value in domainNames):
                            sourceList.append('Domain: ' + source.Value)
                        if(source.Value in addressRanges):
                            sourceList.append('Addres Range: ' + source.Value)
                        if source.Value.upper() in (host.upper() for host in hosts):
                            sourceList.append('Host: ' + source.Value)
                        if source.Value.upper() in (network.upper() for network in networks):
                            sourceList.append('Network: ' + source.Value)

                for destination in rule.Destinations:
                    destinationList = []
                    if destination.Type in matches:
                        for item in matches[destination.Value].Elements:
                            if item.Ref.upper() in (group.upper() for group in groups):
                                destinationList.append('Group: ' + item.Ref)
                            if(any(zone.Name.upper() == item.Ref.upper() for zone in interfaceZones)):
                                destinationList.append('Interface: ' + item.Ref)
                            if item.Ref.upper() in (host.upper() for host in hosts):
                                destinationList.append('Host: '+ item.Ref)
                            if item.Ref.upper() in (network.upper() for network in networks):
                                destinationList.append('Host: ' + item.Ref)
                    else:
                        if destination.Value.upper() in (group.upper() for group in groups):
                            destinationList.append('Group: ' + destination.Value)
                        if (any(zone.Name.upper() == destination.Value.upper() for zone in interfaceZones)):
                            destinationList.append('Interface: ' + destination.Value)
                        if destination.Value.upper() in (host.upper() for host in hosts):
                            destinationList.append('Host: ' + destination.Value)
                        if destination.Value.upper() in (network.upper() for network in networks):
                            destinationList.append('Network: ' + destination.Value)
                        if(destination.Value in domainNames):
                            destinationList.append('Domain: ' + destination.Value)
                        if(destination.Value in addressRanges):
                            destinationList.append('Addres Range: ' + destination.Value)

                    writer.writerow([policy.Name,rule.Id, rule.Name,sourceList, destinationList, rule.Services, rule.Action, rule.Logging])

# Main
#--------------------------------------------------------

if __name__ == "__main__":
    args = cliParser.parse_args()
    config = args.file
    verbosity = args.verbosity

    print('*********************************************')
    print("Force Point Config Review Tool")
    print('version: 0.1')
    print('Nop Sec Consulting Ltd')
    print('Ralph Vickery')
    print('*********************************************')
    print()

    DisplayFirewallConfig(config)

    FirewallPolicies = GetFirewallRules(config)
    DisplayFirewallPolicies(FirewallPolicies, config)

    NatPolicies = GetNATRules(config)
    DisplayNATPolicies(NatPolicies,config)

    #If the output flag is set then output to CSV File
    if(args.output):
        OutputFirewallPolicies(FirewallPolicies, config)
        OutputNATPolicies(NatPolicies, config)
        pass

#Stuff to add in future
#log_server
#certificate_authority
#mgt_server
#situation
#snmp_agent
#vpn_profile
#fw_cluster - probably main firewall