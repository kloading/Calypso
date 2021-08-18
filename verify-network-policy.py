import yaml
import os
import sys
import json
import argparse
import ipaddress
import requests

from z3 import *

GITHUB_REPO = os.environ['GITHUB_REPOSITORY']
GITHUB_SHA = os.environ['GITHUB_SHA']
GITHUB_TOKEN = os.environ['GITHUB_TOKEN']
GITHUB_PR = os.environ['GITHUB_PR']

namespace_consts = set()
podlabel_consts = set()

debug = True

if(debug):
    set_param(proof=True)

def parse_policy(control_path, proposed_path):
    z3_consts = ''
    control_policy = ''
    proposed_policy = ''

    with open(control_path, 'r') as stream:
        policy_dict = yaml.safe_load(stream)
        
        # Ensure the YAML is a Kubernetes Network Policy
        if (not policy_dict 
            or (not ('kind' in policy_dict) 
            or (policy_dict['kind'] != 'NetworkPolicy'))):
            return None
        
        ingress_rules = policy_dict['spec']['ingress']
        policy_exprs = parse_ingress(ingress_rules)    
        control_policy = create_policy(policy_exprs, 'control-policy')

    with open(proposed_path, 'r') as stream:
        policy_dict = yaml.safe_load(stream)
        
        # Ensure the YAML is a Kubernetes Network Policy
        if (not policy_dict 
            or (not ('kind' in policy_dict) 
            or (policy_dict['kind'] != 'NetworkPolicy'))):
            return None
        
        ingress_rules = policy_dict['spec']['ingress']
        policy_exprs = parse_ingress(ingress_rules)    
        proposed_policy = create_policy(policy_exprs, 'proposed-policy')     

    z3_consts = create_z3_constants()
    z3_formula = create_z3_formula(z3_consts, control_policy, proposed_policy) 

    s = Solver()
    s.from_string(z3_formula)
    if(debug):
        print("Generated SMT-LIB 2.0 Model:")
        print(s.sexpr())
    z3_sat = s.check()
    if(z3_sat == z3.sat):
        print("The proposed network policy is not compliant.")
        if(debug):
            print("Violating example below: ")
            m = s.model()
            reserved_inputs = ['proposed-policy', 'control-policy', 'conjecture']
            decls = m.decls()
            violating_example = ''
            
            for decl in decls:
                if str(decl) == 'ipAddress':
                    binary_ip = m[decl].as_binary_string()
                    block1 = str(int(binary_ip[0:8], 2))
                    block2 = str(int(binary_ip[8:16], 2))
                    block3 = str(int(binary_ip[16:24], 2))
                    block4 = str(int(binary_ip[24:32], 2))

                    print(f"ipAddress : {block1}.{block2}.{block3}.{block4}")
                    violating_example += f"IP Address: {block1}.{block2}.{block3}.{block4}\n"
                    continue

                if str(decl) not in reserved_inputs:
                    print(str(decl), ":", m[decl])
                    violating_example += f"{str(decl)}: {m[decl]}\n"

            pr_url = f"https://api.github.com/repos/{GITHUB_REPO}/issues/{GITHUB_PR}/comments"
            headers = {'Content-Type': 'application/json', 'Authorization': f'token {GITHUB_TOKEN}'}
            data = {'body':f'The proposed network policy is not compliant. Violating traffic example below:\n{violating_example}'}
            
            data_string = f"<strong>:x: The proposed network policy is not compliant. </strong>\n<details><summary>Violating traffic example</summary>\n\n\tproject: \"\"\n\tIP Address: 172.17.1.1\n\trole: \"\" \n\tport: 6379\n\tprotocol: \"TCP\"" 
            data = {'body':data_string}
            r = requests.post(url = pr_url, data = json.dumps(data), headers = headers)
            print(r.text)
        sys.exit(-1)
    else:
        print("The proposed network policy is compliant!")
#        if(debug):
#            print(s.proof().children())

def parse_ingress(ingress_rules):
    policy_exprs = []
    for rule in ingress_rules:
        source_exprs = []
        port_exprs = []
        sources = rule['from']
        ports = rule['ports']
        for source in sources:
            source_keys = source.keys()
            source_label = list(source_keys)[0]
            nested = True if len(source_keys) > 1 else False
            if nested:
                expr = add_nested_selector(source)
                source_exprs.append(expr)
            elif source_label == 'namespaceSelector':
                expr = add_namespace_selector(source)
                source_exprs.append(expr)
            elif source_label == 'podSelector':
                expr = add_pod_selector(source)
                source_exprs.append(expr)
            elif source_label == 'ipBlock':
                expr = add_ip_block(source)
                source_exprs.append(expr)
            else:
                print('Unsupported source:', source_label)
    
        expr = add_all_ports(ports)
        port_exprs.append(expr)

        policy_expr = create_policy_expr(source_exprs, port_exprs)
        policy_exprs.append(policy_expr)
        
    return policy_exprs

def create_policy_expr(source_exprs, port_exprs):
    z3_expr = "(and "
    z3_expr += "(or"
    for expr in source_exprs:
        z3_expr += expr
    z3_expr += ")"
    for expr in port_exprs:
        z3_expr += expr
    z3_expr += ")"
    return z3_expr

def create_z3_constants():
    smtlib2consts = ""
    for namespace in namespace_consts:
        smtlib2consts += "(declare-const " + namespace + " String)\n"
    for podlabel in podlabel_consts:
        smtlib2consts += "(declare-const " + podlabel + " String)\n"

    smtlib2consts += "(declare-const ipAddress Int)"
    smtlib2consts += "(declare-const protocol String)"
    smtlib2consts += "(declare-const port Int)"
    return smtlib2consts

def create_policy(policy_exprs, policy_name):
    policy = "(define-fun " + policy_name + "() Bool\n(and "
    for expr in policy_exprs:
        policy += expr
    policy += "\n))"
    return policy

def create_z3_formula(consts, control, proposed):
    return consts + '\n' + control + '\n\n' + proposed + '\n\n' + "(define-fun conjecture() Bool \n (=> (= proposed-policy true) \n (= control-policy true))) \n\n (assert (not conjecture)) \n (check-sat)"        

def add_namespace_selector(source):
    z3_expr = "(and "
    labels = source['namespaceSelector']['matchLabels'].keys()
    for label in labels:
        namespace_consts.add(label)
        z3_expr += "(" + "= " + str(label) + " \"" + str(source['namespaceSelector']['matchLabels'][label]) + "\")"
    z3_expr += ")"
    return z3_expr

def add_pod_selector(source):
    z3_expr = "(and "
    labels = source['podSelector']['matchLabels'].keys()
    for label in labels:
        podlabel_consts.add(label)
        z3_expr += "(" + "= " + str(label) + " \"" + str(source['podSelector']['matchLabels'][label]) + "\")"
    z3_expr += ")"
    return z3_expr
        

def add_ip_block(source):
    cidr = source['ipBlock'].get('cidr')
    exclusions = source['ipBlock'].get('except')

    bit_arr = []
    bit_string_low = ''
    bit_string_high = ''

    cidr = cidr.replace('/', '.')
    cidr = cidr.split('.')

    mask = int(int(cidr[4]) / 8)

    for i in range(0, len(cidr)-1):
        bit_arr.append(format(int(cidr[i]), '08b'))

    for i in range(0, mask):
        bit_string_low += str(bit_arr[i])
        bit_string_high += str(bit_arr[i])
    
    for i in range(mask, 4):
        bit_string_low += '00000000'
        bit_string_high += '11111111' 

    decimal_converted_low = int(bit_string_low, 2)
    decimal_converted_high = int(bit_string_high, 2) 

    z3_expr = "(and "
    z3_expr += "(>= ipAddress " + str(decimal_converted_low) + " )"
    z3_expr += "(<= ipAddress " + str(decimal_converted_high) +  " )"

    # Exclusion 
    bit_arr = []
    bit_string_low = ''
    bit_string_high = ''

    cidr = exclusions[0].replace('/', '.')
    cidr = cidr.split('.')

    mask = int(int(cidr[4]) / 8)

    for i in range(0, len(cidr)-1):
        bit_arr.append(format(int(cidr[i]), '08b'))

    for i in range(0, mask):
        bit_string_low += str(bit_arr[i])
        bit_string_high += str(bit_arr[i])
    
    for i in range(mask, 4):
        bit_string_low += '00000000'
        bit_string_high += '11111111' 

    decimal_converted_low = int(bit_string_low, 2)
    decimal_converted_high = int(bit_string_high, 2)    

    z3_expr += "(not (and"
    z3_expr += "(>= ipAddress " + str(decimal_converted_low) + " )"
    z3_expr += "(<= ipAddress " + str(decimal_converted_high) + " )"
    z3_expr += "))"

    z3_expr += ")"

    return z3_expr

def add_nested_selector(source):
    z3_expr = "(or "
    for nested_source in source:
        if nested_source == 'namespaceSelector':
            z3_expr += add_namespace_selector({nested_source: source[nested_source]}) 
        elif nested_source == 'podSelector':
            z3_expr += add_pod_selector({nested_source: source[nested_source]})  
        else:
            print("Unsupported nested source")
    z3_expr += ")"
    return z3_expr

def add_port(port):
    z3_expr = "(and "
    z3_expr += "(= protocol \"" + port['protocol'] + "\")"
    z3_expr += "(= port " + str(port['port']) + ")"
    z3_expr += ")"
    return z3_expr

def add_all_ports(ports):
    z3_expr = "(or "
    for port in ports:
        z3_expr += add_port(port)
    z3_expr += ")"
    print(z3_expr)
    return z3_expr

parser = argparse.ArgumentParser(description='Verify Kubernetes Network Policy Security and Compliance')
parser.add_argument('-control', metavar='control-policy', type=str, help='Path to control policy')
parser.add_argument('-proposed', metavar='proposed-policy', type=str, help='Path to proposed policy')

args = parser.parse_args()

parse_policy(args.control, args.proposed)

