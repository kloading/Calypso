import yaml
import os
import json
import argparse
from z3 import *

namespace_consts = set()
podlabel_consts = set()

debug = False

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
        print("The proposed network policy is not compliant. Violating example below:")
        if(debug):
            print(s.model())
    else:
        print("The proposed network policy is compliant!")
        # print(s.proof().children())

def parse_ingress(ingress_rules):
    policy_exprs = []
    for rule in ingress_rules:
        sources = rule['from']
        ports = rule['ports']
        for source in sources:
            source_keys = source.keys()
            source_label = list(source_keys)[0]
            nested = True if len(source_keys) > 1 else False
            if nested:
                expr = add_nested_selector(source)
                policy_exprs.append(expr)
            elif source_label == 'namespaceSelector':
                expr = add_namespace_selector(source)
                policy_exprs.append(expr)
            elif source_label == 'podSelector':
                expr = add_pod_selector(source)
                policy_exprs.append(expr)
            elif source_label == 'ipBlock':
                add_ip_block()
            else:
                print('Unsupported source:', source_label)

    return policy_exprs

def create_z3_constants():
    smtlib2consts = ""
    for namespace in namespace_consts:
        smtlib2consts += "(declare-const " + namespace + " String)\n"
    for podlabel in podlabel_consts:
        smtlib2consts += "(declare-const " + podlabel + " String)\n"
    return smtlib2consts

def create_policy(policy_exprs, policy_name):
    policy = "(define-fun " + policy_name + "() Bool\n(or "
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
        

def add_ip_block():
    pass

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

parser = argparse.ArgumentParser(description='Verify Kubernetes Network Policy Security and Compliance')
parser.add_argument('-control', metavar='control-policy', type=str, help='Path to control policy')
parser.add_argument('-proposed', metavar='proposed-policy', type=str, help='Path to proposed policy')

args = parser.parse_args()

parse_policy(args.control, args.proposed)

