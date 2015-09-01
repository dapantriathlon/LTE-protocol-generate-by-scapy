__Name__="check ipsec tunnel create"
__Autor__="pan liang"
__Mail__="liang.5.pan@nokia.com"

import sys
import os
import time
import re

def Get_tunnle_ip(ipsec_config=''):
    list_tunnel=[]
    ip_child={}
    re_left_ip =re.compile(r"left=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_right_ip =re.compile(r"right=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_child_ip =re.compile(r"\S*subnet=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_ip=re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    config_handler=open(ipsec_config, 'r')
    config_read=config_handler.read()
    config_split=config_read.split('conn conn')
    for i in xrange(0, len(config_split)):
        left_ip=re.findall(re_left_ip, config_split[i])
        right_ip=re.findall(re_right_ip, config_split[i])
        child_ip=re.findall(re_child_ip, config_split[i])
        if left_ip:
            yuanzu=(left_ip[0], right_ip[0])
            if yuanzu in ip_child:
                child_raw_ip_left=re.findall(re_ip, child_ip[0])
                child_raw_ip_right=re.findall(re_ip, child_ip[1])
                ip_child[yuanzu].append((child_raw_ip_left[0], child_raw_ip_right[0]))
            else:
                child_raw_ip_left=re.findall(re_ip, child_ip[0])                                 
                child_raw_ip_right=re.findall(re_ip, child_ip[1])
                ip_child[yuanzu]=[(child_raw_ip_left[0],child_raw_ip_right[0])]
                                                     
    return ip_child


def ipsec_child_check(ip_child='', ike='', result=''):
    ike_handler=open(ike, 'r') 
    ike_read=ike_handler.read()
    result_handler=open(result, 'w')
    ike_split=ike_read.split('Arrival Time:')
    success_tunnel=0
    re_src_ip = re.compile(r"Src: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_dst_ip = re.compile(r"Dst: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    re_child_ip=re.compile(r'Starting Addr: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    re_ip=re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_child_list=list(ip_child)
    for child_tunnel in ip_child_list:
        left_ip, right_ip=list(child_tunnel)[0].split('=')[1].strip(' '), list(child_tunnel)[1].split('=')[1].strip(' ')
        child_tunnel_len=len(ip_child[child_tunnel])
        for i in xrange(1, len(ike_split)-1):            
            child_list=[]
            src_ip=re.findall(re_src_ip, ike_split[i])[0].split(':')[1].strip(' ')
            dst_ip=re.findall(re_dst_ip, ike_split[i])[0].split(':')[1].strip(' ')
            if src_ip==left_ip and dst_ip==right_ip and 'Exchange type: IKE_SA_INIT (34)' in ike_split[i]:
                for j in xrange(i, len(ike_split)-1):
                    src_ip1=re.findall(re_src_ip, ike_split[j+1])[0].split(':')[1].strip(' ')
                    dst_ip1=re.findall(re_dst_ip, ike_split[j+1])[0].split(':')[1].strip(' ')
                    if dst_ip1==left_ip and src_ip1==right_ip and 'Exchange type: IKE_SA_INIT (34)' in ike_split[j+1]:
                        for k in xrange(j, len(ike_split)-1):
                            src_ip2=re.findall(re_src_ip, ike_split[k+1])[0].split(':')[1].strip(' ')
                            dst_ip2=re.findall(re_dst_ip, ike_split[k+1])[0].split(':')[1].strip(' ')
                            if src_ip2==left_ip and dst_ip2==right_ip and 'Exchange type: IKE_AUTH  (35)' in ike_split[k+1]:
                                try:
                                    re.findall(re_child_ip, ike_split[k+1])[0]
                                except:
                                        result_handler.write('the decode is not completed')
                			sys.exit(1)
                                child_ip=re.findall(re_child_ip, ike_split[k+1])
                                leftsubnet, rightsubnet=re.findall(re_ip, child_ip[0]),re.findall(re_ip, child_ip[1])
                                temp_yuanzu=(leftsubnet[0], rightsubnet[0])
                                child_list.append(temp_yuanzu)
                                for h in xrange(k, len(ike_split)-1):
                                    src_ip3=re.findall(re_src_ip, ike_split[h+1])[0].split(':')[1].strip(' ')
                                    dst_ip3=re.findall(re_dst_ip, ike_split[h+1])[0].split(':')[1].strip(' ')
                                    if 'Exchange type: IKE_AUTH  (35)' in ike_split[h+1] and dst_ip3==left_ip and src_ip3==right_ip:
                                            ip_config_set=set()
                                            ip_config_set.add(left_ip)
                                            ip_config_set.add(right_ip)
                                            try:
                                                re.findall(re_child_ip, ike_split[h+1])[0]
                                            except:
                                                    result_handler.write('the decode is not completed')
                                                    sys.exit(1)
                                            child_ip=re.findall(re_child_ip, ike_split[h+1])
                                            leftsubnet, rightsubnet=re.findall(re_ip, child_ip[0]),re.findall(re_ip, child_ip[1])
                                            temp_yuanzu=(leftsubnet[0], rightsubnet[0])
                                            child_list.append(temp_yuanzu)
                                            for m in xrange(1, child_tunnel_len*2):
                                                for n in xrange(h+m, len(ike_split)-1):
                                                    if n+1<len(ike_split):
                        				try:
                                                            src_ip=re.findall(re_src_ip, ike_split[n])[0].split(':')[1].strip(' ')
                                                            dst_ip=re.findall(re_dst_ip, ike_split[n])[0].split(':')[1].strip(' ')
                        				except:
                        				    result_handler.write('the ike file do not have CV message')
                        				    sys.exit(1)
                                                        ip_set=set()
                                                        ip_set.add(src_ip)
                                                        ip_set.add(dst_ip)
                                                        if ip_set==ip_config_set and 'Exchange type: CREATE_CHILD_SA (36)' in ike_split[n]:
                                                            try:
                                                                re.findall(re_child_ip, ike_split[n])[0]
                                                            except:
                                                                result_handler.write('the decode is not completed')
                                                                sys.exit(1)
                                                            child_ip=re.findall(re_child_ip, ike_split[n])      
                                                            leftsubnet, rightsubnet=re.findall(re_ip, child_ip[0]),re.findall(re_ip, child_ip[1])
                                                            temp_yuanzu=(leftsubnet[0], rightsubnet[0])
                                                            child_list.append(temp_yuanzu)
                                                            break
                                                        else:
                                                            continue
                                    else:
                                        continue
                                    break            
                            else:
                                continue
                            break        
                    else:
                        continue
                    break    
            else:   
                continue
            child_list_set=set(child_list)
            if len(child_list)>=2*len(child_list_set):
                if child_list_set==set(ip_child[child_tunnel]):
                    success_tunnel=success_tunnel+1
                else:
                    print "the :"+ str(right_ip)+" don't have create success"
                    result_handler.write("the :"+ str(right_ip)+" don't have create success")
            else:
                print "ike file do not have the one to one message"
                result_handler.write("ike file do not have the one to one message")
            break
    if success_tunnel==len(ip_child):
        print "TRSW check PASS"
        result_handler.write('TRSW check PASS')
    else:
        print "not all the tunnel have created successfully"
                    
if __name__=='__main__':
    start_time=time.clock()
    ipsec_config=sys.argv[1]
    decode_ike=sys.argv[2]
    result=sys.argv[3]
    ip_child_result=Get_tunnle_ip(ipsec_config)
    ipsec_child_check(ip_child_result,decode_ike,result)
    end_time=time.clock()
    sys.stdout.write("the total cost time: %s\n" %(end_time-start_time))              
