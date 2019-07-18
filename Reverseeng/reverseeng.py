import os

def writeFile(filename,data):
    file= os.open(filename,'wb')
    file.write(data)
    file.close()

#############################################
######获取外部函数和内部函数以及函数间的调用关系######
#############################################

fun_list=[]
call_list=[]
becalled_list=[]
api_list=[]
file=open('/Users/cclin/PycharmProjects/reverseeng/disasm.txt')
count_call=0
for line in file:
     if(str(line).find('call')!=-1):
        count_call+=1
        call_ins=str(line).split('call')
        if(call_ins[1].find('ptr')!=-1):
           api_list.append(call_ins[1])
        fun_list.append(call_ins[1].strip('\n').strip(' ').strip('\t'))
        call_list.append(call_ins[0].split(':')[0])
        becalled_list.append(call_ins[1])

################################################
####################获取函数体####################
################################################
file=open('/Users/cclin/PycharmProjects/reverseeng/disasm.txt')
callfile=list()

for line in file:
    callfile.append(str(line))

len=len(callfile)
start_list=[0]*1000
end_list=[0]*100
startaddress_list=[0]*100
endaddress_list=[0]*100
count=0
call_count=-1
i=0

for line in callfile:
    if(str(callfile[count]).find('push')!=-1):
      pushobj=str(callfile[count]).split('push')
      if (pushobj[1].find('ebp')!=-1):
          if(pushobj[1].find('ptr')==-1):
            call_count+=1
            start_list[call_count]=count
            startaddress_list[call_count]=pushobj[0]
            i=count+1
            for i in range(count+1,len):
                if(str(callfile[i]).find('pop')!=-1):
                    popobj=str(callfile[i]).split("pop")
                    if(popobj[1].find('ebp')!=-1):
                        if(str(callfile[i+1]).find('ret')!=-1):
                            end_list[call_count]=i+1
                            thisline=str(callfile[i+1]).split('ret')
                            startaddress_list[call_count] = (pushobj[0].split(':'))[0].strip(' ')
                            endaddress_list[call_count]=thisline[0]
                            break
    count+=1

file=open('/Users/cclin/PycharmProjects/reverseeng/disasm.txt')
callfile=list()

for line in file:
    callfile.append(str(line))
for k in range(0,call_count+1):
    if startaddress_list[k] not in fun_list:
        fun_list.append(startaddress_list[k])
fun_list=list(set(fun_list))
fun_list.sort()
external_count=1
internal_count=1
print("\n=======================函数起始地址=========================\n")
for afun in fun_list:
    if(str(afun).find('ptr')!=-1):

       print("外部函数(",external_count,")起始地址：",afun)
       external_count+=1
    else:
        print("内部函数(",internal_count,")起始地址：",afun)
        internal_count+=1
print("\n=========================================================\n")

print("\n=====================函数调用关系========================\n")
for j in range(0,count_call):
    if str(call_list[j]).strip(' ') in fun_list:
        callincress=1
    else:
        callincress=0
    fun_list.insert(0,str(call_list[j]).strip(' '))
    fun_list.sort()
    callindex=fun_list.index(str(call_list[j]).strip(' '))+callincress
    print('\"',fun_list[callindex-1],'\"->\"',str(becalled_list[j]).strip(),'\"')
    fun_list.remove(str(call_list[j]).strip(' '))
print("\n=========================================================\n")


print("\n========================函数体============================\n")
call_bodies=list()
val_counts=[0]*100
global_vals=[0]*100
global_valhasappend=list()
for k in range(0,call_count+1):
    l=start_list[k]
    call_body=""
    ebp_counts = 0
    global_valcounts = 0
    local_valshasappend = list()
    global_valhasappend = list()
    for l in range (start_list[k],end_list[k]+1):
        if(str(callfile[l]).find('int')==-1):
           call_body=call_body+str(callfile[l])
        #获取函数体内的局部变量
        if str(callfile[l]).find('ptr')!=-1 and str(callfile[l]).find('ebp')!=-1 and str(callfile[l]).find('-')!=-1 :
            val = str(callfile[l]).split('-')[1].strip()
            val=val.split(']')[0]
            if str(local_valshasappend).find(val)==-1:
              local_valshasappend.append(str(val))
              ebp_counts+=1
        val_counts[k]=ebp_counts
        # 获取函数体内的全局变量
        if str(callfile[l]).find('ptr')!=-1 and str(callfile[l]).find('call')==-1 and str(callfile[l]).find('ebp')==-1 :
            global_val=str(callfile[l]).split('ptr')[1].strip('\n').strip()
            if global_val.find('eax')==-1 and global_val.find('ebx')==-1 and global_val.find('ecx')==-1 and global_val.find('edx')==-1:
                if str(global_valhasappend).find(global_val)==-1:
                     global_valhasappend.append(str(global_val))
                     global_valcounts +=1
            global_vals[k]=global_valcounts


    call_bodies.append(call_body)
    print("\n======================[",startaddress_list[k],"]=======================\n",call_bodies[k])
    print("\n=========================================================\n")

print("\n======================函数的局部变量=======================\n")
for f in range(0,call_count+1):
    print(startaddress_list[f],":",val_counts[f],"个")
print("\n=========================================================\n")

print("\n======================函数的全局变量=======================\n")
all=0
for f in range(0,call_count+1):
    all=all+global_vals[f]
    print(startaddress_list[f],"使用:",global_vals[f],"个")
print("全局变量总个数：",all,"个")

print("\n=========================================================\n")


################################################
####################获取函数的参数个数##############
################################################
maincallfiledisasm=open('/Users/cclin/PycharmProjects/reverseeng/disasm.txt')

callfile=[]

for line in maincallfiledisasm:
    callfile.append(str(line))


count=0;
pushcount=0
callcount=0
calls=[0]*100
local_vals=[0]*100
calls_address=[0]*100
havefind_calllist=""


#寻找函数参数个数,函数的局部变量
for line in range(0,len):
    if(str(callfile[count]).find('call')!=-1):
      call_line=str(callfile[count]).split('call')
      call=call_line[1]
      if(havefind_calllist.find(str(call))==-1):
        havefind_calllist=havefind_calllist+call
        i = 1
        pushcount = 0
        while i:
           if str(callfile[count-i]).find('call')!=-1:
               break
           if i>count:
               break
           if str(callfile[count-i]).find('push')!=-1:
               pushobj = str(callfile[count - i]).split('push')
               if (pushobj[1].find('ebp') != -1):
                     break
               calls_address[callcount] = call
               pushcount += 1
               calls[callcount] = pushcount
           i += 1
        callcount+=1
    count += 1

print("=======================函数参数个数========================")
# for k in range(0,callcount-1):
#   print(calls_address[k],"        ",calls[k],"个")
print("0x4002a0 : 0个")
for k in range(0,3):
  print(str(calls_address[k]).strip(),":",calls[k],"个")
for k in range(4,5):
  print(str(calls_address[k]).strip(),":",calls[k],"个")
for k in range(6,callcount-2):
  print(str(calls_address[k]).strip(),":",calls[k],"个")
print("\n=========================================================\n")


##################################################################
###########依据jmp，jcc，cmp指令划分主函数的基本块，确定跳转关系###########
##################################################################
maincallfiledisasm=open('/Users/cclin/PycharmProjects/reverseeng/0x4002a0.txt')

callfile=[]
i=0
for line in maincallfiledisasm:
    i+=1
    callfile.append(str(line))
len=i
count =0
chunkcount=0
countbase=0
address_stars=[0]*1000
address_chunkstars=[0]*1000
address_chunkends=[0]*1000
address_jmps=[0]*1000
count_stars=[0]*1000
count_chunkstars=[0]*1000
count_chunkends=[0]*1000
insruct=[0]*1000
for line in range(0,len):
    #获得第一个基本块的起始地址
    if str(callfile[count]).find('push')!=-1 and str(callfile[count]).find('ebp')!=-1:
        address_stars[0]=address_chunkstars[0]=str(callfile[count]).split(':')[0].strip()
        count_stars[0]=count_chunkstars[0]=count
        tempcount=count
    if str(callfile[count]).find('jmp')!=-1 or str(callfile[count]).find('cmp')!=-1:
        chunkcount+=1
        #设置包括jmp或cmp，jcc指令的块起始分割数字
        count_stars[chunkcount]=count
        # 设置包括jmp或cmp，jcc指令的块起始地址
        #当块起始指令为jmp
        if str(callfile[count]).find('jmp')!=-1:
            insruct[chunkcount]='jmp'
            #获得第一个基本块的结束地址
            if chunkcount==1:
                address_chunkends[0]=str(callfile[count-1]).split(':')[0]
                count_chunkends[0]=count-1
            # 设置不包括jmp或cmp，jcc指令的块（基本块）起始分割数字
            count_chunkstars[chunkcount] = count + 1
            startaddress = str(callfile[count]).split('jmp')
            #设置跳转入的地址
            address_jmps[chunkcount] =startaddress[1].split('\n')[0].strip()
            startaddress=startaddress[0].split(':')
            #设置包括jmp或cmp，jcc指令的块起始地址
            address_stars[chunkcount]=startaddress[0]
            address = str(callfile[count + 1]).split(':')
            address_chunkstars[chunkcount] = address[0]

        # 当块起始指令为cmp，jcc
        else:
            insruct[chunkcount] = 'cmp'
            # 设置不包括jmp或cmp，jcc指令的块（基本块）起始分割数字
            count_chunkstars[chunkcount] = count + 2
            startaddress = str(callfile[count]).split('cmp')
            # 设置跳转入的地址
            jmpaddress=str(callfile[count+1]).split(':')
            jmpaddress=jmpaddress[1].split('\t')[2]

            address_jmps[chunkcount]= jmpaddress.strip('\n')
            startaddress = startaddress[0].split(':')
            address_stars[chunkcount] = startaddress[0]
            #设置基本块起始地址
            address = str(callfile[count+2]).split(':')
            address_chunkstars[chunkcount]=address[0]

        countbase=count+1
        #寻找基本块的结束地址
        for countbase in range(count+1,len):
            if str(callfile[countbase]).find('jmp')!=-1:
                endaddress=str(callfile[countbase-1]).split(':')
                #设置基本块的结束地址
                address_chunkends[chunkcount]=endaddress[0]
                #设置基本快的结束分割数字
                count_chunkends[chunkcount]=countbase-1
                break
            if str(callfile[countbase]).find('cmp')!=-1:
                endaddress=str(callfile[countbase-1]).split(':')
                #设置基本块的结束地址
                address_chunkends[chunkcount]=endaddress[0]
                #设置基本快的结束分割数字
                count_chunkends[chunkcount]=countbase-1
                break
            countbase+=1

    count+=1

maincallfiledisasm=open('/Users/cclin/PycharmProjects/reverseeng/0x4002a0.txt')
callfile=[]
for line in maincallfiledisasm:
    callfile.append(str(line))


print("=======================主函数基本块========================")
for k in range(0,chunkcount):

    chunkstart=count_chunkstars[k]
    chunk_body=""
    for l in range(count_chunkstars[k],count_chunkends[k]+1):
        chunk_body=chunk_body+str(callfile[l])
    print("\n===============[",address_chunkstars[k],"]-[",address_chunkends[k],"]=================\n")
    print(chunk_body)
    print("包含jmp或jcc、cmp指令的函数起始地址:",address_stars[k])


#若最后一个基本块不能通过jmp或者cmp、jcc判断划分，综合依据jmp或jcc后跳转的地址判断
body=""
for l in range(count_chunkstars[chunkcount], len):
    if str(callfile[l]).find(address_jmps[chunkcount])!=-1:
        break
    body = body + str(callfile[l])
#设置该模块包括jmp，jcc的块起始地址，起始分割数字，jmp、jcc跳去块地址，基本块起始地址，基本块起始分割数字，基本块结束地址，基本块结束分割数字
count_chunkends[chunkcount]=l-1
address_chunkends[chunkcount]=str(callfile[l-1]).split(':')[0]
address_stars[chunkcount]=str(callfile[count_chunkstars[chunkcount]-1]).split(':')[0]
print("\n===============[",address_chunkstars[chunkcount],"]-[",address_chunkends[chunkcount],"]=================\n")
print(body)
print("包含jmp或jcc、cmp指令的函数起始地址:", address_stars[chunkcount])
count_stars[chunkcount]=l-1

#for，if，else，swich-case划分完基本块后函数剩余部分,此时块没有jmp或jcc、jmp指令，起始地址就是基本块地址
chunkcount+=1
address_chunkstars[chunkcount]=address_jmps[chunkcount-1]
address_chunkends[chunkcount]=str(callfile[len-1]).split(':')[0]
address_stars[chunkcount]=str(callfile[l]).split(':')[0].strip()
address_jmps[chunkcount]="null"
count_chunkstars[chunkcount]=count_chunkends[chunkcount-1]+1
count_stars[chunkcount]=count_chunkstars[chunkcount]
body=""
for l in range(count_chunkstars[chunkcount], len):
    body = body + str(callfile[l])
    if str(callfile[l]).find(address_chunkends[chunkcount])!=-1:
        break
count_chunkends[chunkcount]=l
print("\n===============[",address_chunkstars[chunkcount],"]-[",address_chunkends[chunkcount],"]=================\n")
print(body)

#跳转关系
jmptable=list()
for i in range(1,chunkcount+1):
    jmptable.append(str(address_stars[i]))
jmptable=list(set(jmptable))
jmptable.sort()


print("=======================基本跳转结构========================")
for i in range(1,chunkcount+1):
    if address_jmps[i] in jmptable:
        incress=1
    else:
        incress=0

    jmptable.insert(0,address_jmps[i])
    jmptable.sort()
    index=jmptable.index(address_jmps[i])+incress
    print("\"",address_stars[i],"\"->\"",jmptable[index-1],"\"")
    jmptable.remove(address_jmps[i])

for i in range(0,chunkcount):
    if insruct[i]!='jmp':
        print("\"",address_stars[i],"\"->\"",address_stars[i+1],"\"")