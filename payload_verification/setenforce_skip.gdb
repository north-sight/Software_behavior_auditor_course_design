set pagination off
target remote :31505
break *Mal_func5+0x32
commands
 silent
 printf "\n[HIT] Mal_func5 before system(), pc=%p\n", $pc
 printf "system argument: "
 x/s *(char**)$esp
 printf "[SAFE] skip system('setenforce 0')\n"
 set $esp=$esp+4
 set $pc=$pc+5
 set $eax=-1
 continue
end
continue

