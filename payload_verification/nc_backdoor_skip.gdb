set pagination off
target remote :31503
break *Mal_func3+0x3a
commands
 silent
 printf "\n[HIT] Mal_func3 before system(), pc=%p\n", $pc
 printf "system argument: "
 x/s *(char**)$esp
 printf "[SAFE] skip nc backdoor command\n"
 set $esp=$esp+4
 set $pc=$pc+5
 set $eax=-1
 continue
end
continue

